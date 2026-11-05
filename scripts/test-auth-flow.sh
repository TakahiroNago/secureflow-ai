#!/usr/bin/env bash
# SecureFlow AI — authentication over real HTTP, through nginx and the Vite proxy, with real Redis
# sessions, real CSRF checks and real Argon2id. Complements Pest, which uses in-memory sessions.
#
# It seeds data and creates users, so it runs only on a throwaway stack: a project other than the
# default one, or CI. It needs a migrated database.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
: "${NGINX_PORT:=8080}" "${FRONTEND_PORT:=5173}"
if [ "${COMPOSE_PROJECT_NAME:-secureflow}" = secureflow ] && [ "${CI:-}" != true ]; then
  echo "Refusing to run: this creates users. Use a separate project (README: 複数環境の同時起動) or CI." >&2
  exit 2
fi

NGINX=http://localhost:$NGINX_PORT
VITE=http://localhost:$FRONTEND_PORT
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }
has() { if grep -qiE -- "$3" <<< "$2"; then ok "$1"; else ng "$1 (no '$3')"; fi; }
hasnt() { if grep -qiE -- "$3" <<< "$2"; then ng "$1 (found '$3')"; else ok "$1"; fi; }

# A browser: a cookie jar and a base URL. Sets STATUS, BODY and HEADERS.
call() { # jar base method path [json] [extra curl arguments...]
  local jar=$1 base=$2 method=$3 path=$4 json=${5:-}; shift 5 2>/dev/null || shift $#
  local token args=()
  token=$(awk '$6 == "XSRF-TOKEN" { print $7 }' "$jar" 2>/dev/null | tail -1)
  [ -z "$token" ] || args+=(-H "X-XSRF-TOKEN: $(printf '%b' "${token//%/\\x}")")
  [ -z "$json" ] || args+=(-H 'Content-Type: application/json' --data-binary "$json")
  STATUS=$(curl -s -o "$work/body" -D "$work/headers" -w '%{http_code}' --max-time 20 -X "$method" \
    -b "$jar" -c "$jar" -H 'Accept: application/json' -H "Origin: $base" -H "Referer: $base/" \
    ${args[@]+"${args[@]}"} "$@" "$base$path")
  BODY=$(cat "$work/body"); HEADERS=$(cat "$work/headers")
}
csrf() { call "$1" "$2" GET /sanctum/csrf-cookie ""; }
login_json() { printf '{"email":"%s","password":"%s"}' "$1" "$2"; }
sql() { docker compose exec -T -e PGPASSWORD="$DB_PASSWORD" postgres psql -h 127.0.0.1 -U "$DB_USERNAME" -d "$DB_DATABASE" --no-psqlrc -tAc "$1"; }

PW_ALICE='alice long passphrase 01'
PW_ALICE2='alice other passphrase 02'
PW_BOB='bob long passphrase 03'

create_user() { # email password role
  printf '%s\n%s\n' "$2" "$2" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$1" --email="$1" --role="$3" 2>&1
}

echo "Target: $COMPOSE_PROJECT_NAME nginx=$NGINX vite=$VITE"

echo "== initial data =="
docker compose exec -T app php artisan db:seed --force > "$work/seed" 2>&1
is "db:seed succeeds" "$?" 0
is "the seeder creates an organization" "$(sql "SELECT count(*) FROM organizations WHERE name='Default Organization'")" 1
is "the seeder creates settings" "$(sql 'SELECT count(*) FROM organization_settings')" 1
before_users=$(sql 'SELECT count(*) FROM users')
docker compose exec -T app php artisan db:seed --force > /dev/null 2>&1
is "seeding twice changes nothing" "$(sql "SELECT count(*) FROM organizations WHERE name='Default Organization'")" 1
is "the seeder creates no user" "$(sql 'SELECT count(*) FROM users')" "$before_users"

echo "== user:create =="
out=$(create_user alice@example.com "$PW_ALICE" member); is "creates a user" "$?" 0
hasnt "does not print the password" "$out" "$PW_ALICE"
out=$(create_user bob@example.com "$PW_BOB" admin); is "creates a second user" "$?" 0
out=$(create_user weak@example.com passwordpassword member); is "refuses a password on the list" "$?" 1
is "stores Argon2id" "$(docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "SELECT left(password, 10) FROM users WHERE email='alice@example.com'")" '$argon2id$'

echo "== CSRF and origins =="
A=$work/alice.jar; : > "$A"
call "$A" "$NGINX" POST /api/v1/auth/login "$(login_json alice@example.com "$PW_ALICE")"
is "login without a CSRF cookie is 419" "$STATUS" 419
has "in RFC 9457 format" "$HEADERS" '^content-type: application/problem\+json'
has "with the CSRF code" "$BODY" '"code":"CSRF_TOKEN_MISMATCH"'
F=$work/foreign.jar; : > "$F"
csrf "$F" "$NGINX"
foreign=$(curl -s -o /dev/null -w '%{http_code}' -X POST -b "$F" -H 'Accept: application/json' -H 'Content-Type: application/json' \
  -H 'Origin: https://attacker.example' -H 'Referer: https://attacker.example/' \
  --data-binary "$(login_json alice@example.com "$PW_ALICE")" "$NGINX/api/v1/auth/login")
is "login from another origin is 419" "$foreign" 419
noorigin=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' \
  --data-binary "$(login_json alice@example.com "$PW_ALICE")" "$NGINX/api/v1/auth/login")
is "login with no origin at all is 419" "$noorigin" 419
is "a bearer token is unauthenticated" "$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/json' -H 'Authorization: Bearer 1|abc' "$NGINX/api/v1/auth/me")" 401
is "a form-encoded body is 415" "$(csrf "$A" "$NGINX"; call "$A" "$NGINX" POST /api/v1/auth/login "" -H 'Content-Type: application/x-www-form-urlencoded' --data 'email=a'; echo "$STATUS")" 415

echo "== failed logins look the same =="
normalize() { sed -E 's/"trace_id":"[^"]+"/"trace_id":"x"/' <<< "$1"; }
call "$A" "$NGINX" POST /api/v1/auth/login "$(login_json nobody@example.com 'a wrong password')"
is "unknown address is 401" "$STATUS" 401
has "with AUTH_FAILED" "$BODY" '"code":"AUTH_FAILED"'
unknown=$(normalize "$BODY")
call "$A" "$NGINX" POST /api/v1/auth/login "$(login_json alice@example.com 'a wrong password')"
is "wrong password is 401" "$STATUS" 401
is "and identical" "$(normalize "$BODY")" "$unknown"

echo "== login and session =="
csrf "$A" "$NGINX"
before_id=$(awk '$6 ~ /session/ { print $7 }' "$A" | tail -1)
call "$A" "$NGINX" POST /api/v1/auth/login "$(login_json alice@example.com "$PW_ALICE")"
is "the right password is 200" "$STATUS" 200
has "returns the user" "$BODY" '"email":"alice@example.com"'
hasnt "returns no password or hash" "$BODY" 'argon2|password'
has "session cookie is HttpOnly" "$HEADERS" '^set-cookie: [a-z0-9_-]*session[^;]*;.*httponly'
has "session cookie is SameSite=Lax" "$HEADERS" '^set-cookie: [a-z0-9_-]*session[^;]*;.*samesite=lax'
hasnt "CSRF cookie is readable by the SPA" "$HEADERS" '^set-cookie: xsrf-token[^;]*;.*httponly'
[ "$before_id" != "$(awk '$6 ~ /session/ { print $7 }' "$A" | tail -1)" ] && ok "the session ID changed" || ng "the session ID changed"
call "$A" "$NGINX" GET /api/v1/auth/me ""
is "auth/me is 200" "$STATUS" 200

echo "== Redis holds the session =="
# stdin is closed: otherwise this reads the key list of the loops below and skips keys.
rc() { docker compose exec -T -e REDISCLI_AUTH="$REDIS_PASSWORD" redis redis-cli --no-auth-warning "$@" < /dev/null; }
found=0; leak=0
while read -r db; do
  [ -n "$db" ] || continue
  while read -r key; do
    [ -n "$key" ] || continue
    ttl=$(rc -n "$db" ttl "$key" | tr -d '\r')
    value=$(rc -n "$db" --raw get "$key" 2>/dev/null | tr -d '\0')
    if grep -q 'auth.started_at\|password_fingerprint' <<< "$value" || grep -q 'started_at' <<< "$value"; then
      found=1; session_ttl=$ttl
    fi
    if grep -q 'argon2id\|login_web_.*argon' <<< "$value" && ! grep -q 'dummy-hash' <<< "$key"; then leak=1; fi
  done < <(rc -n "$db" --scan | tr -d '\r')
done < <(rc info keyspace | tr -d '\r' | sed -nE 's/^db([0-9]+):.*/\1/p')
is "a session is stored in Redis" "$found" 1
if [ "${session_ttl:-0}" -gt 1700 ] && [ "${session_ttl:-0}" -le 1800 ]; then ok "its expiry is the 30 minute idle limit (${session_ttl}s)"; else ng "its expiry is the 30 minute idle limit (${session_ttl:-none}s)"; fi
is "no password hash in the session" "$leak" 0

echo "== password change =="
O=$work/alice-other.jar; : > "$O"
csrf "$O" "$VITE"
call "$O" "$VITE" POST /api/v1/auth/login "$(login_json alice@example.com "$PW_ALICE")"
is "a second session through the Vite proxy" "$STATUS" 200
new_key() { cat /proc/sys/kernel/random/uuid; }
call "$A" "$NGINX" PATCH /api/v1/account/password "{\"current_password\":\"wrong one here\",\"new_password\":\"$PW_ALICE2\"}" -H "Idempotency-Key: $(new_key)"
is "wrong current password is 422" "$STATUS" 422
has "with its code" "$BODY" '"code":"CURRENT_PASSWORD_INVALID"'
call "$A" "$NGINX" PATCH /api/v1/account/password "{\"current_password\":\"$PW_ALICE\",\"new_password\":\"passwordpassword\"}" -H "Idempotency-Key: $(new_key)"
is "a password on the list is 422" "$STATUS" 422
KEY=$(new_key)
call "$A" "$NGINX" PATCH /api/v1/account/password "{\"current_password\":\"$PW_ALICE\",\"new_password\":\"$PW_ALICE2\"}" -H "Idempotency-Key: $KEY"
is "the change succeeds" "$STATUS" 200
call "$A" "$NGINX" PATCH /api/v1/account/password "{\"current_password\":\"$PW_ALICE\",\"new_password\":\"$PW_ALICE2\"}" -H "Idempotency-Key: $KEY"
is "the same key and content again is 200" "$STATUS" 200
is "and runs once" "$(sql "SELECT count(*) FROM audit_logs WHERE event_type='auth.password_changed'")" 1
call "$A" "$NGINX" PATCH /api/v1/account/password "{\"current_password\":\"$PW_ALICE\",\"new_password\":\"a different pass phrase 12\"}" -H "Idempotency-Key: $KEY"
is "the same key with other content is 409" "$STATUS" 409
call "$A" "$NGINX" GET /api/v1/auth/me ""
is "the current session keeps working" "$STATUS" 200
call "$O" "$VITE" GET /api/v1/auth/me ""
is "the other session is invalid" "$STATUS" 401

echo "== logout =="
cp "$A" "$work/replay.jar"
call "$A" "$NGINX" POST /api/v1/auth/logout ""
is "logout is 204" "$STATUS" 204
call "$A" "$NGINX" GET /api/v1/auth/me ""
is "the session has ended" "$STATUS" 401
call "$work/replay.jar" "$NGINX" GET /api/v1/auth/me ""
is "the old cookie does not work" "$STATUS" 401

echo "== lock and rate limit =="
B=$work/bob.jar; : > "$B"
csrf "$B" "$VITE"
call "$B" "$VITE" POST /api/v1/auth/login "$(login_json bob@example.com "$PW_BOB")"
is "bob has a session through the Vite proxy" "$STATUS" 200
X=$work/attacker.jar; : > "$X"
csrf "$X" "$NGINX"
for i in 1 2 3 4 5; do call "$X" "$NGINX" POST /api/v1/auth/login "$(login_json bob@example.com 'a wrong password')"; done
is "the fifth failure is still 401" "$STATUS" 401
is "the account is locked" "$(sql "SELECT locked_until > now() FROM users WHERE email='bob@example.com'")" t
call "$X" "$NGINX" POST /api/v1/auth/login "$(login_json bob@example.com 'a wrong password')"
is "the sixth attempt is 429" "$STATUS" 429
has "with Retry-After" "$HEADERS" '^retry-after: [0-9]+'
has "in RFC 9457 format" "$BODY" '"code":"RATE_LIMITED"'
call "$X" "$NGINX" POST /api/v1/auth/login "$(login_json bob@example.com 'a wrong password')" -H 'X-Forwarded-For: 192.0.2.77'
is "X-Forwarded-For does not get around the limit" "$STATUS" 429
L=$work/bob-new.jar; : > "$L"
csrf "$L" "$VITE"
call "$L" "$VITE" POST /api/v1/auth/login "$(login_json bob@example.com "$PW_BOB")"
is "the right password is refused while locked" "$STATUS" 401
has "with the same code" "$BODY" '"code":"AUTH_FAILED"'
call "$B" "$VITE" GET /api/v1/auth/me ""
is "bob's existing session survives the lock" "$STATUS" 200

echo "== disabling a user =="
docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -qc "UPDATE users SET is_active = false WHERE email='bob@example.com'"
call "$B" "$VITE" GET /api/v1/auth/me ""
is "is_active=false ends the session at once" "$STATUS" 401

echo "== the rest of the system =="
is "the SPA serves /login" "$(curl -s -o /dev/null -w '%{http_code}' "$NGINX/login")" 200
is "liveness needs no session" "$(curl -s -o /dev/null -w '%{http_code}' -H "Referer: $NGINX/" "$NGINX/api/health/live")" 200
hasnt "liveness sets no cookie" "$(curl -s -D - -o /dev/null -H "Referer: $NGINX/" -H 'Accept: application/json' "$NGINX/api/health/live")" '^set-cookie'
echo "== audit log =="
for event in auth.login auth.login_failed auth.logout auth.locked auth.password_changed auth.password_change_failed; do
  is "$event is recorded" "$(sql "SELECT count(*) > 0 FROM audit_logs WHERE event_type='$event'")" t
done
is "the application role cannot insert directly" "$(docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "SELECT has_table_privilege('$DB_USERNAME', 'audit_logs', 'INSERT')")" f
docker compose exec -T app php artisan audit:verify --all > "$work/verify.txt" 2>&1
is "audit:verify succeeds on what was recorded" "$?" 0
hasnt "the unknown address is not recorded" "$(sql "SELECT metadata::text || coalesce(host(ip_address),'') FROM audit_logs")" 'nobody@example.com'
hasnt "no password in the audit log" "$(sql "SELECT metadata::text FROM audit_logs")" 'a wrong password'
docker compose exec -T app php artisan audit:status > /dev/null 2>&1
is "audit:status reports available" "$?" 0
logs=$(docker compose logs --no-color --no-log-prefix --since=15m app worker scheduler nginx 2>&1)
for secret in "$PW_ALICE" "$PW_ALICE2" "$PW_BOB" 'a wrong password' 'argon2id'; do
  hasnt "the logs do not contain '${secret:0:12}…'" "$logs" "$secret"
done

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
