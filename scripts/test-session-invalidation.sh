#!/usr/bin/env bash
# SecureFlow AI — which sessions survive a password change, checked by calling an authenticated API
# with each one afterwards (AUDIT-SESSION-01). It creates users, so it runs only on a throwaway stack.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
. scripts/lib/login-limit.sh
: "${NGINX_PORT:=8080}"
if [ "${COMPOSE_PROJECT_NAME:-secureflow}" = secureflow ]; then
  echo "Refusing to run: this creates users. Use a separate project (README: 複数環境の同時起動)." >&2
  exit 2
fi

BASE=http://localhost:$NGINX_PORT
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }

sql() { docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "$1" < /dev/null | tr -d ' \r'; }
new_key() { cat /proc/sys/kernel/random/uuid; }
token_of() { local t; t=$(awk '$6 == "XSRF-TOKEN" { print $7 }' "$1" | tail -1); printf '%b' "${t//%/\\x}"; }
csrf() { curl -s -o /dev/null -b "$1" -c "$1" -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" "$BASE/sanctum/csrf-cookie"; }
request() { # jar method path [json] [extra curl arguments]: prints the status
  local jar=$1 method=$2 path=$3 json=${4:-}; shift 4 2>/dev/null || shift $#
  local args=()
  [ -z "$json" ] || args+=(-H 'Content-Type: application/json' --data-binary "$json")
  curl -s -o "$jar.body" -w '%{http_code}' --max-time 40 -X "$method" -b "$jar" -c "$jar" \
    -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" -H "X-XSRF-TOKEN: $(token_of "$jar")" \
    ${args[@]+"${args[@]}"} "$@" "$BASE$path"
}
login() { : > "$1"; csrf "$1"; request "$1" POST /api/v1/auth/login "$(printf '{"email":"%s","password":"%s"}' "$2" "$3")"; }
me() { request "$1" GET /api/v1/auth/me; }
change() { request "$1" PATCH /api/v1/account/password "$(printf '{"current_password":"%s","new_password":"%s"}' "$2" "$3")" -H "Idempotency-Key: $4"; }
changed_at() { sed -nE 's/.*"password_changed_at":"([^"]+)".*/\1/p' "$1.body"; }
new_user() {
  EMAIL="session-$$-$RANDOM@example.com"; PW="start pass phrase $(new_key)"
  printf '%s\n%s\n' "$PW" "$PW" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$EMAIL" --email="$EMAIL" --role=member > /dev/null 2>&1
}
events() { sql "SELECT count(*) FROM audit_logs a JOIN users u ON u.id = a.actor_user_id WHERE u.email='$1' AND a.event_type='auth.password_changed'"; }
hash_of() { sql "SELECT md5(password) FROM users WHERE email='$1'"; }

echo "Target: $COMPOSE_PROJECT_NAME $BASE"
clear_login_limit
new_user; NEW="changed pass phrase $(new_key)"; KEY=$(new_key)
A=$work/a.jar; B=$work/b.jar; D=$work/d.jar; C=$work/c.jar

echo "== before the change: three sessions =="
is "session A logs in" "$(login "$A" "$EMAIL" "$PW")" 200
is "session B logs in" "$(login "$B" "$EMAIL" "$PW")" 200
is "session D logs in" "$(login "$D" "$EMAIL" "$PW")" 200
is "session A works" "$(me "$A")" 200
is "session B works" "$(me "$B")" 200

echo "== session A changes the password =="
is "the change is 200" "$(change "$A" "$PW" "$NEW" "$KEY")" 200
first_time=$(changed_at "$A"); first_hash=$(hash_of "$EMAIL")

echo "== case 1: the session that changed it stays =="
is "session A: auth/me is 200" "$(me "$A")" 200
is "and again" "$(me "$A")" 200

echo "== case 2: sessions from before the change end =="
is "session B: auth/me is 401" "$(me "$B")" 401
is "session B stays ended" "$(me "$B")" 401
is "session D, whose first request is the retry itself: 401" "$(change "$D" "$PW" "$NEW" "$KEY")" 401
is "session D: auth/me is 401" "$(me "$D")" 401
is "the old password no longer logs in" "$(login "$work/o.jar" "$EMAIL" "$PW")" 401

echo "== case 3: a new login can retry with the same key and content =="
is "logging in with the new password" "$(login "$C" "$EMAIL" "$NEW")" 200
is "session C: auth/me is 200" "$(me "$C")" 200
is "the retry is 200" "$(change "$C" "$PW" "$NEW" "$KEY")" 200
is "with the same time" "$(changed_at "$C")" "$first_time"
is "session C: auth/me is still 200" "$(me "$C")" 200
is "the hash did not change" "$(hash_of "$EMAIL")" "$first_hash"
is "one event only" "$(events "$EMAIL")" 1
is "the same key with other content is 409" "$(change "$C" "$PW" "other pass phrase $(new_key)" "$KEY")" 409
is "session A: auth/me is still 200" "$(me "$A")" 200

echo "== after =="
docker compose exec -T app php artisan audit:verify --all > "$work/verify" 2>&1
is "audit:verify --all exits 0" "$?" 0

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
