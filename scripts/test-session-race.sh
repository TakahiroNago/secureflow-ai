#!/usr/bin/env bash
# SecureFlow AI — requests racing a logout or a password change, over real HTTP with real Redis sessions
# (AUDIT-SESSION-02). A request that read the session before the logout finishes after it, and must not
# bring the ended session back or send its cookie.
#
# It adds a test-only provider to bootstrap/providers.php for its own duration, to hold a request between
# reading and saving its session, so it refuses to run unless the caller names this exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-session-race.sh
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
. scripts/lib/login-limit.sh
: "${NGINX_PORT:=8080}"
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; then
  echo "Refusing to run: this changes a source file for a while. Name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION." >&2
  exit 2
fi
id=$(docker compose ps -q app)
[ -n "$id" ] && [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id")" = "$P" ] \
  || { echo "Refusing to run: app is not running in $P." >&2; exit 2; }

SYNC_ROUNDS=${SYNC_ROUNDS:-10}; OVERLAP_ROUNDS=${OVERLAP_ROUNDS:-20}
BASE=http://localhost:$NGINX_PORT
PROVIDERS=backend/bootstrap/providers.php
work=$(mktemp -d)
cp "$PROVIDERS" "$work/providers.php"
restore() { cat "$work/providers.php" > "$PROVIDERS"; rm -rf "$work"; }
trap restore EXIT
sed -i 's/^    AppServiceProvider::class,$/    AppServiceProvider::class,\n    Tests\\Support\\SessionRaceSyncProvider::class,/' "$PROVIDERS"
grep -q SessionRaceSyncProvider "$PROVIDERS" || { echo 'could not add the provider' >&2; exit 2; }

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }
seen() { echo "  [SEEN] $1"; }

sql() { docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "$1" < /dev/null | tr -d ' \r'; }
rc() { docker compose exec -T -e REDISCLI_AUTH="$REDIS_PASSWORD" redis redis-cli --no-auth-warning "$@" < /dev/null | tr -d '\r'; }
new_key() { cat /proc/sys/kernel/random/uuid; }
token_of() { local t; t=$(awk '$6 == "XSRF-TOKEN" { print $7 }' "$1" | tail -1); printf '%b' "${t//%/\\x}"; }
session_cookie() { awk '$6 ~ /session/ { print $7 }' "$1" | tail -1; }
csrf() { curl -s -o /dev/null -b "$1" -c "$1" -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" "$BASE/sanctum/csrf-cookie"; }
request() { # jar method path [json] [extra curl arguments]: prints the status
  local jar=$1 method=$2 path=$3 json=${4:-}; shift 4 2>/dev/null || shift $#
  local args=()
  [ -z "$json" ] || args+=(-H 'Content-Type: application/json' --data-binary "$json")
  curl -s -o "$jar.body" -D "$jar.headers" -w '%{http_code}' --max-time 60 -X "$method" -b "$jar" -c "$jar" \
    -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" -H "X-XSRF-TOKEN: $(token_of "$jar")" \
    ${args[@]+"${args[@]}"} "$@" "$BASE$path"
}
logins=0
# Stays under the limit per address (30 a minute) on long runs. Called before a login and not from login(),
# which runs in a command substitution, where the count would be lost.
pace() { logins=$((logins+1)); if [ $((logins % 20)) -eq 0 ]; then next_login_window; fi; }
login() { # jar email password
  : > "$1"; csrf "$1"
  request "$1" POST /api/v1/auth/login "$(printf '{"email":"%s","password":"%s"}' "$2" "$3")"
}
new_user() {
  EMAIL="race-$$-$RANDOM-$RANDOM@example.com"; PW="start pass phrase $(new_key)"
  printf '%s\n%s\n' "$PW" "$PW" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$EMAIL" --email="$EMAIL" --role=member > /dev/null 2>&1
  USER_ID=$(sql "SELECT id FROM users WHERE email='$EMAIL'")
}
# Stored sessions holding this user's login. Reads nothing out.
sessions_of() {
  rc eval "local n=0 for _,k in ipairs(redis.call('KEYS','*')) do if redis.call('TYPE',k).ok=='string' then local v=redis.call('GET',k) if v and string.find(v,'login_web_',1,true) and string.find(v,ARGV[1],1,true) then n=n+1 end end end return n" 0 "$1"
}
# What the store holds for a session cookie: absent, empty or login. Prints no id and no content.
stored() {
  docker compose exec -T app php -r '
    chdir("/var/www/html"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";
    $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    $id = Illuminate\Cookie\CookieValuePrefix::remove(Illuminate\Support\Facades\Crypt::decrypt(urldecode($argv[1]), false));
    $data = app("session")->driver()->getHandler()->read($id);
    echo $data === "" ? "absent" : (str_contains($data, "login_web_") ? "login" : "empty");' "$1" 2>/dev/null
}
sync_path() { echo "/tmp/session-race/$1"; }
reached() { # name: waits until the held request has read its session
  local i; for ((i=0;i<150;i++)); do docker compose exec -T app test -f "$(sync_path "$1").reached" 2>/dev/null && return 0; sleep 0.1; done; return 1
}
release() { docker compose exec -T app touch "$(sync_path "$1").release" 2>/dev/null; }
sends_session_cookie() { grep -iE '^set-cookie: [a-z0-9_-]*session' "$1.headers" | wc -l | tr -d ' '; }

echo "Target: $P $BASE, $SYNC_ROUNDS held rounds, $OVERLAP_ROUNDS overlap rounds"
docker compose exec -T app php artisan db:seed --force > /dev/null 2>&1
clear_login_limit

echo; echo "== normal use =="
new_user; N=$work/normal.jar
is "login" "$(login "$N" "$EMAIL" "$PW")" 200
is "auth/me" "$(request "$N" GET /api/v1/auth/me)" 200
old=$(session_cookie "$N"); cp "$N" "$work/normal-old.jar"
is "logout" "$(request "$N" POST /api/v1/auth/logout)" 204
is "logout sends one new session cookie" "$(sends_session_cookie "$N")" 1
[ "$(session_cookie "$N")" != "$old" ] && ok "and it is a different one" || ng "and it is a different one"
is "auth/me after logout" "$(request "$N" GET /api/v1/auth/me)" 401
is "the old cookie" "$(request "$work/normal-old.jar" GET /api/v1/auth/me)" 401
is "logging in again" "$(login "$N" "$EMAIL" "$PW")" 200
is "auth/me" "$(request "$N" GET /api/v1/auth/me)" 200
is "changing state with the token still works" "$(request "$N" POST /api/v1/auth/logout)" 204

echo; echo "== a GET holds the session while a logout ends it ($SYNC_ROUNDS rounds) =="
for ((r=1;r<=SYNC_ROUNDS;r++)); do
  pace; new_user; J=$work/l$r.jar; name="logout-$$-$r"
  is "round $r: login" "$(login "$J" "$EMAIL" "$PW")" 200
  old=$(session_cookie "$J"); cp "$J" "$work/l$r-get.jar"; cp "$J" "$work/l$r-old.jar"
  request "$work/l$r-get.jar" GET /api/v1/auth/me '' -H "X-Test-Session-Sync: $name" > "$work/l$r-get.status" &
  if reached "$name"; then ok "round $r: the GET has read its session and is held"; else ng "round $r: the GET has read its session and is held"; fi
  is "round $r: logout" "$(request "$J" POST /api/v1/auth/logout)" 204
  is "round $r: the session is gone" "$(stored "$old")" absent
  release "$name"; wait
  is "round $r: the GET still answers what it read" "$(cat "$work/l$r-get.status")" 200
  is "round $r: and sends no session cookie" "$(sends_session_cookie "$work/l$r-get.jar")" 0
  is "round $r: and sends no CSRF cookie" "$(grep -ciE '^set-cookie: xsrf-token' "$work/l$r-get.jar.headers")" 0
  is "round $r: the session did not come back" "$(stored "$old")" absent
  is "round $r: no stored login for this user" "$(sessions_of "$USER_ID")" 0
  is "round $r: the old cookie gets 401" "$(request "$work/l$r-old.jar" GET /api/v1/auth/me)" 401
  is "round $r: and no session cookie" "$(sends_session_cookie "$work/l$r-old.jar")" 0
  is "round $r: and that did not store it" "$(stored "$old")" absent
  is "round $r: the logged out browser gets 401" "$(request "$J" GET /api/v1/auth/me)" 401
done

echo; echo "== a GET holds the session while a password change rotates it ($SYNC_ROUNDS rounds) =="
for ((r=1;r<=SYNC_ROUNDS;r++)); do
  pace; new_user; J=$work/p$r.jar; name="password-$$-$r"; NEW="changed pass phrase $(new_key)"
  is "round $r: login" "$(login "$J" "$EMAIL" "$PW")" 200
  old=$(session_cookie "$J"); cp "$J" "$work/p$r-get.jar"; cp "$J" "$work/p$r-old.jar"
  request "$work/p$r-get.jar" GET /api/v1/auth/me '' -H "X-Test-Session-Sync: $name" > "$work/p$r-get.status" &
  if reached "$name"; then ok "round $r: the GET is held"; else ng "round $r: the GET is held"; fi
  is "round $r: the change" "$(request "$J" PATCH /api/v1/account/password "{\"current_password\":\"$PW\",\"new_password\":\"$NEW\"}" -H "Idempotency-Key: $(new_key)")" 200
  release "$name"; wait
  is "round $r: the GET sends no session cookie" "$(sends_session_cookie "$work/p$r-get.jar")" 0
  is "round $r: the old id did not come back" "$(stored "$old")" absent
  is "round $r: one stored login" "$(sessions_of "$USER_ID")" 1
  is "round $r: the new session works" "$(request "$J" GET /api/v1/auth/me)" 200
  is "round $r: the old cookie gets 401" "$(request "$work/p$r-old.jar" GET /api/v1/auth/me)" 401
done

echo; echo "== a request holds a session without a login while the login replaces it ($SYNC_ROUNDS rounds) =="
for ((r=1;r<=SYNC_ROUNDS;r++)); do
  pace; new_user; J=$work/a$r.jar; name="anonymous-$$-$r"
  : > "$J"; csrf "$J"; old=$(session_cookie "$J"); cp "$J" "$work/a$r-get.jar"
  request "$work/a$r-get.jar" GET /api/v1/auth/me '' -H "X-Test-Session-Sync: $name" > "$work/a$r-get.status" &
  if reached "$name"; then ok "round $r: the GET is held"; else ng "round $r: the GET is held"; fi
  is "round $r: login" "$(request "$J" POST /api/v1/auth/login "$(printf '{"email":"%s","password":"%s"}' "$EMAIL" "$PW")")" 200
  release "$name"; wait
  is "round $r: the GET gets 401" "$(cat "$work/a$r-get.status")" 401
  is "round $r: and sends no session cookie" "$(sends_session_cookie "$work/a$r-get.jar")" 0
  is "round $r: the old id did not come back" "$(stored "$old")" absent
  is "round $r: the login works" "$(request "$J" GET /api/v1/auth/me)" 200
done

echo; echo "== GETs really overlap a logout, nothing held ($OVERLAP_ROUNDS rounds) =="
with_cookie=0; statuses=''
for ((r=1;r<=OVERLAP_ROUNDS;r++)); do
  pace; new_user; J=$work/o$r.jar
  is "round $r: login" "$(login "$J" "$EMAIL" "$PW")" 200
  old=$(session_cookie "$J"); cp "$J" "$work/o$r-old.jar"
  for i in 1 2 3 4; do cp "$J" "$work/o$r-$i.jar"; done
  for i in 1 2; do request "$work/o$r-$i.jar" GET /api/v1/auth/me > "$work/o$r-$i.status" & done
  request "$J" POST /api/v1/auth/logout > "$work/o$r-logout.status" &
  for i in 3 4; do request "$work/o$r-$i.jar" GET /api/v1/auth/me > "$work/o$r-$i.status" & done
  wait
  is "round $r: logout" "$(cat "$work/o$r-logout.status")" 204
  for i in 1 2 3 4; do
    statuses+="$(cat "$work/o$r-$i.status") "
    with_cookie=$((with_cookie + $(sends_session_cookie "$work/o$r-$i.jar")))
  done
  is "round $r: the session did not come back" "$(stored "$old")" absent
  is "round $r: no stored login for this user" "$(sessions_of "$USER_ID")" 0
  is "round $r: the old cookie gets 401" "$(request "$work/o$r-old.jar" GET /api/v1/auth/me)" 401
done
seen "GET answers: $(tr ' ' '\n' <<< "$statuses" | grep . | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
seen "GETs that sent a session cookie (whether before or after the logout is not told apart): $with_cookie of $((OVERLAP_ROUNDS * 4))"

echo; echo "== after all of it =="
docker compose exec -T app php artisan audit:verify --all > /dev/null 2>&1
is "audit:verify --all exits 0" "$?" 0
is "no server error" "$(docker compose logs --no-color --no-log-prefix --since=30m app 2>&1 | grep -cE 'INTERNAL_ERROR|local\.ERROR')" 0

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
