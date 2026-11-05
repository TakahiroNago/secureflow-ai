#!/usr/bin/env bash
# SecureFlow AI — a response with the old session cookie that reaches the client after a logout or a password
# change (AUDIT-SESSION-03). One cookie jar takes each Set-Cookie in the order the responses arrive, as a
# browser does: same name replaces, expired removes. It is curl and this jar, not a real browser.
#
# [PASS]/[FAIL] are about authentication. [SEEN] lines report what happened to the cookies and to logging in
# again: those are findings, not expectations.
#
# It adds a test-only provider to bootstrap/providers.php for its own duration, so it refuses to run unless
# the caller names this exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-session-cookie-order.sh
#
# HELD_ROUNDS=0 runs only the rounds where nothing is held, the part whose result depends on timing.
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

HELD_ROUNDS=${HELD_ROUNDS:-20}; NATURAL_ROUNDS=${NATURAL_ROUNDS:-20}
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
token_of() { local t; t=$(awk -F '\t' '$6 == "XSRF-TOKEN" { print $7 }' "$1" | tail -1); printf '%b' "${t//%/\\x}"; }
session_cookie() { awk -F '\t' '$6 ~ /session/ { print $7 }' "$1" | tail -1; }

# Sends with what the jar holds now, and does not touch the jar: the caller applies the answer when it arrives.
send() { # jar method path json [curl arguments]: prints the status
  local jar=$1 method=$2 path=$3 json=${4:-}; shift 4
  local args=()
  [ -z "$json" ] || args+=(-H 'Content-Type: application/json' --data-binary "$json")
  curl -s -o "$jar.body" -D "$jar.headers" -w '%{http_code}' --max-time 60 -X "$method" -b "$jar" \
    -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" -H "X-XSRF-TOKEN: $(token_of "$jar")" \
    ${args[@]+"${args[@]}"} "$@" "$BASE$path"
}
# What a browser does with a response: a Set-Cookie replaces the cookie of that name, or removes an expired one.
apply_cookies() { # jar headers
  local line pair name value lower
  while IFS= read -r line; do
    line=${line%$'\r'}; lower=${line,,}
    case "$lower" in set-cookie:*) ;; *) continue ;; esac
    pair=${line#*: }; pair=${pair%%;*}; name=${pair%%=*}; value=${pair#*=}
    awk -F '\t' -v n="$name" '$6 != n' "$1" > "$1.new"
    case "$lower" in
      *max-age=0*) ;;
      *) printf 'localhost\tFALSE\t/\tFALSE\t0\t%s\t%s\n' "$name" "$value" >> "$1.new" ;;
    esac
    mv "$1.new" "$1"
    [ "$name" != "$(basename "$1")" ] || true
  done < "$2"
}
sends_session_cookie() { grep -ciE '^set-cookie: [a-z0-9_-]*session' "$1" | tr -d ' '; }
sends_csrf_cookie() { grep -ciE '^set-cookie: xsrf-token' "$1" | tr -d ' '; }
header_session_cookie() { grep -iE '^set-cookie: [a-z0-9_-]*session' "$1" | tail -1 | sed -E 's/^[^:]*: [^=]*=([^;]*).*/\1/' | tr -d '\r'; }

# A hash of the id a cookie names, to compare cookies whose encrypted values always differ. Prints no id.
id_of() {
  [ -n "$1" ] || { echo none; return; }
  docker compose exec -T app php -r '
    chdir("/var/www/html"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";
    $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    echo hash("sha256", Illuminate\Cookie\CookieValuePrefix::remove(Illuminate\Support\Facades\Crypt::decrypt(urldecode($argv[1]), false)));' "$1" 2>/dev/null
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
sessions_of() {
  rc eval "local n=0 for _,k in ipairs(redis.call('KEYS','*')) do if redis.call('TYPE',k).ok=='string' then local v=redis.call('GET',k) if v and string.find(v,'login_web_',1,true) and string.find(v,ARGV[1],1,true) then n=n+1 end end end return n" 0 "$1"
}
retired_ttl() { # hash of the id: seconds left on its retirement record
  rc eval "local k=redis.call('KEYS','*session_retired:'..ARGV[1]) if k[1] then return redis.call('TTL',k[1]) end return -2" 0 "$1"
}
sync_path() { echo "/tmp/session-race/$1"; }
reached() { local i; for ((i=0;i<150;i++)); do docker compose exec -T app test -f "$(sync_path "$1").reached" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
release() { docker compose exec -T app touch "$(sync_path "$1").release" 2>/dev/null; }

logins=0
# Stays under the limit per address (30 a minute). Called in this shell: the count would be lost in a $(...).
pace() { logins=$((logins+1)); if [ $((logins % 20)) -eq 0 ]; then next_login_window; fi; }
get_csrf() { send "$1" GET /sanctum/csrf-cookie '' > /dev/null; apply_cookies "$1" "$1.headers"; }
login_with() { # jar email password: applies the answer, prints the status
  local status
  status=$(send "$1" POST /api/v1/auth/login "$(printf '{"email":"%s","password":"%s"}' "$2" "$3")")
  apply_cookies "$1" "$1.headers"; echo "$status"
}
start_login() { : > "$1"; get_csrf "$1"; login_with "$1" "$2" "$3"; }
new_user() {
  EMAIL="order-$$-$RANDOM-$RANDOM@example.com"; PW="start pass phrase $(new_key)"
  printf '%s\n%s\n' "$PW" "$PW" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$EMAIL" --email="$EMAIL" --role=member > /dev/null 2>&1
  USER_ID=$(sql "SELECT id FROM users WHERE email='$EMAIL'")
}
tally() { tr ' ' '\n' <<< "$1" | grep . | sort | uniq -c | tr -s ' ' | tr '\n' ';'; }

# What the browser can do next with the jar it ended up with, as it is, then with its cookies cleared.
try_again() { # jar password
  local jar=$1 password=$2 status
  pace
  send "$jar" GET /sanctum/csrf-cookie '' > /dev/null
  csrf_session_cookies+="$(sends_session_cookie "$jar.headers") "; csrf_csrf_cookies+="$(sends_csrf_cookie "$jar.headers") "
  apply_cookies "$jar" "$jar.headers"
  is "round $r: csrf-cookie leaves the jar with the old id" "$(id_of "$(session_cookie "$jar")")" "$old_id"
  is "round $r: and the old id is still not stored" "$(stored "$old")" absent
  status=$(login_with "$jar" "$EMAIL" "$password")
  relogin+="$status "
  # curl sends no Sec-Fetch-Site, so the token is compared, and it is the one of the retired session.
  is "round $r: logging in again, cookies as they are" "$status" 419
  pace
  status=$(start_login "$jar" "$EMAIL" "$password")
  cleared+="$status "
  is "round $r: with the cookies cleared, logging in" "$status" 200
  is "round $r: and that login works" "$(send "$jar" GET /api/v1/auth/me '')" 200
}

echo "Target: $P $BASE, $HELD_ROUNDS held rounds, $NATURAL_ROUNDS natural rounds"
docker compose exec -T app php artisan db:seed --force > /dev/null 2>&1
clear_login_limit

echo; echo "== the GET's finished response is held until the logout has reached the client ($HELD_ROUNDS rounds) =="
later=0; carried_old=0; carried_csrf=0; after_logout_replaced=0; after_logout_removed=0; final_old=0; me_cookies=0; ttls=''
relogin=''; cleared=''; csrf_session_cookies=''; csrf_csrf_cookies=''
for ((r=1;r<=HELD_ROUNDS;r++)); do
  pace; new_user; J=$work/l$r.jar; G=$work/l$r-get.jar; name="logout-order-$$-$r"
  is "round $r: login" "$(start_login "$J" "$EMAIL" "$PW")" 200
  old=$(session_cookie "$J"); old_id=$(id_of "$old"); cp "$J" "$G"
  ( send "$G" GET /api/v1/auth/me '' -H "X-Test-Response-Hold: $name" > "$G.status"; date +%s%N > "$G.arrived" ) &
  if reached "$name"; then ok "round $r: the response is finished and held"; else ng "round $r: the response is finished and held"; fi
  is "round $r: the logout" "$(send "$J" POST /api/v1/auth/logout '')" 204
  date +%s%N > "$J.arrived"; apply_cookies "$J" "$J.headers"
  after=$(session_cookie "$J")
  if [ -z "$after" ]; then after_logout_removed=$((after_logout_removed+1)); elif [ "$(id_of "$after")" != "$old_id" ]; then after_logout_replaced=$((after_logout_replaced+1)); fi
  is "round $r: logged out, before the held response arrives" "$(send "$J" GET /api/v1/auth/me '')" 401
  apply_cookies "$J" "$J.headers"
  is "round $r: the session is gone" "$(stored "$old")" absent
  release "$name"; wait
  is "round $r: the held GET answers" "$(cat "$G.status")" 200
  [ "$(cat "$G.arrived")" -gt "$(cat "$J.arrived")" ] && later=$((later+1))
  [ "$(id_of "$(header_session_cookie "$G.headers")")" = "$old_id" ] && carried_old=$((carried_old+1))
  [ "$(sends_csrf_cookie "$G.headers")" -gt 0 ] && carried_csrf=$((carried_csrf+1))
  apply_cookies "$J" "$G.headers"
  final=$(session_cookie "$J"); [ "$(id_of "$final")" = "$old_id" ] && final_old=$((final_old+1))
  is "round $r: the jar as it ended up gets 401" "$(send "$J" GET /api/v1/auth/me '')" 401
  me_cookies=$((me_cookies + $(sends_session_cookie "$J.headers")))
  apply_cookies "$J" "$J.headers"
  is "round $r: the old id is not back" "$(stored "$old")" absent
  is "round $r: no stored login for this user" "$(sessions_of "$USER_ID")" 0
  ttls+="$(retired_ttl "$old_id") "
  try_again "$J" "$PW"
done
seen "the GET arrived after the logout: $later of $HELD_ROUNDS"
seen "its response carried the old session id: $carried_old of $HELD_ROUNDS, and a CSRF cookie: $carried_csrf"
seen "the logout replaced the jar's session cookie with a new id: $after_logout_replaced; removed it: $after_logout_removed"
seen "the jar ended up with the old id: $final_old of $HELD_ROUNDS"
seen "session cookies sent back to that jar by auth/me: $me_cookies"
seen "seconds left on the retirement record: $(tr ' ' '\n' <<< "$ttls" | grep . | sort -n | sed -n '1p;$p' | tr '\n' ' ')"
seen "with that jar, csrf-cookie sent a session cookie: $(tally "$csrf_session_cookies")"
seen "with that jar, csrf-cookie sent a CSRF cookie: $(tally "$csrf_csrf_cookies")"
seen "with that jar, logging in again: $(tally "$relogin")"
seen "after clearing the cookies, logging in again: $(tally "$cleared")"

echo; echo "== the GET's finished response is held until the password change has reached the client ($HELD_ROUNDS rounds) =="
later=0; carried_old=0; final_old=0; final_new=0; before_ok=0; server_ok=0; relogin=''; cleared=''; csrf_session_cookies=''; csrf_csrf_cookies=''; final_me=''
for ((r=1;r<=HELD_ROUNDS;r++)); do
  pace; new_user; J=$work/p$r.jar; G=$work/p$r-get.jar; name="password-order-$$-$r"; NEW="changed pass phrase $(new_key)"
  is "round $r: login" "$(start_login "$J" "$EMAIL" "$PW")" 200
  old=$(session_cookie "$J"); old_id=$(id_of "$old"); cp "$J" "$G"
  ( send "$G" GET /api/v1/auth/me '' -H "X-Test-Response-Hold: $name" > "$G.status"; date +%s%N > "$G.arrived" ) &
  if reached "$name"; then ok "round $r: the response is finished and held"; else ng "round $r: the response is finished and held"; fi
  is "round $r: the change" "$(send "$J" PATCH /api/v1/account/password "{\"current_password\":\"$PW\",\"new_password\":\"$NEW\"}" -H "Idempotency-Key: $(new_key)")" 200
  date +%s%N > "$J.arrived"; apply_cookies "$J" "$J.headers"
  new_cookie=$(session_cookie "$J"); new_id=$(id_of "$new_cookie"); cp "$J" "$work/p$r-new.jar"
  [ "$new_id" != "$old_id" ] && ok "round $r: the change gave a new id" || ng "round $r: the change gave a new id"
  [ "$(send "$work/p$r-new.jar" GET /api/v1/auth/me '')" = 200 ] && before_ok=$((before_ok+1))
  release "$name"; wait
  [ "$(cat "$G.arrived")" -gt "$(cat "$J.arrived")" ] && later=$((later+1))
  [ "$(id_of "$(header_session_cookie "$G.headers")")" = "$old_id" ] && carried_old=$((carried_old+1))
  apply_cookies "$J" "$G.headers"
  final_id=$(id_of "$(session_cookie "$J")")
  [ "$final_id" = "$old_id" ] && final_old=$((final_old+1)); [ "$final_id" = "$new_id" ] && final_new=$((final_new+1))
  status=$(send "$J" GET /api/v1/auth/me ''); final_me+="$status "; apply_cookies "$J" "$J.headers"
  is "round $r: the old id is not back" "$(stored "$old")" absent
  # The session the client lost is still there. Reaching it needs the cookie it no longer has.
  is "round $r: the new session still exists on the server" "$(stored "$new_cookie")" login
  [ "$(send "$work/p$r-new.jar" GET /api/v1/auth/me '')" = 200 ] && server_ok=$((server_ok+1))
  pace
  is "round $r: the old password does not log in" "$(start_login "$work/p$r-oldpw.jar" "$EMAIL" "$PW")" 401
  try_again "$J" "$NEW"
done
seen "the GET arrived after the change: $later of $HELD_ROUNDS"
seen "its response carried the old session id: $carried_old of $HELD_ROUNDS"
seen "the new session worked before the held response arrived: $before_ok of $HELD_ROUNDS"
seen "the jar ended up with the old id: $final_old, with the new id: $final_new, of $HELD_ROUNDS"
seen "auth/me with the jar as it ended up: $(tally "$final_me")"
seen "the new session, with a copy of its cookie, afterwards: $server_ok of $HELD_ROUNDS answered 200"
seen "with that jar, csrf-cookie sent a session cookie: $(tally "$csrf_session_cookies")"
seen "with that jar, csrf-cookie sent a CSRF cookie: $(tally "$csrf_csrf_cookies")"
seen "with that jar, logging in again: $(tally "$relogin")"
seen "after clearing the cookies, logging in again: $(tally "$cleared")"

# Nothing held: how often it happens by itself here, on one machine with no network in between.
natural() { # kind rounds
  local kind=$1 rounds=$2 r i
  local total=0 with_cookie=0 after=0 overwritten=0 final_me=''
  for ((r=1;r<=rounds;r++)); do
    pace; new_user; J=$work/n$kind$r.jar; NEW="changed pass phrase $(new_key)"
    is "round $r: login" "$(start_login "$J" "$EMAIL" "$PW")" 200
    old=$(session_cookie "$J"); old_id=$(id_of "$old")
    for i in 1 2 3 4; do cp "$J" "$J.g$i"; done
    for i in 1 2; do ( send "$J.g$i" GET /api/v1/auth/me '' > /dev/null; date +%s%N > "$J.g$i.arrived" ) & done
    if [ "$kind" = logout ]; then
      ( send "$J" POST /api/v1/auth/logout '' > "$J.status"; date +%s%N > "$J.arrived" ) &
      want=204
    else
      ( send "$J" PATCH /api/v1/account/password "{\"current_password\":\"$PW\",\"new_password\":\"$NEW\"}" -H "Idempotency-Key: $(new_key)" > "$J.status"; date +%s%N > "$J.arrived" ) &
      want=200
    fi
    for i in 3 4; do ( send "$J.g$i" GET /api/v1/auth/me '' > /dev/null; date +%s%N > "$J.g$i.arrived" ) & done
    wait
    is "round $r: the $kind" "$(cat "$J.status")" "$want"
    # Apply everything in the order it arrived.
    { echo "$(cat "$J.arrived") $J"; for i in 1 2 3 4; do echo "$(cat "$J.g$i.arrived") $J.g$i"; done; } | sort -n | awk '{print $2}' > "$J.order"
    seen_main=0
    while read -r f; do
      if [ "$f" = "$J" ]; then seen_main=1; else
        total=$((total+1))
        if [ "$(sends_session_cookie "$f.headers")" -gt 0 ]; then
          with_cookie=$((with_cookie+1)); [ "$seen_main" = 1 ] && after=$((after+1))
        fi
      fi
      apply_cookies "$J" "$f.headers"
    done < "$J.order"
    [ "$(id_of "$(session_cookie "$J")")" = "$old_id" ] && overwritten=$((overwritten+1))
    status=$(send "$J" GET /api/v1/auth/me ''); final_me+="$status "
    is "round $r: the old id is not back" "$(stored "$old")" absent
  done
  seen "$kind: GETs $total, sent a session cookie $with_cookie, of those arrived after the $kind $after"
  seen "$kind: the jar ended up with the old id in $overwritten of $rounds rounds"
  seen "$kind: auth/me with the jar as it ended up: $(tally "$final_me")"
}
echo; echo "== nothing held: 4 GETs and a logout ($NATURAL_ROUNDS rounds) =="
natural logout "$NATURAL_ROUNDS"
echo; echo "== nothing held: 4 GETs and a password change ($NATURAL_ROUNDS rounds) =="
natural password "$NATURAL_ROUNDS"

echo; echo "== after all of it =="
docker compose exec -T app php artisan audit:verify --all > /dev/null 2>&1
is "audit:verify --all exits 0" "$?" 0
is "no server error" "$(docker compose logs --no-color --no-log-prefix --since=30m app 2>&1 | grep -cE 'INTERNAL_ERROR|local\.ERROR')" 0

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
