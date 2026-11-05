#!/usr/bin/env bash
# SecureFlow AI — PATCH /api/v1/account/password under real parallel HTTP requests, through nginx and
# php-fpm, with real Redis sessions and real row locks (AUDIT-PWCHG-01). It creates users, so it runs
# only on a throwaway stack: a project other than the default one. It needs seeded, migrated data.
#
# It asserts what must hold however the requests interleave, and prints each outcome. Which request
# wins, and whether a loser sees 200 or 401, depends on timing.
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
URI=/api/v1/account/password
ROUNDS=${ROUNDS:-3}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pass=0; fail=0; findings=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }
note() { echo "  [NOTE] $1"; findings=$((findings+1)); }

sql() { docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "$1" < /dev/null; }
new_key() { cat /proc/sys/kernel/random/uuid; }
token_of() { local t; t=$(awk '$6 == "XSRF-TOKEN" { print $7 }' "$1" | tail -1); printf '%b' "${t//%/\\x}"; }

csrf() { curl -s -o /dev/null -b "$1" -c "$1" -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" "$BASE/sanctum/csrf-cookie"; }
request() { # jar method path [json] [extra curl arguments]: prints the status
  local jar=$1 method=$2 path=$3 json=${4:-}; shift 4 2>/dev/null || shift $#
  local args=()
  [ -z "$json" ] || args+=(-H 'Content-Type: application/json' --data-binary "$json")
  curl -s -o "$jar.body" -w '%{http_code}' --max-time 60 -X "$method" -b "$jar" -c "$jar" \
    -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" -H "X-XSRF-TOKEN: $(token_of "$jar")" \
    ${args[@]+"${args[@]}"} "$@" "$BASE$path"
}
login() { # jar email password: prints the status
  : > "$1"; csrf "$1"
  request "$1" POST /api/v1/auth/login "$(printf '{"email":"%s","password":"%s"}' "$2" "$3")"
}
change_json() { printf '{"current_password":"%s","new_password":"%s"}' "$1" "$2"; }

user_seq=0
EMAIL=''; PW=''
new_user() {
  user_seq=$((user_seq+1))
  EMAIL="concurrent-$$-$user_seq@example.com"
  PW="start pass phrase $(new_key)"
  printf '%s\n%s\n' "$PW" "$PW" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$EMAIL" --email="$EMAIL" --role=member > /dev/null 2>&1
}
events() { sql "SELECT count(*) FROM audit_logs a JOIN users u ON u.id = a.actor_user_id WHERE u.email='$1' AND a.event_type='auth.password_changed'" | tr -d ' '; }

# Each request gets its own copy of the jar, as parallel tabs would, and records when it ran.
fire() { # index jar key json
  local i=$1 jar=$2 key=$3 json=$4
  cp "$jar" "$work/r$i.jar"
  local started; started=$(date +%s%N)
  request "$work/r$i.jar" PATCH "$URI" "$json" -H "Idempotency-Key: $key" > "$work/r$i.status"
  echo "$started $(date +%s%N)" > "$work/r$i.time"
}
wait_all() { wait; }
overlapped() { # count: did every request start before the first one finished?
  local n=$1 last_start=0 first_end=0 i s e
  for ((i=0;i<n;i++)); do
    read -r s e < "$work/r$i.time"
    [ "$s" -gt "$last_start" ] && last_start=$s
    if [ "$first_end" -eq 0 ] || [ "$e" -lt "$first_end" ]; then first_end=$e; fi
  done
  [ "$last_start" -lt "$first_end" ] && ok "the requests really overlapped" || note "the requests did not all overlap in this round"
}
changed_at() { sed -nE 's/.*"password_changed_at":"([^"]+)".*/\1/p' "$work/r$1.jar.body"; }

rc() { docker compose exec -T -e REDISCLI_AUTH="$REDIS_PASSWORD" redis redis-cli --no-auth-warning "$@" < /dev/null | tr -d '\r'; }
user_id() { sql "SELECT id FROM users WHERE email='$1'" | tr -d ' '; }
# Stored sessions with this user's login. Reads nothing out.
sessions_of() {
  rc eval "local n=0 for _,k in ipairs(redis.call('KEYS','*')) do if redis.call('TYPE',k).ok=='string' then local v=redis.call('GET',k) if v and string.find(v,'login_web_',1,true) and string.find(v,ARGV[1],1,true) then n=n+1 end end end return n" 0 "$1"
}
session_cookie() { awk '$6 ~ /session/ { print $7 }' "$1" | tail -1; }

echo "Target: $COMPOSE_PROJECT_NAME $BASE"
clear_login_limit
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "== same key, same content, four parallel requests of one session =="
for ((round=1;round<=ROUNDS;round++)); do
  new_user; jar=$work/a$round.jar; other=$work/a$round-other.jar
  is "round $round: login" "$(login "$jar" "$EMAIL" "$PW")" 200
  is "round $round: another session exists from before" "$(login "$other" "$EMAIL" "$PW")" 200
  uid=$(user_id "$EMAIL"); before=$(session_cookie "$jar")
  is "round $round: two stored sessions before" "$(sessions_of "$uid")" 2
  key=$(new_key); NEW="changed pass phrase $(new_key)"; json=$(change_json "$PW" "$NEW"); n=4
  for ((i=0;i<n;i++)); do fire "$i" "$jar" "$key" "$json" & done; wait_all
  overlapped "$n"
  statuses=''; winners=0; rotated=0; bad=0; winner=-1
  for ((i=0;i<n;i++)); do
    s=$(cat "$work/r$i.status"); statuses+="$s "
    [ "$(session_cookie "$work/r$i.jar")" != "$before" ] && rotated=$((rotated+1))
    case "$s" in
      200) winners=$((winners+1)); winner=$i ;;
      401) ;;
      419) note "round $round: request $i got 419" ;;
      *) bad=1 ;;
    esac
  done
  echo "  round $round statuses: $statuses"
  is "round $round: only 200, 401 or 419" "$bad" 0
  is "round $round: exactly one request got 200" "$winners" 1
  is "round $round: exactly one response has a new session cookie" "$rotated" 1
  is "round $round: one password_changed event" "$(events "$EMAIL")" 1
  valid=0
  for ((i=0;i<n;i++)); do
    s=$(request "$work/r$i.jar" GET /api/v1/auth/me); [ "$s" = 200 ] && valid=$((valid+1))
    [ "$i" = "$winner" ] && is "round $round: the session of the 200 works" "$s" 200
    [ "$i" = "$winner" ] || is "round $round: request $i has no working session" "$s" 401
  done
  is "round $round: exactly one working session id" "$valid" 1
  is "round $round: the session from before is invalid" "$(request "$other" GET /api/v1/auth/me)" 401
  is "round $round: one stored session remains" "$(sessions_of "$uid")" 1
  is "round $round: the old password is refused" "$(login "$work/o.jar" "$EMAIL" "$PW")" 401
  retry=$work/a$round-retry.jar
  is "round $round: logging in with the new password" "$(login "$retry" "$EMAIL" "$NEW")" 200
  is "round $round: the same key and content after logging in is 200" "$(request "$retry" PATCH "$URI" "$json" -H "Idempotency-Key: $key")" 200
  is "round $round: and nothing ran again" "$(events "$EMAIL")" 1
  is "round $round: that session works" "$(request "$retry" GET /api/v1/auth/me)" 200
  is "round $round: the winner still works" "$(request "$work/r$winner.jar" GET /api/v1/auth/me)" 200
  is "round $round: two stored sessions, no more" "$(sessions_of "$uid")" 2
done
next_login_window

echo "== same key, different content, same session =="
for ((round=1;round<=ROUNDS;round++)); do
  new_user; jar=$work/b$round.jar
  is "round $round: login" "$(login "$jar" "$EMAIL" "$PW")" 200
  key=$(new_key); X="content x pass phrase $(new_key)"; Y="content y pass phrase $(new_key)"; n=4
  fire 0 "$jar" "$key" "$(change_json "$PW" "$X")" & fire 1 "$jar" "$key" "$(change_json "$PW" "$Y")" &
  fire 2 "$jar" "$key" "$(change_json "$PW" "$X")" & fire 3 "$jar" "$key" "$(change_json "$PW" "$Y")" &
  wait_all
  overlapped "$n"
  sx="$(cat "$work/r0.status") $(cat "$work/r2.status")"; sy="$(cat "$work/r1.status") $(cat "$work/r3.status")"
  echo "  round $round content x: $sx / content y: $sy"
  is "round $round: one password_changed event" "$(events "$EMAIL")" 1
  lx=$(login "$work/o.jar" "$EMAIL" "$X"); ly=$(login "$work/o.jar" "$EMAIL" "$Y")
  is "round $round: exactly one content became the password" "$(printf '%s %s' "$lx" "$ly" | tr ' ' '\n' | grep -c '^200$')" 1
  is "round $round: the old password is refused" "$(login "$work/o.jar" "$EMAIL" "$PW")" 401
  if [ "$lx" = 200 ]; then win=$sx; lose=$sy; else win=$sy; lose=$sx; fi
  grep -q 200 <<< "$lose" && ng "round $round: the losing content got 200 ($lose)" || ok "round $round: the losing content did not get 200 ($lose)"
  grep -q 409 <<< "$lose $win" && ok "round $round: a conflict was reported as 409" || note "round $round: no 409 this round (winner $win, loser $lose)"
  bad=$(tr ' ' '\n' <<< "$sx $sy" | grep -vE '^(200|401|409|419)$' | grep -c .)
  is "round $round: only 200, 401, 409 or 419" "$bad" 0
done
next_login_window

echo "== different keys, same content, same session =="
for ((round=1;round<=ROUNDS;round++)); do
  new_user; jar=$work/c$round.jar
  is "round $round: login" "$(login "$jar" "$EMAIL" "$PW")" 200
  NEW="changed pass phrase $(new_key)"; json=$(change_json "$PW" "$NEW"); n=3
  for ((i=0;i<n;i++)); do fire "$i" "$jar" "$(new_key)" "$json" & done; wait_all
  overlapped "$n"
  statuses="$(cat "$work/r0.status") $(cat "$work/r1.status") $(cat "$work/r2.status")"
  echo "  round $round statuses: $statuses"
  is "round $round: one password_changed event" "$(events "$EMAIL")" 1
  is "round $round: exactly one 200" "$(tr ' ' '\n' <<< "$statuses" | grep -c '^200$')" 1
  is "round $round: the new password works" "$(login "$work/o.jar" "$EMAIL" "$NEW")" 200
done
next_login_window

echo "== same key, same content, two sessions =="
for ((round=1;round<=ROUNDS;round++)); do
  new_user; ja=$work/d$round-a.jar; jb=$work/d$round-b.jar
  is "round $round: first login" "$(login "$ja" "$EMAIL" "$PW")" 200
  is "round $round: second login" "$(login "$jb" "$EMAIL" "$PW")" 200
  key=$(new_key); NEW="changed pass phrase $(new_key)"; json=$(change_json "$PW" "$NEW"); n=2
  fire 0 "$ja" "$key" "$json" & fire 1 "$jb" "$key" "$json" & wait_all
  overlapped "$n"
  echo "  round $round statuses: $(cat "$work/r0.status") $(cat "$work/r1.status")"
  is "round $round: one password_changed event" "$(events "$EMAIL")" 1
  winners=0
  for i in 0 1; do
    s=$(cat "$work/r$i.status"); after=$(request "$work/r$i.jar" GET /api/v1/auth/me)
    if [ "$s" = 200 ]; then
      winners=$((winners+1)); is "round $round: the session that got 200 stays" "$after" 200
    else
      is "round $round: the other session from before the change ends ($s)" "$after" 401
    fi
  done
  is "round $round: exactly one session got 200" "$winners" 1
  is "round $round: the new password works" "$(login "$work/o.jar" "$EMAIL" "$NEW")" 200
done

echo "== after all of it =="
docker compose exec -T app php artisan audit:verify --all > "$work/verify" 2>&1
is "audit:verify --all succeeds" "$?" 0
is "no server error in the app log" "$(docker compose logs --no-color --no-log-prefix --since="$started_at" app 2>&1 | grep -c 'INTERNAL_ERROR\|production.ERROR\|local.ERROR')" 0
logs=$(docker compose logs --no-color --no-log-prefix --since="$started_at" app nginx 2>&1)
grep -qE 'pass phrase|argon2id' <<< "$logs" && ng "no password or hash in the logs" || ok "no password or hash in the logs"

echo
echo "Result: $pass passed, $fail failed, $findings notes"
[ "$fail" -eq 0 ]
