#!/usr/bin/env bash
# SecureFlow AI — real failures of Redis and PostgreSQL (AUDIT-REDIS-01, AUDIT-AVAIL-01, AUDIT-PWCHG-01).
# It stops and freezes containers, so it refuses to run unless the caller names this exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-failure-modes.sh
#
# The default project is always refused. Results are kept apart: before, during and after each failure.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
. scripts/lib/login-limit.sh
: "${NGINX_PORT:=8080}"
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; then
  echo "Refusing to run: this stops containers. Name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION." >&2
  exit 2
fi
for s in redis postgres; do
  id=$(docker compose ps -q "$s")
  [ -n "$id" ] || { echo "Refusing to run: $s is not running in $P." >&2; exit 2; }
  [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id")" = "$P" ] || { echo "Refusing to run: $s is not in $P." >&2; exit 2; }
done

BASE=http://localhost:$NGINX_PORT
work=$(mktemp -d)
restore() {
  docker compose unpause redis > /dev/null 2>&1
  docker compose start redis postgres > /dev/null 2>&1
  rm -rf "$work"
}
trap restore EXIT

PASSWORD_DETAIL='パスワード変更の結果を確認できませんでした。変更が確定している可能性があります。できるだけ早く、同じ内容・同じ冪等性キーで再試行してください。'
pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }
has() { if grep -qE -- "$3" <<< "$2"; then ok "$1"; else ng "$1 (no '$3')"; fi; }
hasnt() { if grep -qE -- "$3" <<< "$2"; then ng "$1 (found '$3')"; else ok "$1"; fi; }
seen() { echo "  [SEEN] $1"; }

sql() { docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "$1" < /dev/null | tr -d ' \r'; }
rc() { docker compose exec -T -e REDISCLI_AUTH="$REDIS_PASSWORD" redis redis-cli --no-auth-warning "$@" < /dev/null | tr -d '\r'; }
new_key() { cat /proc/sys/kernel/random/uuid; }
token_of() { local t; t=$(awk '$6 == "XSRF-TOKEN" { print $7 }' "$1" 2>/dev/null | tail -1); printf '%b' "${t//%/\\x}"; }

# Sets STATUS, BODY, HEADERS and SECONDS_TAKEN.
call() { # jar method path [json] [extra curl arguments]
  local jar=$1 method=$2 path=$3 json=${4:-}; shift 4 2>/dev/null || shift $#
  local args=() out
  [ -z "$json" ] || args+=(-H 'Content-Type: application/json' --data-binary "$json")
  out=$(curl -s -o "$work/body" -D "$work/headers" -w '%{http_code} %{time_total}' --max-time 90 -X "$method" -b "$jar" -c "$jar" \
    -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" -H "X-XSRF-TOKEN: $(token_of "$jar")" \
    ${args[@]+"${args[@]}"} "$@" "$BASE$path")
  STATUS=${out% *}; SECONDS_TAKEN=${out#* }
  BODY=$(cat "$work/body"); HEADERS=$(tr -d '\r' < "$work/headers")
}
csrf() { call "$1" GET /sanctum/csrf-cookie; }
login_json() { printf '{"email":"%s","password":"%s"}' "$1" "$2"; }
login() { call "$1" POST /api/v1/auth/login "$(login_json "$2" "$3")"; }
fresh_login() { : > "$1"; csrf "$1"; login "$@"; }
# Everything a client could compare, without the trace id.
shape() {
  printf '%s|%s|%s|%s' "$STATUS" "$(grep -i '^content-type:' <<< "$HEADERS")" "$(grep -i '^retry-after:' <<< "$HEADERS")" \
    "$(sed -E 's/"trace_id":"[^"]+"/"trace_id":"x"/' <<< "$BODY")"
}
is_503() { # label
  is "$1: 503" "$STATUS" 503
  has "$1: RFC 9457" "$HEADERS" '^[Cc]ontent-[Tt]ype: application/problem\+json'
  has "$1: SERVICE_UNAVAILABLE" "$BODY" '"code":"SERVICE_UNAVAILABLE"'
  is "$1: Retry-After is the fixed value" "$(sed -nE 's/^[Rr]etry-[Aa]fter: //p' <<< "$HEADERS")" 30
  seen "$1 took ${SECONDS_TAKEN}s"
}
raw() { # method path [curl arguments]: no Origin and no CSRF. Prints the status.
  local method=$1 path=$2; shift 2
  curl -s -o "$work/raw" -w '%{http_code}' --max-time 90 -X "$method" -H 'Accept: application/json' "$@" "$BASE$path"
}
user_seq=0
new_user() { # sets EMAIL and PW
  user_seq=$((user_seq+1))
  EMAIL="failure-$$-$user_seq@example.com"
  PW="start pass phrase $(new_key)"
  printf '%s\n%s\n' "$PW" "$PW" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$EMAIL" --email="$EMAIL" --role=member > /dev/null 2>&1
}
wait_healthy() { docker compose up -d --wait "$@" > /dev/null 2>&1; }
health() {
  docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' | sed 's/^/  [SEEN] /'
}
applog() { docker compose logs --no-color --no-log-prefix --since="$1" app 2>&1; }
count() { grep -c -- "$2" <<< "$1"; }
secrets_absent() { # label logs
  hasnt "$1: no password or hash" "$2" 'pass phrase|argon2id'
  hasnt "$1: no Redis password" "$2" "$REDIS_PASSWORD"
  hasnt "$1: no database password" "$2" "$DB_PASSWORD"
}
below() { # label value limit
  if awk -v v="$2" -v l="$3" 'BEGIN { exit !(v < l) }'; then ok "$1 (${2}s)"; else ng "$1 (${2}s, limit ${3}s)"; fi
}
verify_chains() {
  docker compose exec -T app php artisan audit:verify --all > "$work/verify" 2>&1
  is "$1: audit:verify --all exits 0" "$?" 0
  seen "$1: $(grep -c '"valid":true' "$work/verify") chains valid, $(grep -c '"valid":false' "$work/verify") invalid"
}
flag_ttl() { # seconds left on the DB flag, or -2
  local key; key=$(rc -n "${REDIS_CACHE_DB:-1}" --scan --pattern '*audit:db_unavailable*' | head -1)
  [ -n "$key" ] && rc -n "${REDIS_CACHE_DB:-1}" ttl "$key" || echo -2
}

redis_failure() { # title, the command that breaks it, the command that repairs it
  local title=$1 break_cmd=$2 repair_cmd=$3 mark
  echo; echo "########## $title ##########"

  echo "== before =="
  new_user; local right=$EMAIL right_pw=$PW
  new_user; local other=$EMAIL other_pw=$PW
  new_user; local locked=$EMAIL locked_pw=$PW
  local S=$work/session.jar A=$work/a.jar B=$work/b.jar C=$work/c.jar X=$work/x.jar
  fresh_login "$S" "$other" "$other_pw"; is "login is 200" "$STATUS" 200
  call "$S" GET /api/v1/auth/me; is "auth/me is 200" "$STATUS" 200
  is "liveness is 200" "$(raw GET /api/health/live)" 200
  is "readiness is 200" "$(raw GET /api/health/ready)" 200
  : > "$X"; csrf "$X"
  for i in 1 2 3 4 5; do login "$X" "$locked" 'a wrong pass phrase here'; done
  is "an account is locked in the database" "$(sql "SELECT locked_until > now() FROM users WHERE email='$locked'")" t
  for j in "$A" "$B" "$C"; do : > "$j"; csrf "$j"; done
  local rows hash; rows=$(sql 'SELECT count(*) FROM audit_logs'); hash=$(sql "SELECT md5(password) FROM users WHERE email='$other'")
  seen "audit rows before: $rows"
  mark=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  echo "== during: $title =="
  eval "$break_cmd"
  seen "redis state: $(docker compose ps -a --format '{{.State}}' redis)"
  login "$A" "$right" "$right_pw"; is_503 "right password"; local s1; s1=$(shape)
  login "$B" "$right" 'a wrong pass phrase here'; is_503 "wrong password"
  is "wrong password: identical except the trace id" "$(shape)" "$s1"
  login "$C" 'nobody-failure@example.com' 'a wrong pass phrase here'; is_503 "unknown address"
  is "unknown address: identical except the trace id" "$(shape)" "$s1"
  hasnt "the login answers say nothing about credentials" "$BODY" 'AUTH_FAILED|CURRENT_PASSWORD'
  is "login with no Origin is 503" "$(raw POST /api/v1/auth/login -H 'Content-Type: application/json' --data-binary "$(login_json "$right" "$right_pw")")" 503
  call "$S" GET /api/v1/auth/me; is_503 "authenticated API"
  local KEY; KEY=$(new_key)
  local NEW; NEW="changed pass phrase $(new_key)"
  call "$S" PATCH /api/v1/account/password "{\"current_password\":\"$other_pw\",\"new_password\":\"$NEW\"}" -H "Idempotency-Key: $KEY"
  is_503 "password change"
  has "password change: the fixed guidance" "$BODY" "$PASSWORD_DETAIL"
  local live ready; live=$(raw GET /api/health/live -H "Origin: $BASE" -H "Referer: $BASE/")
  is "liveness with the frontend Origin stays 200" "$live" 200
  ready=$(raw GET /api/health/ready); is "readiness is 503" "$ready" 503
  is "readiness says nothing else" "$(cat "$work/raw")" '{"status":"unavailable"}'
  raw GET /api/health/ready > /dev/null; raw GET /api/health/ready > /dev/null
  is "the password did not change" "$(sql "SELECT md5(password) FROM users WHERE email='$other'")" "$hash"
  is "no audit row was added" "$(sql 'SELECT count(*) FROM audit_logs')" "$rows"
  is "the failure count did not move" "$(sql "SELECT failed_login_count FROM users WHERE email='$right'")" 0
  is "the idempotency key was not stored" "$(sql "SELECT count(*) FROM users WHERE email='$other' AND password_change_key_hash IS NOT NULL")" 0
  local during; during=$(applog "$mark")
  has "the log names the outage" "$during" 'redis\.outage_started'
  seen "log lines: started=$(count "$during" 'redis.outage_started') continuing=$(count "$during" 'redis.outage_continuing') raw RedisException=$(count "$during" 'RedisException')"
  seen "causes: $(grep -oE '"cause":"[a-z_]+"' <<< "$during" | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
  is "three readiness polls log one started" "$(count "$during" 'readiness.redis.outage_started {')" 1
  is "and no line per request" "$(count "$during" 'readiness check failed')" 0
  is "and the storage check is not counted as a second failure" "$(count "$during" 'readiness.storage')" 0
  secrets_absent "log during" "$during"
  docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' worker scheduler | sed 's/^/  [SEEN] during: /'

  echo "== after: $title =="
  eval "$repair_cmd"
  wait_healthy redis
  local after_mark; after_mark=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  is "readiness is 200 at once" "$(raw GET /api/health/ready)" 200
  call "$S" GET /api/v1/auth/me
  seen "the session from before answers $STATUS"
  local session_status=$STATUS
  if [ "$session_status" = 200 ]; then
    call "$S" PATCH /api/v1/account/password "{\"current_password\":\"$other_pw\",\"new_password\":\"$NEW\"}" -H "Idempotency-Key: $KEY"
    is "the same key now changes the password" "$STATUS" 200
  else
    fresh_login "$S" "$other" "$other_pw"; is "logging in again works" "$STATUS" 200
    call "$S" PATCH /api/v1/account/password "{\"current_password\":\"$other_pw\",\"new_password\":\"$NEW\"}" -H "Idempotency-Key: $KEY"
    is "the same key now changes the password" "$STATUS" 200
  fi
  is "and it ran once" "$(sql "SELECT count(*) FROM audit_logs a JOIN users u ON u.id=a.actor_user_id WHERE u.email='$other' AND a.event_type='auth.password_changed'")" 1
  fresh_login "$A" "$right" "$right_pw"; is "login needs nothing else to recover" "$STATUS" 200
  is "the lock in the database is still there" "$(sql "SELECT locked_until > now() FROM users WHERE email='$locked'")" t
  new_user; local limited=$EMAIL
  : > "$C"; csrf "$C"
  for i in 1 2 3 4 5; do login "$C" "$limited" 'a wrong pass phrase here'; done
  login "$C" "$limited" 'a wrong pass phrase here'
  is "the rate limit works again: the sixth is 429" "$STATUS" 429
  sleep 70
  fresh_login "$B" "$locked" "$locked_pw"
  is "the right password is still refused while locked" "$STATUS" 401
  health
  local logs; logs=$(applog "$after_mark")
  has "the log records the recovery" "$(applog "$mark")" 'redis\.outage_recovered'
  has "readiness records its recovery" "$(applog "$mark")" 'readiness\.redis\.outage_recovered'
  secrets_absent "log after" "$logs"
  local ip; ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$(docker compose ps -q worker)")
  local connected=0 a; for a in $ip; do grep -q "addr=$a:" <<< "$(rc client list)" && connected=1; done
  is "the worker is connected to Redis again" "$connected" 1
  has "the scheduler reports after the failure" "$(docker compose logs --no-color --no-log-prefix --since="$after_mark" scheduler 2>&1)" 'audit\.unavailable'
  seen "restart counts: $(for s in app worker scheduler; do printf '%s=%s ' "$s" "$(docker inspect -f '{{.RestartCount}}' "$(docker compose ps -q "$s")")"; done)"
  verify_chains "after"
  docker compose exec -T app php artisan audit:status > /dev/null 2>&1; is "audit:status is 0" "$?" 0
}

postgres_failure() {
  echo; echo "########## PostgreSQL stopped, then started ##########"

  echo "== before =="
  new_user; local right=$EMAIL right_pw=$PW
  new_user; local other=$EMAIL other_pw=$PW
  local S=$work/session.jar A=$work/a.jar B=$work/b.jar C=$work/c.jar D=$work/d.jar
  fresh_login "$S" "$other" "$other_pw"; is "login is 200" "$STATUS" 200
  call "$S" GET /api/v1/auth/me; is "auth/me is 200" "$STATUS" 200
  is "readiness is 200" "$(raw GET /api/health/ready)" 200
  is "there is no flag" "$(flag_ttl)" -2
  for j in "$A" "$B" "$C" "$D"; do : > "$j"; csrf "$j"; done
  local rows; rows=$(sql 'SELECT count(*) FROM audit_logs')
  local mark; mark=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  echo "== during: stopped =="
  docker compose stop postgres > /dev/null 2>&1
  seen "postgres state: $(docker compose ps -a --format '{{.State}}' postgres)"
  login "$A" "$right" "$right_pw"; is_503 "first request (right password)"; local first_time=$SECONDS_TAKEN s1; s1=$(shape)
  below "the first request connects once and probes once" "$first_time" 10
  local t1; t1=$(flag_ttl); seen "the flag has ${t1}s left"
  if [ "$t1" -gt 0 ] && [ "$t1" -le 30 ]; then ok "the flag is set, with a TTL of at most 30s"; else ng "the flag is set (ttl $t1)"; fi
  login "$B" "$right" 'a wrong pass phrase here'; is_503 "wrong password, flag set"
  is "wrong password: identical except the trace id" "$(shape)" "$s1"
  login "$C" 'nobody-failure@example.com' 'a wrong pass phrase here'; is_503 "unknown address, flag set"
  is "unknown address: identical except the trace id" "$(shape)" "$s1"
  seen "first request ${first_time}s, flagged request ${SECONDS_TAKEN}s"
  sleep 4
  login "$D" "$right" "$right_pw"; is_503 "another request"
  local t2; t2=$(flag_ttl)
  if [ "$t2" -lt "$t1" ]; then ok "a 503 does not extend the flag ($t1 then $t2)"; else ng "a 503 does not extend the flag ($t1 then $t2)"; fi
  call "$S" GET /api/v1/auth/me; is_503 "authenticated API, flag set"
  below "authenticated API, flag set: no connection attempt" "$SECONDS_TAKEN" 1
  call "$S" PATCH /api/v1/account/password "{\"current_password\":\"$other_pw\",\"new_password\":\"changed pass phrase x\"}" -H "Idempotency-Key: $(new_key)"
  is_503 "password change, flag set"
  below "password change, flag set: no connection attempt" "$SECONDS_TAKEN" 1
  has "password change: the fixed guidance" "$BODY" "$PASSWORD_DETAIL"
  call "$work/none.jar" GET /api/v1/auth/me; is "no login, flag set: still 401" "$STATUS" 401
  call "$work/none.jar" GET /sanctum/csrf-cookie; is "the CSRF cookie needs no database" "$STATUS" 204
  is "liveness stays 200" "$(raw GET /api/health/live -H "Origin: $BASE" -H "Referer: $BASE/")" 200
  is "readiness is 503" "$(raw GET /api/health/ready)" 503
  is "readiness says nothing else" "$(cat "$work/raw")" '{"status":"unavailable"}'

  echo "== during: the TTL passes with PostgreSQL still stopped =="
  local left; left=$(flag_ttl); seen "waiting ${left}s for the flag to expire"
  sleep $((left + 2))
  is "the flag has expired" "$(flag_ttl)" -2
  # Everyone at once: one rechecks, the others are answered without waiting.
  local i; for i in 1 2 3 4 5 6 7 8; do
    curl -s -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 60 -b "$S" -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" "$BASE/api/v1/auth/me" > "$work/p$i" &
  done; wait
  seen "eight requests at the expiry: $(cat "$work"/p[1-8] | sort -k2 -n | tr '\n' ';')"
  is "all eight are 503" "$(cat "$work"/p[1-8] | grep -c '^503 ')" 8
  local slow; slow=$(cat "$work"/p[1-8] | awk '$2 >= 1' | wc -l)
  if [ "$slow" -le 1 ]; then ok "at most one of them waited for a connection ($slow)"; else ng "at most one of them waited for a connection ($slow)"; fi
  local t3; t3=$(flag_ttl); seen "the flag has ${t3}s left"
  if [ "$t3" -gt 20 ]; then ok "the check ran again and set a new flag"; else ng "the check ran again and set a new flag (ttl $t3)"; fi
  local during; during=$(applog "$mark")
  has "the log names the outage" "$during" 'db\.outage_started'
  seen "log lines: started=$(count "$during" 'db.outage_started') continuing=$(count "$during" 'db.outage_continuing') query_failed=$(count "$during" 'db.query_failed')"
  secrets_absent "log during" "$during"
  docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' worker scheduler | sed 's/^/  [SEEN] during: /'

  echo "== after: started, flag still set =="
  docker compose start postgres > /dev/null 2>&1
  wait_healthy postgres
  local after_mark; after_mark=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local t4; t4=$(flag_ttl); seen "PostgreSQL is healthy, the flag has ${t4}s left"
  if [ "$t4" -gt 1 ]; then
    : > "$B"; csrf "$B"
    login "$B" "$right" "$right_pw"; is "the flag still answers 503" "$STATUS" 503
    is "readiness asks the database itself, and is 200" "$(raw GET /api/health/ready)" 200
    sleep $(($(flag_ttl) + 2))
  else
    seen "the flag ran out before this could be checked"
  fi

  echo "== after: flag expired =="
  is "the flag has expired" "$(flag_ttl)" -2
  fresh_login "$A" "$right" "$right_pw"; is "the first request connects and logs in" "$STATUS" 200
  is "no new flag" "$(flag_ttl)" -2
  call "$A" GET /api/v1/auth/me; is "auth/me is 200" "$STATUS" 200
  call "$S" GET /api/v1/auth/me; seen "the session from before answers $STATUS"; is "the session from before still works" "$STATUS" 200
  is "the failure count did not move" "$(sql "SELECT failed_login_count FROM users WHERE email='$right'")" 0
  has "audit rows only grew by what happened after" "$(sql "SELECT count(*) > $rows FROM audit_logs")" t
  sleep 70
  health
  has "the log records the recovery" "$(applog "$mark")" 'db\.outage_recovered'
  secrets_absent "log after" "$(applog "$after_mark")"
  has "the scheduler reports after the failure" "$(docker compose logs --no-color --no-log-prefix --since="$after_mark" scheduler 2>&1)" 'audit\.unavailable'
  seen "restart counts: $(for s in app worker scheduler; do printf '%s=%s ' "$s" "$(docker inspect -f '{{.RestartCount}}' "$(docker compose ps -q "$s")")"; done)"
  verify_chains "after"
  docker compose exec -T app php artisan audit:status > /dev/null 2>&1; is "audit:status is 0" "$?" 0
}

echo "Target: $P $BASE"
clear_login_limit
redis_failure 'Redis stopped, then started' 'docker compose stop redis > /dev/null 2>&1' 'docker compose start redis > /dev/null 2>&1'
next_login_window
redis_failure 'Redis not answering (frozen), then resumed' 'docker compose pause redis > /dev/null 2>&1' 'docker compose unpause redis > /dev/null 2>&1'
next_login_window
postgres_failure

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
