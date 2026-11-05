#!/usr/bin/env bash
# SecureFlow AI — what the worker does to a job when Redis fails (AUDIT-WORKER-01). It stops and kills
# Redis, so it refuses to run unless the caller names this exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-worker-redis-failure.sh
#
# The application has no jobs and no failed_jobs table yet (step 1-6). This pushes a test job, and for
# one scenario creates a temporary failed_jobs table in this project's database and drops it again.
# [SEEN] lines report behaviour: whether it is acceptable is for the review, not for this script.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; then
  echo "Refusing to run: this stops containers. Name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION." >&2
  exit 2
fi
for s in redis worker postgres; do
  id=$(docker compose ps -q "$s")
  [ -n "$id" ] && [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id")" = "$P" ] \
    || { echo "Refusing to run: $s is not running in $P." >&2; exit 2; }
done

su_sql() { docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "$1" < /dev/null | tr -d ' \r'; }
restore() {
  docker compose start redis worker > /dev/null 2>&1
  su_sql 'DROP TABLE IF EXISTS failed_jobs' > /dev/null 2>&1
}
trap restore EXIT

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }
seen() { echo "  [SEEN] $1"; }

rc() { docker compose exec -T -e REDISCLI_AUTH="$REDIS_PASSWORD" redis redis-cli --no-auth-warning "$@" < /dev/null | tr -d '\r'; }
depth() { # waiting / reserved / delayed
  local prefix k; k=$(rc --scan --pattern '*queues:default*' | head -5)
  prefix=$(rc config get databases > /dev/null; echo "${REDIS_PREFIX:-}")
  local w=0 r=0 d=0 key
  for key in $k; do
    case "$key" in
      *:reserved) r=$(rc zcard "$key") ;;
      *:delayed) d=$(rc zcard "$key") ;;
      *:notify) ;;
      *queues:default) w=$(rc llen "$key") ;;
    esac
  done
  echo "waiting=$w reserved=$r delayed=$d"
}
push() { # id seconds. Prints what the producer saw.
  docker compose exec -T app php -r '
    chdir("/var/www/html"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";
    $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    try { Illuminate\Support\Facades\Queue::connection("redis")->push(new Tests\Support\QueueProbeJob($argv[1], (int) $argv[2])); echo "pushed"; }
    catch (Throwable $e) { echo "refused: ".get_class($e); }' "$1" "$2" 2>/dev/null
}
runs() { docker compose exec -T worker sh -c "grep -c start /tmp/queue-probe/$1.log 2>/dev/null || true" 2>/dev/null | tr -d '\r' | tail -1; }
finished() { docker compose exec -T worker sh -c "grep -c finish /tmp/queue-probe/$1.log 2>/dev/null || true" 2>/dev/null | tr -d '\r' | tail -1; }
wait_for() { # seconds, command that must print a number above 0
  local i
  for ((i=0;i<$1;i++)); do local v; v=$(eval "$2"); [ "${v:-0}" -gt 0 ] 2>/dev/null && return 0; sleep 1; done
  return 1
}
restarts() { docker inspect -f '{{.RestartCount}}' "$(docker compose ps -q worker)"; }
wait_worker() { # until the worker runs a new job
  local id="recover-$RANDOM-$$" i
  for ((i=0;i<60;i++)); do [ "$(docker compose ps --format '{{.State}}' worker)" = running ] && break; sleep 2; done
  push "$id" 0 > /dev/null
  if wait_for 90 "finished $id"; then ok "$1: the worker runs a new job"; else ng "$1: the worker runs a new job"; fi
  is "$1: that job ran once" "$(runs "$id")" 1
}
redis_back() { docker compose start redis > /dev/null 2>&1; docker compose up -d --wait redis > /dev/null 2>&1; }
worker_log_since() { docker compose logs --no-color --no-log-prefix --since="$1" worker 2>&1; }

queued_ids() { # the ids of the jobs in Redis, from their payloads
  local key out=''
  for key in $(rc --scan --pattern '*queues:default' ); do out+="waiting: $(rc lrange "$key" 0 -1 | grep -oE '(normal|waiting|running|recover|dropped)[a-z-]*-[0-9]+(-[0-9]+)?' | sort -u | tr '\n' ' ') "; done
  for key in $(rc --scan --pattern '*queues:default:reserved'); do out+="reserved: $(rc zrange "$key" 0 -1 | grep -oE '(normal|waiting|running|recover|dropped)[a-z-]*-[0-9]+(-[0-9]+)?' | sort -u | tr '\n' ' ') "; done
  echo "${out:-none}"
}
timeline() { docker compose exec -T worker sh -c "cat /tmp/queue-probe/$1.log 2>/dev/null" 2>/dev/null | tr -d '\r' | tr '\n' ';'; }
redis_state() { docker compose ps -a --format '{{.State}}' redis; }
# A throwaway project's Redis only: each scenario starts with an empty queue and a snapshot of it.
clean_queue() { rc flushdb > /dev/null; rc save > /dev/null; }
worker_results() { # lines for the test job since a time
  worker_log_since "$1" | grep -E 'QueueProbeJob' | sed -E 's/ +/ /g; s/\.{2,}//; s/Tests.Support.QueueProbeJob //' | tr '\n' ';'
}

echo "Target: $P"
echo "retry_after=${REDIS_QUEUE_RETRY_AFTER:-90}, worker: $(docker inspect -f '{{join .Config.Cmd " "}}' "$(docker compose ps -q worker)")"
seen "failed_jobs before: $(su_sql "SELECT to_regclass('public.failed_jobs')")"

echo; echo "########## 1. no failure ##########"
id="normal-$$"; is "the job is accepted" "$(push "$id" 1)" pushed
if wait_for 30 "finished $id"; then ok "it finishes"; else ng "it finishes"; fi
is "it ran once" "$(runs "$id")" 1
seen "queue: $(depth)"

echo; echo "########## 2. pushing while Redis is stopped ##########"
docker compose stop redis > /dev/null 2>&1
out=$(push "dropped-$$" 0); seen "the producer sees: $out"
case "$out" in refused*) ok "the producer is told" ;; *) ng "the producer is told ($out)" ;; esac
redis_back
wait_worker "after"

echo; echo "########## 3. a waiting job, Redis stopped normally ##########"
docker compose stop worker > /dev/null 2>&1
id="waiting-$$"; is "the job is accepted" "$(push "$id" 0)" pushed
seen "queue before the stop: $(depth)"
docker compose stop redis > /dev/null 2>&1
redis_back
seen "queue after the restart: $(depth) [$(queued_ids)]"
docker compose start worker > /dev/null 2>&1
if wait_for 60 "finished $id"; then ok "the job survives and runs"; else ng "the job survives and runs"; fi
is "it ran once" "$(runs "$id")" 1
done_job=$id

echo; echo "########## 4. a waiting job, Redis killed ##########"
docker compose stop worker > /dev/null 2>&1
id="waiting-killed-$$"; is "the job is accepted" "$(push "$id" 0)" pushed
seen "queue before the kill: $(depth) [$(queued_ids)]"
docker compose kill redis > /dev/null 2>&1
seen "redis state: $(redis_state)"
redis_back
seen "queue after the restart: $(depth) [$(queued_ids)]"
docker compose start worker > /dev/null 2>&1
if wait_for 60 "finished $id"; then seen "the job pushed before the kill ran"; else seen "THE JOB PUSHED BEFORE THE KILL IS GONE, and nothing told the producer"; fi
sleep 10
seen "the job already done in scenario 3 has now run $(runs "$done_job") time(s): $(timeline "$done_job")"

clean_queue
echo; echo "########## 5a. a running job, Redis back before the worker gives up ##########"
id="running-short-$$"; mark=$(date -u +%Y-%m-%dT%H:%M:%SZ)
is "the job is accepted" "$(push "$id" 8)" pushed
if wait_for 30 "runs $id"; then ok "it started"; else ng "it started"; fi
docker compose stop redis > /dev/null 2>&1
sleep 12
redis_back
seen "$(date -u +%H:%M:%S) queue after the restart: $(depth) [$(queued_ids)]"
wait_worker "after"
seen "side effect: $(timeline "$id")"
seen "worker said: $(worker_results "$mark")"

for table in without with; do
  clean_queue
  echo; echo "########## 5b. a running job, Redis down past the worker's retries, $table a failed_jobs table ##########"
  if [ "$table" = with ]; then
    su_sql "CREATE TABLE failed_jobs (id bigserial PRIMARY KEY, uuid varchar(255) UNIQUE NOT NULL, connection text NOT NULL, queue text NOT NULL, payload text NOT NULL, exception text NOT NULL, failed_at timestamptz NOT NULL DEFAULT now())" > /dev/null
    su_sql "GRANT SELECT, INSERT, DELETE ON failed_jobs TO \"$DB_USERNAME\"; GRANT USAGE ON SEQUENCE failed_jobs_id_seq TO \"$DB_USERNAME\"" > /dev/null
  fi
  id="running-$table-$$"; before=$(restarts); mark=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  is "the job is accepted" "$(push "$id" 8)" pushed
  if wait_for 30 "runs $id"; then ok "it started"; else ng "it started"; fi
  seen "queue while running: $(depth) [$(queued_ids)]"
  docker compose stop redis > /dev/null 2>&1
  seen "$(date -u +%H:%M:%S) redis state: $(redis_state), side effect finished so far: $(finished "$id")"
  sleep 70
  seen "$(date -u +%H:%M:%S) while stopped: worker $(docker compose ps -a --format '{{.State}}' worker), side effect finished: $(finished "$id")"
  redis_back
  seen "$(date -u +%H:%M:%S) queue after the restart: $(depth) [$(queued_ids)]"
  wait_worker "after"
  seen "waiting past retry_after (90s from when it was reserved), so that a reserved job comes back"
  sleep 45
  r=$(runs "$id"); seen "side effect ran $r time(s): $(timeline "$id")"
  if [ "$r" = 1 ]; then ok "no second run of the side effect"; else ng "no second run of the side effect (ran $r)"; fi
  seen "queue at the end: $(depth) [$(queued_ids)]"
  seen "worker restarts during this scenario: $(($(restarts) - before))"
  seen "worker said: $(worker_results "$mark")"
  logs=$(worker_log_since "$mark")
  seen "the worker logged: $(grep -oE 'MaxAttemptsExceededException|QueryException|RedisException|has been attempted too many times|Undefined table|failed_jobs|redis\.outage_[a-z]+|db\.query_failed|DONE|FAIL' <<< "$logs" | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
  if [ "$table" = with ]; then
    seen "failed_jobs rows: $(su_sql 'SELECT count(*) FROM failed_jobs')"
    seen "their payload names the job: $(su_sql "SELECT count(*) FROM failed_jobs WHERE payload LIKE '%$id%'")"
    seen "recorded exception: $(su_sql 'SELECT left(exception, 70) FROM failed_jobs LIMIT 1')"
    su_sql 'DROP TABLE failed_jobs' > /dev/null
  else
    seen "failed_jobs: $(su_sql "SELECT to_regclass('public.failed_jobs')") — nowhere to record it"
  fi
done

clean_queue
echo; echo "########## 6. a running job, Redis killed ##########"
mark=$(date -u +%Y-%m-%dT%H:%M:%SZ)
id="running-killed-$$"; is "the job is accepted" "$(push "$id" 8)" pushed
if wait_for 30 "runs $id"; then ok "it started"; else ng "it started"; fi
docker compose kill redis > /dev/null 2>&1
sleep 12
redis_back
seen "queue after the restart: $(depth)"
wait_worker "after"
sleep 100
r=$(runs "$id"); seen "side effect ran $r time(s): $(timeline "$id")"
if [ "$r" = 1 ]; then ok "no second run of the side effect"; else ng "no second run of the side effect (ran $r)"; fi
seen "worker said: $(worker_results "$mark")"

echo; echo "########## after all of it ##########"
docker compose up -d --wait worker > /dev/null 2>&1
docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' | sed 's/^/  [SEEN] /'
is "no failed_jobs table is left behind" "$(su_sql "SELECT to_regclass('public.failed_jobs') IS NULL")" t
docker compose exec -T app php artisan audit:verify --all > /dev/null 2>&1
is "audit:verify --all exits 0" "$?" 0

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
