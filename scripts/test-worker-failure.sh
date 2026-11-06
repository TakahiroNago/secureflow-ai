#!/usr/bin/env bash
# SecureFlow AI — what happens to an analysis when the worker, Redis or PostgreSQL fails (AUDIT-WORKER-01,
# docs/test-strategy.md §19). It stops and kills containers, so it refuses to run unless the caller names this
# exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-worker-failure.sh
#
# Needs a migrated and seeded stack, with the scheduler running. Takes a few minutes.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; then
  echo "Refusing to run: this stops containers. Name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION." >&2
  exit 2
fi
for s in redis worker postgres scheduler; do
  id=$(docker compose ps -q "$s")
  [ -n "$id" ] && [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id")" = "$P" ] \
    || { echo "Refusing to run: $s is not running in $P." >&2; exit 2; }
done

restore() { docker compose up -d --wait redis postgres worker scheduler > /dev/null 2>&1; }
trap restore EXIT

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }

su_sql() { docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "$1" < /dev/null | tr -d ' \r'; }
bootstrap='chdir("/var/www/html"); require "vendor/autoload.php"; $a = require "bootstrap/app.php"; $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();'
# Asks for an analysis as the real service does, and prints its id.
request() {
  docker compose exec -T app php -r "$bootstrap"'
    $u = App\Models\User::query()->where("email", $argv[1])->firstOrFail();
    echo app(App\Support\Organization\OrganizationContext::class)->run($u->organization_id, fn () => app(App\Domain\Workflow\AnalysisService::class)->request($u, 1))->id;' "$USER_EMAIL" < /dev/null | tail -1
}
status_of() { su_sql "SELECT status FROM ai_analysis_requests WHERE id='$1'"; }
error_of() { su_sql "SELECT error_code FROM ai_analysis_requests WHERE id='$1'"; }
wait_for() { # id status seconds
  local i
  for i in $(seq 1 "$3"); do
    [ "$(status_of "$1")" = "$2" ] && return 0
    sleep 1
  done
  return 1
}

USER_EMAIL=worker-failure-$$@example.com
docker compose exec -T app php artisan db:seed --force > /dev/null 2>&1
printf '%s\n%s\n' 'worker failure passphrase 11' 'worker failure passphrase 11' | docker compose exec -T app php artisan user:create \
  --organization='Default Organization' --name=worker --email="$USER_EMAIL" --role=member > /dev/null 2>&1

echo "== the normal case =="
id=$(request)
wait_for "$id" succeeded 30; is "the worker runs a job" "$?" 0

echo "== Redis killed while a job waits: the job is in the database =="
docker compose stop worker > /dev/null 2>&1
id=$(request)
is "the job is in the table" "$(su_sql "SELECT count(*) FROM jobs WHERE payload LIKE '%$id%'")" 1
docker compose kill redis > /dev/null 2>&1
docker compose up -d --wait redis > /dev/null 2>&1
docker compose up -d --wait worker > /dev/null 2>&1
wait_for "$id" succeeded 60; is "it survives and runs once" "$?" 0
is "one workflow" "$(su_sql "SELECT count(*) FROM ai_analysis_requests WHERE id='$id' AND workflow_id IS NOT NULL")" 1

echo "== Redis down while a job runs: the worker does not need it to finish the queue =="
docker compose stop redis > /dev/null 2>&1
id=$(request 2>/dev/null)
case "$id" in
  *-*-*-*-*) echo "  [SEEN] the service could still queue with Redis down"; wait_for "$id" succeeded 30 && echo "  [SEEN] and it finished" ;;
  *) echo "  [SEEN] the service refused while Redis is down (fail closed)" ;;
esac
docker compose up -d --wait redis > /dev/null 2>&1

echo "== a worker that died holding a job: the job comes back and fails the row =="
docker compose stop worker > /dev/null 2>&1
id=$(request)
before=$(su_sql 'SELECT count(*) FROM failed_jobs')
su_sql "UPDATE ai_analysis_requests SET status='processing', started_at=now(), heartbeat_at=now() WHERE id='$id'" > /dev/null
su_sql "UPDATE jobs SET attempts=1, reserved_at=extract(epoch from now())::int-200 WHERE payload LIKE '%$id%'" > /dev/null
docker compose up -d --wait worker > /dev/null 2>&1
wait_for "$id" failed 60; is "the row fails" "$?" 0
is "with a code" "$(error_of "$id")" ANALYSIS_FAILED
is "failed_jobs has a row" "$(su_sql 'SELECT count(*) FROM failed_jobs')" "$((before+1))"
is "the job is gone" "$(su_sql "SELECT count(*) FROM jobs WHERE payload LIKE '%$id%'")" 0

echo "== a row left behind with no job: the scheduler gives up on it =="
docker compose stop worker > /dev/null 2>&1
id=$(request)
su_sql "DELETE FROM jobs WHERE payload LIKE '%$id%'" > /dev/null
su_sql "UPDATE ai_analysis_requests SET status='processing', heartbeat_at=now()-interval '181 seconds' WHERE id='$id'" > /dev/null
wait_for "$id" failed 90; is "the row fails within a scheduler run" "$?" 0
is "as stale" "$(error_of "$id")" ANALYSIS_STALE
docker compose up -d --wait worker > /dev/null 2>&1

echo "== PostgreSQL restarted: the worker comes back by itself =="
docker compose restart postgres > /dev/null 2>&1
docker compose up -d --wait postgres > /dev/null 2>&1
# The service answers 503 until the database-unavailable flag expires: that is the design, not a failure here.
id=
for _ in $(seq 1 45); do
  id=$(request 2>/dev/null)
  case "$id" in *-*-*-*-*) break ;; *) id=; sleep 1 ;; esac
done
[ -n "$id" ] && ok "the service accepts again" || ng "the service accepts again"
[ -n "$id" ] && { wait_for "$id" succeeded 120; is "a new job runs" "$?" 0; }

echo "== the time limit =="
push_probe() { # id seconds queue
  docker compose exec -T app php -r "$bootstrap"'
    Illuminate\Support\Facades\Queue::connection("database")->pushOn($argv[3], new Tests\Support\QueueProbeJob($argv[1], (int) $argv[2]));' "$1" "$2" "$3" < /dev/null > /dev/null
}
# A job longer than the old limit of 60 seconds would need too long a test: 5 seconds shows it finishes and runs once.
push_probe "under-$$" 5 ai
sleep 12
is "a job under the limit finishes, once" "$(docker compose exec -T worker sh -c "grep -c finish /tmp/queue-probe/under-$$.log" < /dev/null | tr -d '\r')" 1
is "and started once" "$(docker compose exec -T worker sh -c "grep -c start /tmp/queue-probe/under-$$.log" < /dev/null | tr -d '\r')" 1

before=$(su_sql 'SELECT count(*) FROM failed_jobs')
push_probe "over-$$" 30 probe
started=$SECONDS
# As the real worker runs: --once does not set a time limit, only the long-running loop does.
docker compose exec -T app php artisan queue:work database --queue=probe --stop-when-empty --tries=1 --timeout=3 > /dev/null 2>&1 < /dev/null
elapsed=$((SECONDS-started))
[ "$elapsed" -lt 15 ] && ok "a job over the limit is stopped (after ${elapsed}s)" || ng "a job over the limit is stopped (after ${elapsed}s)"
is "and is recorded as failed" "$(su_sql 'SELECT count(*) FROM failed_jobs')" "$((before+1))"
is "and leaves the queue" "$(su_sql "SELECT count(*) FROM jobs WHERE queue='probe'")" 0

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
