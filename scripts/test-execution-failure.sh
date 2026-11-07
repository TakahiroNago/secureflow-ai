#!/usr/bin/env bash
# SecureFlow AI — what happens to an execution when the worker really dies (ST-33, docs/test-strategy.md §26). The worker
# gets SIGKILL in the middle of a run: a row lock on the workflow holds the run between its claim and its completion,
# with no test code in the application. It stops and kills containers, so it refuses to run unless the caller names
# this exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-execution-failure.sh
#
# Needs a migrated and seeded stack, with the scheduler running. Takes about ten minutes, because one case waits for the
# real retry_after of the queue.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; then
  echo "Refusing to run: this stops containers. Name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION." >&2
  exit 2
fi
for s in worker postgres scheduler app; do
  id=$(docker compose ps -q "$s")
  [ -n "$id" ] && [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id")" = "$P" ] \
    || { echo "Refusing to run: $s is not running in $P." >&2; exit 2; }
done

restore() { docker compose up -d --wait worker scheduler > /dev/null 2>&1 < /dev/null; }
trap restore EXIT

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }

su_sql() { docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "$1" < /dev/null | tr -d ' \r'; }
bootstrap='chdir("/var/www/html"); require "vendor/autoload.php"; $a = require "bootstrap/app.php"; $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
  function who($e) { return App\Models\User::query()->where("email", $e)->firstOrFail(); }
  function inOrg($u, $f) { return app(App\Support\Organization\OrganizationContext::class)->run($u->organization_id, $f); }
  function flow($id) { return App\Models\Workflow::query()->findOrFail($id); }'
in_app() { docker compose exec -T app php -r "$bootstrap $1" -- "${@:2}" < /dev/null; }

OWNER=execution-owner-$$@example.com
ADMIN=execution-admin-$$@example.com
docker compose exec -T app php artisan db:seed --force > /dev/null 2>&1 < /dev/null
for pair in "$OWNER member" "$ADMIN admin"; do
  set -- $pair
  printf '%s\n%s\n' 'execution failure passphrase 12' 'execution failure passphrase 12' | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$1" --email="$1" --role="$2" > /dev/null 2>&1
done

status_of() { su_sql "SELECT status FROM workflow_executions WHERE id='$1'"; }
error_of() { su_sql "SELECT error_code FROM workflow_executions WHERE id='$1'"; }
state_of() { su_sql "SELECT status FROM workflows WHERE id='$1'"; }
wait_for() { # id status seconds
  local i
  for i in $(seq 1 "$3"); do
    [ "$(status_of "$1")" = "$2" ] && return 0
    sleep 1
  done
  return 1
}
# Submits and approves whatever the workflow holds now.
approve() {
  in_app '$u = who($argv[1]); $b = who($argv[2]); inOrg($u, function () use ($u, $b, $argv) {
    app(App\Domain\Workflow\WorkflowSubmission::class)->submit($u, flow($argv[3]));
    $r = App\Models\WorkflowRevision::query()->findOrFail(flow($argv[3])->current_revision_id);
    app(App\Domain\Workflow\WorkflowDecisions::class)->approve($b, flow($argv[3]), $r->revision_no, $r->plan_hash, true, null);
  });' "$OWNER" "$ADMIN" "$1"
}
# A plan that is ready to run. Needs the worker. Prints the workflow.
ready_plan() {
  local analysis workflow i
  analysis=$(in_app '$u = who($argv[1]); echo inOrg($u, fn () => app(App\Domain\Workflow\AnalysisService::class)->request($u, "週次の報告を作成する"))->id;' "$OWNER")
  for i in $(seq 1 40); do
    workflow=$(su_sql "SELECT workflow_id FROM ai_analysis_requests WHERE id='$analysis'")
    [ -n "$workflow" ] && break
    sleep 1
  done
  approve "$workflow" > /dev/null
  echo "$workflow"
}
request_execution() { # workflow key: prints the execution, or the problem
  in_app '$u = who($argv[1]); try { echo inOrg($u, fn () => app(App\Domain\Execution\ExecutionService::class)->request($u, flow($argv[2]), $argv[3]))->id; } catch (App\Domain\Workflow\WorkflowConflictException $e) { echo $e->problemCode; }' "$OWNER" "$1" "$2"
}
# Sets EXECUTION: the worker is killed with the run in the middle of its work.
kill_during_run() { # workflow
  local i seen=
  docker compose stop worker > /dev/null 2>&1 < /dev/null
  EXECUTION=$(request_execution "$1" "kill-$RANDOM-$$")
  # Longer than the time it takes to see the claim, and released before the end of the case.
  docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -qc \
    "BEGIN; SELECT 1 FROM workflows WHERE id='$1' FOR UPDATE; SELECT pg_sleep(12); COMMIT;" > /dev/null 2>&1 < /dev/null &
  HOLDER=$!
  sleep 1
  docker compose up -d --no-deps worker > /dev/null 2>&1 < /dev/null
  for i in $(seq 1 100); do
    [ "$(status_of "$EXECUTION")" = running ] && { seen=1; break; }
    sleep 0.05
  done
  docker compose kill -s SIGKILL worker > /dev/null 2>&1 < /dev/null
  [ -n "$seen" ] && ok "the run started" || ng "the run started"
  wait "$HOLDER"
  is "the worker is gone" "$(docker inspect -f '{{.State.Running}}' "$(docker compose ps -aq worker)")" false
  is "the run is left behind" "$(status_of "$EXECUTION")" running
  is "with no result" "$(su_sql "SELECT result IS NULL FROM workflow_executions WHERE id='$EXECUTION'")" t
  is "the workflow is left running" "$(state_of "$1")" running
}

echo "== the normal case =="
workflow=$(ready_plan)
execution=$(request_execution "$workflow" "normal-$$")
wait_for "$execution" completed 30; is "the worker runs it" "$?" 0
is "the workflow is completed" "$(state_of "$workflow")" completed

echo "== a job that waits for a stopped worker: it is in the table, and runs once =="
workflow=$(ready_plan)
docker compose stop worker > /dev/null 2>&1 < /dev/null
execution=$(request_execution "$workflow" "waiting-$$")
is "it waits" "$(status_of "$execution")" queued
is "the job is in the table" "$(su_sql "SELECT count(*) FROM jobs WHERE queue='execution' AND payload LIKE '%$execution%'")" 1
docker compose up -d --wait --no-deps worker > /dev/null 2>&1 < /dev/null
wait_for "$execution" completed 60; is "it runs when the worker is back" "$?" 0
is "one record of it" "$(su_sql "SELECT count(*) FROM audit_logs WHERE event_type='execution.completed' AND resource_id='$workflow'")" 1

echo "== killed during a run, with no worker to come back: the scheduler gives up on it =="
workflow=$(ready_plan)
kill_during_run "$workflow"
# The limit is five minutes. The heartbeat is what it reads, and this is the only thing changed by hand.
su_sql "UPDATE workflow_executions SET heartbeat_at=now()-interval '301 seconds' WHERE id='$EXECUTION'" > /dev/null
wait_for "$EXECUTION" failed 90; is "the run fails within a scheduler run" "$?" 0
is "as stale" "$(error_of "$EXECUTION")" EXECUTION_STALE
is "the workflow fails" "$(state_of "$workflow")" failed
is "recorded once" "$(su_sql "SELECT count(*) FROM audit_logs WHERE event_type='execution.failed' AND resource_id='$workflow'")" 1

echo "== the job of that run comes back: nothing changes =="
before=$(su_sql 'SELECT count(*) FROM failed_jobs')
su_sql "UPDATE jobs SET reserved_at=extract(epoch from now())::int-200 WHERE payload LIKE '%$EXECUTION%'" > /dev/null
docker compose up -d --wait --no-deps worker > /dev/null 2>&1 < /dev/null
for _ in $(seq 1 30); do
  [ "$(su_sql "SELECT count(*) FROM jobs WHERE payload LIKE '%$EXECUTION%'")" = 0 ] && break
  sleep 1
done
is "the job leaves the queue" "$(su_sql "SELECT count(*) FROM jobs WHERE payload LIKE '%$EXECUTION%'")" 0
is "and is recorded as a failed job" "$(su_sql 'SELECT count(*) FROM failed_jobs')" "$((before+1))"
is "the code stays" "$(error_of "$EXECUTION")" EXECUTION_STALE
is "still one record" "$(su_sql "SELECT count(*) FROM audit_logs WHERE event_type='execution.failed' AND resource_id='$workflow'")" 1

echo "== the approval is used up: it takes reopening, submitting and approving again =="
is "not with another key" "$(request_execution "$workflow" "again-$$")" EXECUTION_ALREADY_EXISTS
in_app '$u = who($argv[1]); inOrg($u, fn () => app(App\Domain\Workflow\WorkflowEditor::class)->reopen($u, flow($argv[2])));' "$OWNER" "$workflow"
is "back to a draft" "$(state_of "$workflow")" draft
is "not without a new approval" "$(request_execution "$workflow" "again-$$")" APPROVAL_NOT_VALID
approve "$workflow"
execution=$(request_execution "$workflow" "again-$$")
wait_for "$execution" completed 60; is "then it runs" "$?" 0

echo "== killed during a run, with the worker back: the job itself comes back after retry_after (waits for real) =="
workflow=$(ready_plan)
kill_during_run "$workflow"
docker compose up -d --wait --no-deps worker > /dev/null 2>&1 < /dev/null
wait_for "$EXECUTION" failed 240; is "the run fails" "$?" 0
is "with a code" "$(error_of "$EXECUTION")" EXECUTION_FAILED
is "the workflow fails" "$(state_of "$workflow")" failed
is "it did not run twice" "$(su_sql "SELECT result IS NULL FROM workflow_executions WHERE id='$EXECUTION'")" t

echo "== the audit chain =="
docker compose exec -T app php artisan audit:verify --all > /dev/null 2>&1 < /dev/null
is "the chains verify" "$?" 0

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
