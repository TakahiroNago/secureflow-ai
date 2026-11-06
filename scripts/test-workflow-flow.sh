#!/usr/bin/env bash
# SecureFlow AI — an analysis and an edit over real HTTP, through nginx, with the real worker and scheduler
# (docs/test-strategy.md §19). Complements Pest, which does not run a separate worker process.
#
# It creates users and workflows, so it runs only on a throwaway stack: a project other than the default one, or
# CI. It needs a migrated database.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
: "${NGINX_PORT:=8080}"
if [ "${COMPOSE_PROJECT_NAME:-secureflow}" = secureflow ] && [ "${CI:-}" != true ]; then
  echo "Refusing to run: this creates users. Use a separate project (README: 複数環境の同時起動) or CI." >&2
  exit 2
fi

BASE=http://localhost:$NGINX_PORT
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }
hasnt() { if grep -qE -- "$3" <<< "$2"; then ng "$1 (found '$3')"; else ok "$1"; fi; }

# Sets STATUS and BODY.
call() { # jar method path [json] [extra curl arguments...]
  local jar=$1 method=$2 path=$3 json=${4:-}; shift 4 2>/dev/null || shift $#
  local token args=()
  token=$(awk '$6 == "XSRF-TOKEN" { print $7 }' "$jar" 2>/dev/null | tail -1)
  [ -z "$token" ] || args+=(-H "X-XSRF-TOKEN: $(printf '%b' "${token//%/\\x}")")
  [ -z "$json" ] || args+=(-H 'Content-Type: application/json' --data-binary "$json")
  STATUS=$(curl -s -o "$work/body" -w '%{http_code}' --max-time 30 -X "$method" -b "$jar" -c "$jar" \
    -H 'Accept: application/json' -H "Origin: $BASE" -H "Referer: $BASE/" ${args[@]+"${args[@]}"} "$@" "$BASE$path")
  BODY=$(cat "$work/body")
}
field() { python3 -c 'import json,sys; v=json.loads(sys.argv[1]); [v:=v[int(k) if k.isdigit() else k] for k in sys.argv[2].split(".")]; print(v)' "$BODY" "$1"; }
su_sql() { docker compose exec -T postgres psql -U postgres -d "$DB_DATABASE" --no-psqlrc -tAc "$1" < /dev/null | tr -d ' \r'; }

create_user() { # email password role
  printf '%s\n%s\n' "$2" "$2" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$1" --email="$1" --role="$3" > /dev/null 2>&1
}
login() { # jar email password
  : > "$1"
  call "$1" GET /sanctum/csrf-cookie
  call "$1" POST /api/v1/auth/login "$(printf '{"email":"%s","password":"%s"}' "$2" "$3")"
}

PASSWORD='workflow flow passphrase 07'
MARKER="input-marker-$(cat /proc/sys/kernel/random/uuid)"
TASK='{"title":"編集後","description":"説明","action_type":"report.draft","steps":["手順"],"priority":"high","target_data":"対象","impact_summary":"影響"}'
USER_A=flow-a-$$@example.com
USER_B=flow-b-$$@example.com

docker compose exec -T app php artisan db:seed --force > /dev/null 2>&1
create_user "$USER_A" "$PASSWORD" member
create_user "$USER_B" "$PASSWORD" admin
A=$work/a.jar; B=$work/b.jar
login "$A" "$USER_A" "$PASSWORD"; is "the member logs in" "$STATUS" 200
login "$B" "$USER_B" "$PASSWORD"; is "the admin logs in" "$STATUS" 200

echo "== an analysis through the real worker =="
call "$A" POST /api/v1/analyses "{\"input\":\"$MARKER\"}"
is "accepted" "$STATUS" 202
is "says it is not scanned" "$(field data.scan.status)" not_scanned
analysis=$(field data.id)

status=queued
for _ in $(seq 1 40); do
  call "$A" GET "/api/v1/analyses/$analysis"
  status=$(field data.status)
  case "$status" in succeeded|failed) break ;; esac
  sleep 0.5
done
is "the worker finishes it" "$status" succeeded
workflow=$(field data.workflow_id)
is "the queue is empty" "$(su_sql 'SELECT count(*) FROM jobs')" 0
is "nothing failed" "$(su_sql 'SELECT count(*) FROM failed_jobs')" 0

echo "== the input is stored nowhere =="
dump=$(docker compose exec -T postgres pg_dump -U postgres --data-only "$DB_DATABASE" < /dev/null)
hasnt "not in the database" "$dump" "$MARKER"
hasnt "not in the logs" "$(docker compose logs --no-color app worker scheduler nginx 2>/dev/null)" "$MARKER"
is "the row has no input" "$(su_sql "SELECT input_masked IS NULL FROM ai_analysis_requests WHERE id='$analysis'")" t
is "the workflow has no input" "$(su_sql "SELECT source_input_masked IS NULL FROM workflows WHERE id='$workflow'")" t

echo "== reading and editing =="
call "$A" GET "/api/v1/workflows/$workflow"
is "the owner reads it" "$STATUS" 200
is "first revision" "$(field data.current_revision.no)" 1
task=$(field data.tasks.0.id)
hash=$(field data.current_revision.plan_hash)

call "$A" PUT "/api/v1/workflows/$workflow/tasks/$task" "$TASK"
is "an edit needs If-Match" "$STATUS" 428
call "$B" PUT "/api/v1/workflows/$workflow/tasks/$task" "$TASK" -H 'If-Match: "1"'
is "another user cannot edit" "$STATUS" 403
call "$A" PUT "/api/v1/workflows/$workflow/tasks/$task" "$TASK" -H 'If-Match: "1"'
is "the owner edits" "$STATUS" 200
is "a new revision" "$(field data.current_revision.no)" 2
is "permissions from the server" "$(field data.tasks.0.derived_permissions.1)" report.draft.write
[ "$(field data.current_revision.plan_hash)" != "$hash" ] && ok "a new hash" || ng "a new hash"
call "$A" PUT "/api/v1/workflows/$workflow/tasks/$task" "$TASK" -H 'If-Match: "1"'
is "an old revision is refused" "$STATUS" 409
is "with the right code" "$(field code)" REVISION_CONFLICT

echo "== the audit chain =="
is "the creation is recorded" "$(su_sql "SELECT count(*) FROM audit_logs WHERE event_type='workflow.created' AND resource_id='$workflow'")" 1
is "the edit is recorded" "$(su_sql "SELECT count(*) FROM audit_logs WHERE event_type='workflow.updated' AND resource_id='$workflow'")" 1
docker compose exec -T app php artisan audit:verify --all > "$work/verify" 2>&1
is "the chains verify" "$?" 0

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
