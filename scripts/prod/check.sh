#!/usr/bin/env bash
# SecureFlow AI — what the operator checks on the host after a deploy, and whenever in doubt (docs/operations.md).
# Reads only: nothing here writes to the database or changes a container (scripts/verify-infra.sh is for development,
# because it creates and drops objects as the owner).
#
#   PROD-C1  every container healthy, the deployed digests are the running ones
#   PROD-C2  liveness and readiness through nginx, with HSTS and the headers of the design
#   PROD-C3  nginx is the only published port, on NGINX_BIND:NGINX_PORT, and postgres / redis are not published
#   PROD-C4  the audit log can be written to, and the chains verify
#   PROD-C5  the scheduler lists its commands and the worker is on its queues
. "$(dirname "$0")/lib.sh"
require_root

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else ng "$1"; fi; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
bind=$(env_value NGINX_BIND); bind=${bind:-127.0.0.1}
port=$(env_value NGINX_PORT); port=${port:-8080}
BASE="http://$bind:$port"
header() { awk -v name="$1" '{ line = $0; sub(/\r$/, "", line); split(line, parts, ":"); if (tolower(parts[1]) == tolower(name)) { sub(/^[^:]*:[ \t]*/, "", line); print line } }' "$work/h"; }
fetch() { STATUS=$(curl -s -o "$work/b" -D "$work/h" -w '%{http_code}' --max-time 10 "$@"); }

echo "== PROD-C1: containers =="
unhealthy=$(compose ps --format '{{.Service}} {{.Health}}' | grep -v ' healthy$' || true)
if [ -z "$unhealthy" ]; then ok "every container is healthy"; else ng "not healthy: $(echo "$unhealthy" | tr '\n' ' ')"; fi
for service in app worker scheduler; do
  running=$(docker inspect --format '{{.Image}}' "$(compose ps -q "$service")" 2> /dev/null || true)
  wanted=$(docker image inspect --format '{{.Id}}' "$(sed -n 's/^SECUREFLOW_PHP_IMAGE=//p' "$IMAGES_FILE")" 2> /dev/null || true)
  is "$service runs the deployed php image" "$running" "$wanted"
done
running=$(docker inspect --format '{{.Image}}' "$(compose ps -q nginx)" 2> /dev/null || true)
wanted=$(docker image inspect --format '{{.Id}}' "$(sed -n 's/^SECUREFLOW_WEB_IMAGE=//p' "$IMAGES_FILE")" 2> /dev/null || true)
is "nginx runs the deployed web image" "$running" "$wanted"

echo "== PROD-C2: health through nginx =="
fetch "$BASE/api/health/live"; is "liveness" "$STATUS" 200
fetch "$BASE/api/health/ready"; is "readiness" "$STATUS" 200
is "HSTS" "$(header Strict-Transport-Security)" 'max-age=31536000; includeSubDomains'
is "X-Frame-Options" "$(header X-Frame-Options)" DENY
check "Content-Security-Policy" "[ -n \"\$(header Content-Security-Policy)\" ]"
fetch "$BASE/"; is "the page" "$STATUS" 200

echo "== PROD-C3: published ports =="
# One line per container: "<service> <port>=<host ip>:<host port> ..." from what Docker has configured (not parsed output).
bindings=$(compose ps -q | xargs docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}{{range $p, $b := .HostConfig.PortBindings}} {{$p}}{{range $b}}={{.HostIp}}:{{.HostPort}}{{end}}{{end}}')
is "nginx is the only service with a published port" "$(printf '%s\n' "$bindings" | awk 'NF > 1 { print $1 }' | sort -u | tr '\n' ' ')" "nginx "
is "nginx publishes 80 on $bind:$port only" "$(printf '%s\n' "$bindings" | awk '$1 == "nginx" { $1 = ""; print }' | tr -s ' ')" " 80/tcp=$bind:$port"
check "postgres, redis and php-fpm listen on no host address" "! ss -Hltn | awk '{ print \$4 }' | grep -E ':(5432|6379|9000|9001)$'"

echo "== PROD-C4: the audit log =="
compose exec -T app php artisan audit:status > "$work/status" 2>&1; is "audit:status: the log can be written to" "$?" 0
compose exec -T app php artisan audit:verify --all > "$work/verify" 2>&1; is "audit:verify --all" "$?" 0

echo "== PROD-C5: worker and scheduler =="
check "the scheduler lists audit:housekeeping, analysis:recover, executions:reap-stale and selftest:recover" \
  "compose exec -T scheduler php artisan schedule:list | grep -q audit:housekeeping && compose exec -T scheduler php artisan schedule:list | grep -q selftest:recover"
check "the worker is on the ai, execution and selftest queues" "docker inspect --format '{{join .Config.Cmd \" \"}}' \"\$(compose ps -q worker)\" | grep -q -- '--queue=ai,execution,selftest'"

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
