#!/usr/bin/env bash
# SecureFlow AI — infrastructure verification (Phase 0 tests P0-DB-03, P0-NET-01, P0-NET-02, DB part of P0-DB-01)
# Usage: scripts/verify-infra.sh   (run from the repository root with the stack running)
set -uo pipefail

cd "$(dirname "$0")/.."

# Resolve these the way Compose does (shell > .env > default) so that every check below
# targets this project and its ports, never another copy running on the same machine.
shell_project=${COMPOSE_PROJECT_NAME-}; shell_nginx_port=${NGINX_PORT-}; shell_frontend_port=${FRONTEND_PORT-}
set -a; . ./.env; set +a
export COMPOSE_PROJECT_NAME="${shell_project:-${COMPOSE_PROJECT_NAME:-secureflow}}"
export NGINX_PORT="${shell_nginx_port:-${NGINX_PORT:-8080}}"
export FRONTEND_PORT="${shell_frontend_port:-${FRONTEND_PORT:-5173}}"
echo "Target: project=$COMPOSE_PROJECT_NAME nginx=127.0.0.1:$NGINX_PORT frontend=127.0.0.1:$FRONTEND_PORT"

pass=0; fail=0
ok()   { echo "  [PASS] $1"; pass=$((pass+1)); }
ng()   { echo "  [FAIL] $1"; fail=$((fail+1)); }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else ng "$1"; fi; }

psql_as() { # user password db sql
  docker compose exec -T -e PGPASSWORD="$2" postgres \
    psql -h 127.0.0.1 -U "$1" -d "$3" -v ON_ERROR_STOP=1 --no-psqlrc -tAc "$4"
}
psql_su() { docker compose exec -T postgres psql -U postgres -d "$1" --no-psqlrc -tAc "$2"; }

echo "== P0-NET-01: no host-published ports for postgres / redis =="
for s in postgres redis; do
  cid=$(docker compose ps -q "$s")
  if [ -n "$cid" ] && [ -z "$(docker port "$cid")" ]; then ok "$s has no published ports"; else ng "$s has published ports or is not running"; fi
done
# shellcheck disable=SC2046 # one argument per container id
if port_report=$(bash scripts/check-published-ports.sh \
    --allow "nginx 80/tcp $NGINX_PORT" --allow "frontend 5173/tcp $FRONTEND_PORT" \
    $(docker compose ps -aq) 2>&1); then
  ok "only the expected ports are published, and only on 127.0.0.1 ($port_report)"
else
  ng "published port policy"; echo "$port_report" | sed 's/^/         /'
fi

echo "== P0-NET-02: redis requires authentication =="
check "unauthenticated PING is rejected (NOAUTH)" \
  "docker compose exec -T redis redis-cli ping 2>&1 | grep -q NOAUTH"
check "authenticated PING succeeds" \
  "docker compose exec -T -e REDISCLI_AUTH=\"\$REDIS_PASSWORD\" redis redis-cli ping | grep -q PONG"

echo "== P0-DB-03: role attributes =="
for r in "$DB_MIGRATOR_USERNAME" "$DB_USERNAME"; do
  attrs=$(psql_su postgres "SELECT concat(rolsuper::int, rolcreatedb::int, rolcreaterole::int, rolreplication::int, rolbypassrls::int) FROM pg_roles WHERE rolname='$r'")
  if [ "$attrs" = "00000" ]; then ok "$r is NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"; else ng "$r attributes=$attrs"; fi
done

for db in "$DB_DATABASE" "$DB_TEST_DATABASE"; do
  echo "== database: $db =="
  owner=$(psql_su postgres "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='$db'")
  [ "$owner" = "$DB_MIGRATOR_USERNAME" ] && ok "$db owned by $DB_MIGRATOR_USERNAME" || ng "$db owner=$owner"
  schema_owner=$(psql_su "$db" "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public'")
  [ "$schema_owner" = "$DB_MIGRATOR_USERNAME" ] && ok "schema public owned by $DB_MIGRATOR_USERNAME" || ng "schema owner=$schema_owner"
  check "PUBLIC has no CREATE on schema public" \
    "[ \"\$(psql_su $db \"SELECT has_schema_privilege('public','public','CREATE')\")\" = f ]"
  check "app role can connect" "psql_as \"\$DB_USERNAME\" \"\$DB_PASSWORD\" $db 'SELECT 1'"
  check "P0-DB-01(db): app role cannot CREATE TABLE" \
    "! psql_as \"\$DB_USERNAME\" \"\$DB_PASSWORD\" $db 'CREATE TABLE p0_probe(x int)'"
  check "owner role can CREATE/DROP TABLE" \
    "psql_as \"\$DB_MIGRATOR_USERNAME\" \"\$DB_MIGRATOR_PASSWORD\" $db 'CREATE TABLE p0_probe(x int); DROP TABLE p0_probe'"
done
check "app role cannot connect to maintenance db 'postgres'" \
  "! psql_as \"\$DB_USERNAME\" \"\$DB_PASSWORD\" postgres 'SELECT 1'"

if [ -n "$(docker compose ps -q app 2>/dev/null)" ]; then
  echo "== P0-DB-02: owner credentials are absent from runtime containers =="
  for s in app worker scheduler; do
    check "$s has no DB_MIGRATOR_* / POSTGRES_PASSWORD in its environment" \
      "! docker compose exec -T $s env | grep -qE '^(DB_MIGRATOR_|POSTGRES_PASSWORD=)'"
  done
  check "php artisan migrate in the app container fails because of the DB privilege" \
    "! migrate_output=\$(docker compose exec -T app php artisan migrate --force 2>&1) && grep -qi 'permission denied' <<< \"\$migrate_output\""

  echo "== P0-HC-03 / P0-HC-04: container health =="
  for s in app worker scheduler; do
    check "$s reports healthy" \
      "[ \"\$(docker inspect --format '{{.State.Health.Status}}' \"\$(docker compose ps -q $s)\")\" = healthy ]"
  done

  echo "== P0-HC-01 / P0-HC-02: health endpoints through nginx =="
  base=http://127.0.0.1:$NGINX_PORT
  check "this project's nginx is published on 127.0.0.1:$NGINX_PORT" \
    "[ \"\$(docker compose port nginx 80)\" = 127.0.0.1:$NGINX_PORT ]"
  check "live returns exactly {\"status\":\"ok\"}" \
    "[ \"\$(curl -s $base/api/health/live)\" = '{\"status\":\"ok\"}' ]"
  check "ready returns exactly {\"status\":\"ok\"}" \
    "[ \"\$(curl -s $base/api/health/ready)\" = '{\"status\":\"ok\"}' ]"
  check "no X-Powered-By / version in Server header" \
    "! curl -s -I $base/api/health/live | grep -qiE '^x-powered-by|^server: nginx/'"
  check "no CORS header for foreign Origin" \
    "! curl -s -I -H 'Origin: https://attacker.example' $base/api/health/live | grep -qi '^access-control-allow-origin'"
  # With the SPA fallback these paths return index.html (or 404 before 0-4), never the real endpoint.
  check "nginx container healthcheck endpoint is not reachable from the host" \
    "b=\$(curl -s $base/nginx-health); [ \"\$b\" != 'ok' ] && ! echo \"\$b\" | grep -qx ok"
  check "framework /up route is not exposed (not handled by Laravel)" \
    "! curl -s $base/up | grep -qiE 'application up|laravel'"
  check "dotfiles are not served" \
    "[ \"\$(curl -s -o /dev/null -w '%{http_code}' $base/.env)\" = 404 ]"
  check "health endpoints are rate limited by nginx (429 after burst)" \
    "for i in \$(seq 1 30); do curl -s -o /dev/null -w '%{http_code}\n' $base/api/health/live; done | grep -q 429"
fi

if [ -n "$(docker compose ps -q frontend 2>/dev/null)" ]; then
  echo "== P0-FE-01: frontend delivery =="
  check "this project's Vite dev server is published on 127.0.0.1:$FRONTEND_PORT" \
    "[ \"\$(docker compose port frontend 5173)\" = 127.0.0.1:$FRONTEND_PORT ]"
  check "nginx serves the built SPA at /" \
    "curl -s http://127.0.0.1:$NGINX_PORT/ | grep -q '<title>SecureFlow AI</title>'"
  check "SPA fallback: unknown client route returns index.html" \
    "curl -s http://127.0.0.1:$NGINX_PORT/some/client/route | grep -q '<div id=\"root\">'"
  check "SPA responses carry the CSP header" \
    "curl -s -I http://127.0.0.1:$NGINX_PORT/ | grep -qi \"^content-security-policy: default-src 'self'\""
  check "Vite dev server proxies /api to nginx (same-origin)" \
    "[ \"\$(curl -s http://127.0.0.1:$FRONTEND_PORT/api/health/live)\" = '{\"status\":\"ok\"}' ]"
fi

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
