#!/usr/bin/env bash
# SecureFlow AI — infrastructure verification (Phase 0 tests P0-DB-03, P0-NET-01, P0-NET-02, DB part of P0-DB-01)
# Usage: scripts/verify-infra.sh   (run from the repository root with the stack running)
set -uo pipefail

cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

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
published=$(docker compose ps --format '{{.Publishers}}' | grep -oE '[0-9.:]+->' | grep -vE '^127\.0\.0\.1:' || true)
if [ -z "$published" ]; then ok "all published ports bind to 127.0.0.1 only"; else ng "ports published on non-loopback: $published"; fi

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

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
