#!/bin/sh
# SecureFlow AI — dedicated owner role for the test database.
#
# Runs as superuser on first container start, and is safe to run again on an existing volume
# (scripts/add-test-owner.sh). It only touches this role and the test database.
#
# Result:
#   - test owner role (DB_TEST_MIGRATOR_USERNAME): owns the test database and its public schema,
#     cannot connect to the development database
#   - development owner role (DB_MIGRATOR_USERNAME): cannot connect to the test database
#
# Do not use REASSIGN OWNED here: it also moves shared objects, including the development
# database itself.
set -eu

: "${DB_DATABASE:?DB_DATABASE is required}"
: "${DB_TEST_DATABASE:?DB_TEST_DATABASE is required}"
: "${DB_USERNAME:?DB_USERNAME is required}"
: "${DB_MIGRATOR_USERNAME:?DB_MIGRATOR_USERNAME is required}"
: "${DB_TEST_MIGRATOR_USERNAME:?DB_TEST_MIGRATOR_USERNAME is required}"
: "${DB_TEST_MIGRATOR_PASSWORD:?DB_TEST_MIGRATOR_PASSWORD is required}"

psql_su() {
  psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" "$@"
}

psql_su --dbname postgres \
  -v role="$DB_TEST_MIGRATOR_USERNAME" -v pw="$DB_TEST_MIGRATOR_PASSWORD" \
  -v dev_db="$DB_DATABASE" -v test_db="$DB_TEST_DATABASE" -v dev_owner="$DB_MIGRATOR_USERNAME" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'role')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
ALTER ROLE :"role" LOGIN PASSWORD :'pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER DATABASE :"test_db" OWNER TO :"role";
REVOKE ALL ON DATABASE :"test_db" FROM PUBLIC;
REVOKE ALL ON DATABASE :"test_db" FROM :"dev_owner";
REVOKE ALL ON DATABASE :"dev_db" FROM :"role";
SQL

psql_su --dbname "$DB_TEST_DATABASE" -v role="$DB_TEST_MIGRATOR_USERNAME" -v app="$DB_USERNAME" <<'SQL'
ALTER SCHEMA public OWNER TO :"role";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO :"app";
-- Objects left in the test database by the previous owner (existing volumes only).
SELECT format('ALTER TABLE public.%I OWNER TO %I', c.relname, :'role')
  FROM pg_class c
  WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm')
    AND pg_get_userbyid(c.relowner) <> :'role' \gexec
SELECT format('ALTER ROUTINE %s OWNER TO %I', p.oid::regprocedure, :'role')
  FROM pg_proc p
  WHERE p.pronamespace = 'public'::regnamespace
    AND pg_get_userbyid(p.proowner) <> :'role'
    AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e') \gexec
SQL

echo "secureflow: test owner role ready"
