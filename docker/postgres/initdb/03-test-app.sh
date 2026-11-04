#!/bin/sh
# SecureFlow AI — dedicated application role for the test database.
#
# Runs as superuser on first container start, and is safe to run again on an existing volume
# (scripts/add-test-roles.sh). It changes nothing inside the development database.
#
# Result:
#   - test application role (DB_TEST_USERNAME): can connect to the test database only.
#     Table privileges come from the migrations, as for the normal application role.
#   - application role (DB_USERNAME): keeps the development database, loses the test database.
set -eu

: "${DB_DATABASE:?DB_DATABASE is required}"
: "${DB_TEST_DATABASE:?DB_TEST_DATABASE is required}"
: "${DB_USERNAME:?DB_USERNAME is required}"
: "${DB_TEST_USERNAME:?DB_TEST_USERNAME is required}"
: "${DB_TEST_PASSWORD:?DB_TEST_PASSWORD is required}"

psql_su() {
  psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" "$@"
}

psql_su --dbname postgres \
  -v role="$DB_TEST_USERNAME" -v pw="$DB_TEST_PASSWORD" -v app="$DB_USERNAME" \
  -v dev_db="$DB_DATABASE" -v test_db="$DB_TEST_DATABASE" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'role')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
ALTER ROLE :"role" LOGIN PASSWORD :'pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE :"test_db" TO :"role";
REVOKE ALL ON DATABASE :"dev_db" FROM :"role";
REVOKE ALL ON DATABASE :"test_db" FROM :"app";
SQL

psql_su --dbname "$DB_TEST_DATABASE" -v role="$DB_TEST_USERNAME" -v app="$DB_USERNAME" <<'SQL'
GRANT USAGE ON SCHEMA public TO :"role";
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"app";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM :"app";
REVOKE ALL ON ALL ROUTINES IN SCHEMA public FROM :"app";
REVOKE ALL ON SCHEMA public FROM :"app";
SQL

echo "secureflow: test application role ready"
