#!/bin/sh
# SecureFlow AI — PostgreSQL bootstrap (runs once, on first container start, as superuser)
#
# Creates two non-superuser roles and the databases:
#   - owner role  (DB_MIGRATOR_USERNAME): owns databases/schema, used ONLY for migrations
#   - app role    (DB_USERNAME):          runtime DML only, no CREATE on schema
# Passwords are taken from the environment and never written to disk by this script.
# Table-level privileges are granted explicitly by each migration (no DEFAULT PRIVILEGES).
set -eu

: "${DB_DATABASE:?DB_DATABASE is required}"
: "${DB_TEST_DATABASE:?DB_TEST_DATABASE is required}"
: "${DB_USERNAME:?DB_USERNAME is required}"
: "${DB_PASSWORD:?DB_PASSWORD is required}"
: "${DB_MIGRATOR_USERNAME:?DB_MIGRATOR_USERNAME is required}"
: "${DB_MIGRATOR_PASSWORD:?DB_MIGRATOR_PASSWORD is required}"

psql_su() {
  psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" "$@"
}

psql_su --dbname postgres \
  -v owner="$DB_MIGRATOR_USERNAME" -v owner_pw="$DB_MIGRATOR_PASSWORD" \
  -v app="$DB_USERNAME" -v app_pw="$DB_PASSWORD" <<'SQL'
CREATE ROLE :"owner" LOGIN PASSWORD :'owner_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE :"app" LOGIN PASSWORD :'app_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
-- Nobody but the superuser connects to the maintenance database.
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
SQL

for db in "$DB_DATABASE" "$DB_TEST_DATABASE"; do
  psql_su --dbname postgres -v db="$db" -v owner="$DB_MIGRATOR_USERNAME" -v app="$DB_USERNAME" <<'SQL'
CREATE DATABASE :"db" OWNER :"owner" ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO :"app";
SQL

  psql_su --dbname "$db" -v owner="$DB_MIGRATOR_USERNAME" -v app="$DB_USERNAME" <<'SQL'
ALTER SCHEMA public OWNER TO :"owner";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO :"app";
SQL
done

echo "secureflow: roles and databases initialized"
