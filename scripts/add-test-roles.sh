#!/usr/bin/env bash
# SecureFlow AI — add the test database roles to an existing PostgreSQL volume.
#
# New volumes get them from docker/postgres/initdb/. Existing volumes never re-run init scripts,
# so this runs the same scripts in the running container. Data in the development database is
# not touched, and the postgres container is not recreated. Safe to run again.
#
# Usage: bash scripts/add-test-roles.sh   (from anywhere, with the postgres service running)
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo ".env not found; run scripts/init-env.sh first" >&2; exit 1; }

# Add the new settings to an older .env. Generated values are not printed.
umask 077
add_username() { grep -q "^$1=" .env || echo "$1=$2" >> .env; }
add_password() {
  grep -q "^$1=." .env && return 0
  sed -i "/^$1=/d" .env
  echo "$1=$(openssl rand -hex 24)" >> .env
}
add_username DB_TEST_MIGRATOR_USERNAME secureflow_test_owner
add_password DB_TEST_MIGRATOR_PASSWORD
add_username DB_TEST_USERNAME secureflow_test_app
add_password DB_TEST_PASSWORD

set -a; . ./.env; set +a

# Read from the host: the mount in a running container can be stale. Passwords are passed by
# name, so they do not appear on any command line.
for script in 02-test-owner.sh 03-test-app.sh; do
  docker compose exec -T \
    -e DB_TEST_MIGRATOR_USERNAME -e DB_TEST_MIGRATOR_PASSWORD -e DB_TEST_USERNAME -e DB_TEST_PASSWORD \
    postgres sh -s < "docker/postgres/initdb/$script"
done
