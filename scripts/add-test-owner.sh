#!/usr/bin/env bash
# SecureFlow AI — add the test database owner role to an existing PostgreSQL volume.
#
# New volumes get it from docker/postgres/initdb/02-test-owner.sh. Existing volumes never re-run
# init scripts, so this runs the same script in the running container. The development database
# and its data are not touched, and the postgres container is not recreated. Safe to run again.
#
# Usage: bash scripts/add-test-owner.sh   (from anywhere, with the postgres service running)
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo ".env not found; run scripts/init-env.sh first" >&2; exit 1; }

# Add the new settings to an older .env. The generated value is not printed.
umask 077
grep -q '^DB_TEST_MIGRATOR_USERNAME=' .env || echo 'DB_TEST_MIGRATOR_USERNAME=secureflow_test_owner' >> .env
if ! grep -q '^DB_TEST_MIGRATOR_PASSWORD=.' .env; then
  sed -i '/^DB_TEST_MIGRATOR_PASSWORD=/d' .env
  echo "DB_TEST_MIGRATOR_PASSWORD=$(openssl rand -hex 24)" >> .env
fi

set -a; . ./.env; set +a

# Read from the host: the mount in a running container can be stale. The password is passed by
# name, so it does not appear on any command line.
docker compose exec -T \
  -e DB_TEST_MIGRATOR_USERNAME -e DB_TEST_MIGRATOR_PASSWORD \
  postgres sh -s < docker/postgres/initdb/02-test-owner.sh
