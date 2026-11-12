#!/usr/bin/env bash
# SecureFlow AI — restore a dump of backup.sh into a database (docs/security-design.md §22 B, docs/operations.md).
#
#   restore.sh <dump file> [--into <database>] [--from-s3 <key>]
#
# Into a scratch database by default (secureflow_restore_test), which is how the restore is tested without touching
# the live one: the roles, the audit triggers and the chain come back as they were, and `audit:verify` is run against
# it. Restoring over the live database is a deliberate, separate step: stop the services, --into the live name after
# dropping it, start them. It never happens by itself.
. "$(dirname "$0")/lib.sh"
require_root

dump=${1:?usage: restore.sh <dump file> [--into <database>] [--from-s3 <key>]}; shift
into=secureflow_restore_test
key=""
while [ $# -gt 0 ]; do
  case "$1" in
    --into) into=$2; shift 2 ;;
    --from-s3) key=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
live=$(env_value DB_DATABASE)
owner=$(env_value DB_MIGRATOR_USERNAME)
app_role=$(env_value DB_USERNAME)

if [ -n "$key" ]; then
  bucket=$(env_value BACKUP_BUCKET)
  umask 077; mkdir -p "$SECUREFLOW_BACKUPS"
  aws s3 cp --only-show-errors "s3://$bucket/$key" "$dump"
  aws s3 cp --only-show-errors "s3://$bucket/$key.sha256" "$dump.sha256"
fi
[ -f "$dump" ] || { echo "no such dump: $dump" >&2; exit 2; }
if [ -f "$dump.sha256" ]; then
  [ "$(sha256sum "$dump" | awk '{ print $1 }')" = "$(cat "$dump.sha256")" ] || { log "the checksum does not match"; exit 1; }
  log "checksum ok"
fi

psql_su() { compose exec -T postgres psql -U postgres -d "$1" --no-psqlrc -v ON_ERROR_STOP=1 -qAtc "$2"; }

if [ "$into" = "$live" ]; then
  log "restoring over the live database $live: the services must be stopped and the database dropped first"
  [ -z "$(compose ps -q app worker scheduler)" ] || { log "app, worker or scheduler is still running"; exit 1; }
  [ "$(psql_su postgres "SELECT count(*) FROM pg_database WHERE datname = '$live'")" = 0 ] || { log "$live still exists; drop it on purpose first"; exit 1; }
else
  psql_su postgres "DROP DATABASE IF EXISTS \"$into\""
fi

# As the development restores: a prepared database owned by the owner role, restored as that role (not --create as
# the superuser), so that ownership and the grants to the application role come back as the migrations made them.
psql_su postgres "CREATE DATABASE \"$into\" OWNER \"$owner\""
psql_su "$into" "REVOKE ALL ON DATABASE \"$into\" FROM PUBLIC"
psql_su "$into" "GRANT CONNECT ON DATABASE \"$into\" TO \"$app_role\""
log "restoring $(basename "$dump") into $into as $owner"
compose exec -T postgres pg_restore -U postgres --role="$owner" --no-owner --exit-on-error -d "$into" < "$dump"

log "the chain of the restored database:"
compose run --rm --no-deps -T -e DB_DATABASE="$into" app php artisan audit:verify --all
log "done. Drop a scratch database with: compose exec postgres psql -U postgres -c 'DROP DATABASE \"$into\"'"
