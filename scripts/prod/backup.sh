#!/usr/bin/env bash
# SecureFlow AI — a dump of the production database, kept on the host and uploaded to S3 (docs/security-design.md §22 B).
#
#   backup.sh [--label <word>]      e.g. --label pre-deploy
#
# pg_dump in custom format by the postgres superuser inside the container (the same way as the development backups),
# a SHA-256 beside it, upload to s3://$BACKUP_BUCKET/dumps/, and the last 3 kept locally. The bucket keeps versions
# and encrypts at rest; the dump holds hashes of passwords and the audit chain, so it is a secret (threat-model R-21).
# restore.sh is the other half; the restore is tested in step 5-3 and after any change to either script.
. "$(dirname "$0")/lib.sh"
require_root

label=manual
while [ $# -gt 0 ]; do
  case "$1" in
    --label) label=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
bucket=$(env_value BACKUP_BUCKET)
[ -n "$bucket" ] || { echo "BACKUP_BUCKET is not set in $ENV_FILE" >&2; exit 2; }
database=$(env_value DB_DATABASE)

umask 077
mkdir -p "$SECUREFLOW_BACKUPS"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
file=$SECUREFLOW_BACKUPS/secureflow-$stamp-$label.dump

log "dumping $database to $file"
compose exec -T postgres pg_dump -U postgres -Fc --no-owner "$database" > "$file"
[ -s "$file" ] || { log "the dump is empty"; put_metric BackupFailed 1; exit 1; }
sha256sum "$file" | awk '{ print $1 }' > "$file.sha256"

log "uploading to s3://$bucket/dumps/"
if aws s3 cp --only-show-errors "$file" "s3://$bucket/dumps/$(basename "$file")" \
   && aws s3 cp --only-show-errors "$file.sha256" "s3://$bucket/dumps/$(basename "$file").sha256"; then
  put_metric BackupFailed 0
else
  log "the upload failed; the dump stays on the host"
  put_metric BackupFailed 1
  exit 1
fi

# The last three on the host, whatever their label.
ls -1t "$SECUREFLOW_BACKUPS"/secureflow-*.dump 2> /dev/null | tail -n +4 | while read -r old; do rm -f "$old" "$old.sha256"; done
log "done: $(basename "$file") ($(du -h "$file" | cut -f1))"
