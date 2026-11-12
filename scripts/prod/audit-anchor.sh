#!/usr/bin/env bash
# SecureFlow AI — the daily anchor of the audit chains (docs/security-design.md §22 A-4, §16.3; threat-model R-03).
#
# 1. `audit:verify --all --anchor=<the newest anchor in S3>`: the chains recompute, and none has been cut back behind
#    what was stored outside the database the last time. A failure (exit 1) or an impossible run (exit 2) becomes
#    the metric AuditVerifyFailed=1 (alarm in docs/operations.md). The first run has no anchor and verifies without.
# 2. `audit:head --all` to s3://$BACKUP_BUCKET/audit-heads/<timestamp>.jsonl. The bucket keeps versions and nobody
#    on the host can delete them (the instance role may only put and get), so a database owner cannot rewrite what
#    was stored. The metric AuditAnchorFailed says whether the head was stored.
# Run by a systemd timer (scripts/prod/systemd). Nothing in it changes the database.
. "$(dirname "$0")/lib.sh"
require_root

bucket=$(env_value BACKUP_BUCKET)
[ -n "$bucket" ] || { echo "BACKUP_BUCKET is not set in $ENV_FILE" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

newest=$(aws s3api list-objects-v2 --bucket "$bucket" --prefix audit-heads/ --query 'sort_by(Contents, &LastModified)[-1].Key' --output text 2> /dev/null || true)
if [ -n "$newest" ] && [ "$newest" != None ]; then
  aws s3 cp --only-show-errors "s3://$bucket/$newest" "$work/anchor.jsonl"
  log "verifying against $newest"
  compose exec -T app php artisan audit:verify --all --anchor=/dev/stdin < "$work/anchor.jsonl"
else
  log "no anchor stored yet: verifying without one"
  compose exec -T app php artisan audit:verify --all
fi
verify_rc=$?
if [ "$verify_rc" -eq 0 ]; then put_metric AuditVerifyFailed 0; else log "audit:verify exited $verify_rc"; put_metric AuditVerifyFailed 1; fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
if compose exec -T app php artisan audit:head --all > "$work/head.jsonl" && [ -s "$work/head.jsonl" ] \
   && aws s3 cp --only-show-errors "$work/head.jsonl" "s3://$bucket/audit-heads/$stamp.jsonl"; then
  put_metric AuditAnchorFailed 0
  log "stored audit-heads/$stamp.jsonl ($(wc -l < "$work/head.jsonl") chains)"
else
  put_metric AuditAnchorFailed 1
  log "the head could not be stored"
  exit 1
fi
exit "$verify_rc"
