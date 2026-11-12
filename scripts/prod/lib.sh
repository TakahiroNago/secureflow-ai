# SecureFlow AI — shared by scripts/prod/*.sh. Sourced, not run. Everything here runs on the host as root.
#
# Layout on the host (docs/operations.md):
#   /opt/secureflow              the repository, checked out at the deployed tag
#   /etc/secureflow/.env         the environment (scripts/prod/fetch-env.sh), root only
#   /etc/secureflow/images.env   SECUREFLOW_PHP_IMAGE / SECUREFLOW_WEB_IMAGE by digest, written by deploy.sh
#   /etc/secureflow/deployed     the deployed tag and digests; .previous is the one before, for a rollback
#   /var/backups/secureflow      the last dumps, also uploaded to S3 (backup.sh)
set -euo pipefail

SECUREFLOW_HOME=${SECUREFLOW_HOME:-/opt/secureflow}
SECUREFLOW_ETC=${SECUREFLOW_ETC:-/etc/secureflow}
SECUREFLOW_BACKUPS=${SECUREFLOW_BACKUPS:-/var/backups/secureflow}
ENV_FILE=$SECUREFLOW_ETC/.env
IMAGES_FILE=$SECUREFLOW_ETC/images.env

require_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }; }

# docker compose for the production stack. The two env files are read by compose only; this shell never exports them.
compose() {
  docker compose --project-directory "$SECUREFLOW_HOME" --env-file "$ENV_FILE" --env-file "$IMAGES_FILE" -f "$SECUREFLOW_HOME/compose.prod.yaml" "$@"
}

# One value from the .env, without exporting the rest.
env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | head -1; }

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# A metric for CloudWatch: the alarms of docs/operations.md watch these (namespace SecureFlow).
put_metric() { # name value
  aws cloudwatch put-metric-data --namespace SecureFlow --metric-name "$1" --value "$2" --unit Count > /dev/null 2>&1 \
    || log "warning: could not publish the metric $1"
}
