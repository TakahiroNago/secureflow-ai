#!/usr/bin/env bash
# SecureFlow AI — deploy a release to the host, or go back to the previous one (docs/operations.md, step 5-1).
#
#   deploy.sh <tag>          e.g. deploy.sh v1.0.0
#   deploy.sh --rollback     the tag and digests of /etc/secureflow/deployed.previous
#
# In order: the environment from the parameter store, the repository at the tag (compose file and scripts), the two
# images pulled by tag and pinned by digest, a backup, the migrations with the owner role, the services replaced,
# then scripts/prod/check.sh. Each step stops the deploy when it fails, and nothing is replaced before the migration
# succeeded. A rollback replaces the images with the previous digests and does not touch the database: migrations
# are forward-only, and a restore (scripts/prod/restore.sh) is a separate decision.
. "$(dirname "$0")/lib.sh"
require_root

REGISTRY=${SECUREFLOW_REGISTRY:-ghcr.io/takahironago/secureflow-ai}

tag=""; rollback=false
case "${1:-}" in
  --rollback) rollback=true ;;
  v[0-9]*) tag=$1 ;;
  *) echo "usage: deploy.sh <tag> | --rollback" >&2; exit 2 ;;
esac

if [ "$rollback" = true ]; then
  [ -f "$SECUREFLOW_ETC/deployed.previous" ] || { log "nothing to roll back to"; exit 1; }
  tag=$(sed -n 's/^TAG=//p' "$SECUREFLOW_ETC/deployed.previous")
  log "rolling back to $tag"
fi

log "1/7 the environment"
bash "$SECUREFLOW_HOME/scripts/prod/fetch-env.sh" > /dev/null

log "2/7 the repository at $tag"
git -C "$SECUREFLOW_HOME" fetch --quiet --tags origin
git -C "$SECUREFLOW_HOME" -c advice.detachedHead=false checkout --quiet "$tag"

log "3/7 the images"
umask 077
if [ "$rollback" = true ]; then
  php_image=$(sed -n 's/^SECUREFLOW_PHP_IMAGE=//p' "$SECUREFLOW_ETC/deployed.previous")
  web_image=$(sed -n 's/^SECUREFLOW_WEB_IMAGE=//p' "$SECUREFLOW_ETC/deployed.previous")
  docker pull --quiet "$php_image" > /dev/null
  docker pull --quiet "$web_image" > /dev/null
else
  docker pull --quiet "$REGISTRY/php:$tag" > /dev/null
  docker pull --quiet "$REGISTRY/web:$tag" > /dev/null
  php_image=$(docker image inspect --format '{{index .RepoDigests 0}}' "$REGISTRY/php:$tag")
  web_image=$(docker image inspect --format '{{index .RepoDigests 0}}' "$REGISTRY/web:$tag")
fi
printf 'SECUREFLOW_PHP_IMAGE=%s\nSECUREFLOW_WEB_IMAGE=%s\n' "$php_image" "$web_image" > "$IMAGES_FILE.next"
log "    php $php_image"
log "    web $web_image"

if [ -f "$SECUREFLOW_ETC/deployed" ]; then
  log "4/7 a backup before anything changes"
  bash "$SECUREFLOW_HOME/scripts/prod/backup.sh" --label pre-deploy
else
  log "4/7 first deploy: nothing to back up yet"
fi

mv "$IMAGES_FILE.next" "$IMAGES_FILE"
if [ "$rollback" = true ]; then
  log "5/7 rollback: the database is left as it is"
else
  log "5/7 postgres and redis, then the migrations (owner role)"
  compose up -d --wait postgres redis
  compose run --rm -T migrate
fi

log "6/7 the services"
compose up -d --wait --remove-orphans

if [ -f "$SECUREFLOW_ETC/deployed" ] && [ "$rollback" = false ]; then cp "$SECUREFLOW_ETC/deployed" "$SECUREFLOW_ETC/deployed.previous"; fi
printf 'TAG=%s\nSECUREFLOW_PHP_IMAGE=%s\nSECUREFLOW_WEB_IMAGE=%s\nDEPLOYED_AT=%s\n' "$tag" "$php_image" "$web_image" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$SECUREFLOW_ETC/deployed"

log "7/7 the checks"
bash "$SECUREFLOW_HOME/scripts/prod/check.sh"
docker image prune -f > /dev/null
log "deployed $tag"
