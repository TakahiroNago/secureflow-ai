#!/usr/bin/env bash
# SecureFlow AI — the Playwright suite in e2e/ against a running stack (docs/test-strategy.md §10, §33): the built
# SPA as nginx serves it, with nginx's own headers and the real worker, in Chromium, Firefox and WebKit. A small TCP
# forwarder in the container gives the browsers localhost:<NGINX_PORT>, which is what Sanctum's stateful domains
# list. It changes no bytes.
#
# It creates users, so it refuses to run unless the caller names this exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-e2e.sh [playwright test arguments]
#
# CI runs it on its own stack, which is thrown away after the job. Needs a migrated database and a built frontend.
# Downloads the image and the packages of e2e/package-lock.json on first use. Screenshots, traces of failures and
# the report land in e2e/output/.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
. scripts/lib/login-limit.sh
: "${NGINX_PORT:=8080}"
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "${CI:-}" != true ] && { [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; }; then
  echo "Refusing to run: this creates users. Name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION." >&2
  exit 2
fi
nginx_id=$(docker compose ps -q nginx)
[ -n "$nginx_id" ] && [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$nginx_id")" = "$P" ] \
  || { echo "Refusing to run: nginx is not running in $P." >&2; exit 2; }
NET=${P}_web
[ "$(docker network inspect -f '{{index .Labels "com.docker.compose.project"}}' "$NET" 2>/dev/null)" = "$P" ] \
  || { echo "Refusing to run: network $NET is not in $P." >&2; exit 2; }

# The same version as e2e/package.json: the browsers in the image belong to it.
PW_VERSION=1.56.1
IMAGE=${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v$PW_VERSION-noble@sha256:f1e7e01021efd65dd1a2c56064be399f3e4de00fd021ac561325f2bfbb2b837a}

mkdir -p "$HOME/tmp"
secrets=$(mktemp -d "$HOME/tmp/e2e-users-XXXXXX")
chmod 700 "$secrets"
trap 'rm -rf "$secrets"' EXIT
in_image() { docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/tmp/npm -v "$PWD/e2e:/work" -w /work "$@"; }

in_image "$IMAGE" npm ci --silent --no-audit --no-fund > /dev/null || { echo 'could not install the e2e packages' >&2; exit 2; }
rm -rf e2e/output

docker compose exec -T app php artisan db:seed --force > /dev/null 2>&1
# A script before this one may have used up the limit per address. In CI this waits for the window to pass.
next_login_window
echo "Target: $P through $NET"

# One set of users per Playwright project, so that what a flow counts is its own. The passwords never touch the
# repository: they go to the container in a file of their own, read-only, removed at the end.
create_user() { # role email password
  printf '%s\n%s\n' "$3" "$3" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$2" --email="$2" --role="$1" > /dev/null 2>&1
}
{
  echo '{'
  sep=''
  for project in chromium firefox webkit chromium-more; do
    printf '%s  "%s": {' "$sep" "$project"
    inner=''
    for who in member:member admin:admin auditor:auditor extra:member; do
      name=${who%%:*}; role=${who##*:}
      email="e2e-$$-$RANDOM-$project-$name@example.com"; pw="start pass phrase $(cat /proc/sys/kernel/random/uuid)"
      create_user "$role" "$email" "$pw" || { echo "could not create $email" >&2; exit 2; }
      printf '%s"%s": {"email": "%s", "password": "%s"}' "$inner" "$name" "$email" "$pw"
      inner=', '
    done
    printf '}'
    sep=$',\n'
  done
  printf '\n}\n'
} > "$secrets/users.json" || exit 2

in_image --network "$NET" -e E2E_PORT="$NGINX_PORT" -e E2E_USERS=/secrets/users.json -v "$secrets:/secrets:ro" "$IMAGE" \
  npx playwright test "$@"
