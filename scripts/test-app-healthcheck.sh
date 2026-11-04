#!/usr/bin/env bash
# SecureFlow AI — negative tests for the app healthcheck.
# Runs the exact command configured on this project's running app container against throwaway
# containers with an empty or incomplete /var/www/html (no network, nothing else is touched).
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0; fail=0
containers=()
cleanup() { [ ${#containers[@]} -eq 0 ] || docker rm -f "${containers[@]}" >/dev/null 2>&1; }
trap cleanup EXIT

result() { # description ok|bad rc
  local matched=false
  case "$2" in
    ok)  [ "$3" -eq 0 ] && matched=true ;;
    bad) [ "$3" -ne 0 ] && matched=true ;;
  esac
  if [ "$matched" = true ]; then
    echo "  [PASS] $1"; pass=$((pass+1))
  else
    echo "  [FAIL] $1 (rc=$3, want $2)"; fail=$((fail+1))
  fi
}

app=$(docker compose ps -q app)
[ -n "$app" ] || { echo "the app service is not running" >&2; exit 2; }
kind=$(docker inspect --format '{{index .Config.Healthcheck.Test 0}}' "$app")
[ "$kind" = CMD-SHELL ] || { echo "unexpected healthcheck type: $kind" >&2; exit 2; }
cmd=$(docker inspect --format '{{index .Config.Healthcheck.Test 1}}' "$app")
image=$(docker inspect --format '{{.Image}}' "$app")

probe() { docker exec "$1" sh -c "$cmd" >/dev/null 2>&1; }
run_in() { docker exec "$1" sh -c "$2" >/dev/null 2>&1; }

echo "== healthy app =="
probe "$app"; result "the running app passes" ok $?

echo "== php-fpm running, code missing or broken =="
c=$(docker run -d --network none --label secureflow.healthcheck-test=1 --tmpfs /var/www/html:mode=1777 "$image") || exit 2
containers+=("$c")
for _ in $(seq 1 30); do
  run_in "$c" "php -r \"exit(@fsockopen('127.0.0.1', 9000) ? 0 : 1);\"" && break
  sleep 1
done
run_in "$c" "php -r \"exit(@fsockopen('127.0.0.1', 9000) ? 0 : 1);\""; result "precondition: php-fpm accepts TCP connections" ok $?

probe "$c"; result "empty bind mount is unhealthy" bad $?
run_in "$c" 'mkdir -p public; echo "<?php exit(0);" > artisan'
probe "$c"; result "artisan without public/index.php is unhealthy" bad $?
run_in "$c" 'rm artisan; touch public/index.php'
probe "$c"; result "public/index.php without artisan is unhealthy" bad $?
run_in "$c" 'echo "<?php exit(1);" > artisan'
probe "$c"; result "Laravel that cannot run is unhealthy" bad $?
run_in "$c" 'echo "<?php exit(0);" > artisan'
probe "$c"; result "control: the same container passes once both files work" ok $?

echo "== code present, php-fpm not listening =="
c=$(docker run -d --network none --label secureflow.healthcheck-test=1 --tmpfs /var/www/html:mode=1777 --entrypoint sleep "$image" 300) || exit 2
containers+=("$c")
run_in "$c" 'mkdir -p public; echo "<?php exit(0);" > artisan; touch public/index.php'
probe "$c"; result "no php-fpm is unhealthy" bad $?

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
