#!/usr/bin/env bash
# SecureFlow AI — negative tests for the worker and scheduler healthchecks.
# Runs the exact command configured on this project's running containers against throwaway
# containers whose PID 1 and /var/www/html are controlled by the test (no network).
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

# A stand-in for artisan: answers --version, otherwise stays alive like the real command.
STUB='<?php if (($argv[1] ?? "") === "--version") { exit(0); } sleep(600);'
run_in() { docker exec "$1" sh -c "$2" >/dev/null 2>&1; }

start_as() { # image artisan-command -> container whose PID 1 is `php artisan <command>`
  docker run -d --network none --label secureflow.healthcheck-test=1 \
    --tmpfs /var/www/html:mode=1777 -e STUB="$STUB" --entrypoint sh "$1" -c \
    "cd /var/www/html && mkdir -p bootstrap && touch bootstrap/app.php && printf '%s' \"\$STUB\" > artisan && exec php artisan $2"
}

test_service() { # service artisan-command other-artisan-command
  local service=$1 command=$2 other=$3 cid kind cmd image c
  echo "== $service =="
  cid=$(docker compose ps -q "$service")
  [ -n "$cid" ] || { echo "the $service service is not running" >&2; exit 2; }
  kind=$(docker inspect --format '{{index .Config.Healthcheck.Test 0}}' "$cid")
  [ "$kind" = CMD-SHELL ] || { echo "unexpected healthcheck type on $service: $kind" >&2; exit 2; }
  cmd=$(docker inspect --format '{{index .Config.Healthcheck.Test 1}}' "$cid")
  image=$(docker inspect --format '{{.Image}}' "$cid")
  probe() { docker exec "$1" sh -c "$cmd" >/dev/null 2>&1; }

  probe "$cid"; result "the running $service passes with no work to do" ok $?

  c=$(start_as "$image" "$command") || exit 2
  containers+=("$c")
  sleep 1
  probe "$c"; result "control: stand-in $service with source and process passes" ok $?
  run_in "$c" 'mv artisan artisan.off'
  probe "$c"; result "missing artisan is unhealthy" bad $?
  run_in "$c" 'mv artisan.off artisan; mv bootstrap/app.php bootstrap/app.off'
  probe "$c"; result "missing bootstrap/app.php is unhealthy" bad $?
  run_in "$c" 'mv bootstrap/app.off bootstrap/app.php; cp artisan artisan.ok; echo "<?php exit(1);" > artisan'
  probe "$c"; result "Laravel that cannot run is unhealthy" bad $?
  run_in "$c" 'mv artisan.ok artisan'
  probe "$c"; result "control: passes again once restored" ok $?

  c=$(docker run -d --network none --label secureflow.healthcheck-test=1 --tmpfs /var/www/html:mode=1777 --entrypoint sleep "$image" 300) || exit 2
  containers+=("$c")
  probe "$c"; result "empty mount and a different process is unhealthy" bad $?
  run_in "$c" "mkdir -p bootstrap; touch bootstrap/app.php; printf '%s' '$STUB' > artisan"
  probe "$c"; result "source present but the process is not running is unhealthy" bad $?

  c=$(start_as "$image" "$other") || exit 2
  containers+=("$c")
  sleep 1
  probe "$c"; result "the other service's process does not satisfy the check" bad $?
}

test_service worker "queue:work redis" "schedule:work"
test_service scheduler "schedule:work" "queue:work redis"

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
