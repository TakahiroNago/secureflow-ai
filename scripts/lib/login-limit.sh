# SecureFlow AI — sourced by the test scripts, after .env. Long runs log in more than the limit of 30 a minute
# per address allows. On a throwaway stack the counter is cleared instead of waiting a minute. The limiter itself
# stays on, with its real limit, and test-auth-flow.sh does not use this.
#
# If the clearing misses (a different key, a different address) logins answer 429, and the scripts fail on that.

# The caller's addresses, or those this machine reaches nginx from. The same key the throttle middleware builds.
clear_login_limit() { # [address...]
  local project=${COMPOSE_PROJECT_NAME:-secureflow}
  if [ "$project" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$project" ]; then
    return 1
  fi
  local addresses=("$@")
  if [ "$#" -eq 0 ]; then
    mapfile -t addresses < <(
      {
        docker network inspect -f '{{range .IPAM.Config}}{{println .Gateway}}{{end}}' "${project}_web" 2>/dev/null
        docker compose logs --no-color --no-log-prefix --since=5m nginx 2>/dev/null | grep -oE '^[0-9.]+'
      } | grep . | sort -u
    )
  fi
  docker compose exec -T app php -r '
    chdir("/var/www/html"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";
    $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    foreach (array_slice($argv, 1) as $ip) { Illuminate\Support\Facades\RateLimiter::clear(md5("login"."ip|".$ip)); }' \
    "${addresses[@]}" < /dev/null > /dev/null 2>&1
}

# Where clearing is not allowed, waits for the window to pass.
next_login_window() { clear_login_limit || sleep 61; }
