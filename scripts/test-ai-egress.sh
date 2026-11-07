#!/usr/bin/env bash
# SecureFlow AI — the worker's way out (docs/test-strategy.md §28): OpenAI through the relay, and nothing else. It starts
# the relay and makes one request to OpenAI with no key and no text, which answers 401. It refuses to run unless the
# caller names this exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-ai-egress.sh
#
# Not in CI: a required check should not depend on OpenAI being up. scripts/test-compose-env.sh checks the configuration.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; then
  echo "Refusing to run: name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION." >&2
  exit 2
fi
export COMPOSE_PROFILES=openai

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }

docker compose up -d --wait worker ai-egress < /dev/null > /dev/null 2>&1 || { echo 'could not start the relay' >&2; docker compose logs --no-color ai-egress < /dev/null 2>&1 | tail -5; exit 2; }
relay=$(docker compose ps -q ai-egress)
worker=$(docker compose ps -q worker)
relay_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${P}_data\").IPAddress}}" "$relay")

# Prints: errno http issuer. Never sends a key: the request has no Authorization header at all.
fetch() { # url [resolve]
  docker compose exec -T worker php -r '
    $c = curl_init($argv[1]);
    curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 6, CURLOPT_TIMEOUT => 10, CURLOPT_CERTINFO => true]);
    if (($argv[2] ?? "") !== "") { curl_setopt($c, CURLOPT_RESOLVE, [$argv[2]]); }
    curl_exec($c);
    $issuer = "-";
    foreach (curl_getinfo($c, CURLINFO_CERTINFO) ?: [] as $cert) { $issuer = str_replace(" ", "_", $cert["Issuer"] ?? "-"); break; }
    echo curl_errno($c), " ", curl_getinfo($c, CURLINFO_HTTP_CODE), " ", $issuer;' -- "$@" < /dev/null | tr -d '\r'
}

echo "== the worker stays where it was =="
is "the worker is on the internal network only" "$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$worker" | xargs)" "${P}_data"
is "that network has no way out" "$(docker network inspect -f '{{.Internal}}' "${P}_data")" true

echo "== OpenAI, through the relay =="
is "the name is the relay on this network" "$(docker compose exec -T worker php -r 'echo gethostbyname("api.openai.com");' < /dev/null | tr -d '\r')" "$relay_ip"
read -r errno http issuer <<< "$(fetch https://api.openai.com/v1/models)"
is "it arrives, and the certificate verifies" "$errno" 0
is "OpenAI answers: no key was sent" "$http" 401
if grep -qiE 'avast' <<< "$issuer"; then ng "the certificate is not one made on the way ($issuer)"; else ok "the certificate is not one made on the way"; fi
echo "  [SEEN] issuer: $issuer"

echo "== nothing else =="
read -r errno http _ <<< "$(fetch https://example.com/)"
is "another name does not resolve" "$errno" 6
read -r errno http _ <<< "$(fetch https://1.1.1.1/)"
[ "$http" = 0 ] && [ "$errno" != 0 ] && ok "an address directly goes nowhere (curl $errno)" || ng "an address directly goes nowhere (curl $errno, http $http)"
read -r errno http _ <<< "$(fetch https://example.com/ "example.com:443:$relay_ip")"
[ "$http" = 0 ] && [ "$errno" != 0 ] && ok "the relay does not carry another name (curl $errno)" || ng "the relay does not carry another name (curl $errno, http $http)"
read -r errno http _ <<< "$(fetch "https://$relay_ip/")"
[ "$http" = 0 ] && [ "$errno" != 0 ] && ok "or no name at all (curl $errno)" || ng "or no name at all (curl $errno, http $http)"

echo "== the relay holds nothing =="
env_of_relay=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$relay")
if grep -qE '^(OPENAI|DB_|REDIS_|APP_KEY)' <<< "$env_of_relay"; then ng "it has no secret in its environment"; else ok "it has no secret in its environment"; fi
is "it publishes no port" "$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$relay")" '{}'
is "its filesystem is read-only" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$relay")" true
is "it runs as nobody in particular" "$(docker inspect -f '{{.Config.User}}' "$relay")" '101:101'
is "it has no capabilities" "$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$relay")" '["ALL"]'

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
