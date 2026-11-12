#!/usr/bin/env bash
# SecureFlow AI — the public environment stack as compose.prod.yaml runs it (docs/test-strategy.md §36, PROD-01 to PROD-06).
#
# Runs against a started production stack whose images were built locally, with .env made by scripts/init-env.sh plus
# the production variables (see .github/workflows/ci.yml, job prod-stack). It recreates nginx once with another trusted
# range and makes requests that count against the login limit, so it runs only on a throwaway stack: a project other
# than the default one, or CI.
#
#   PROD-01  what is in the images and what is not (no development dependency, no tests, caches built at start)
#   PROD-02  the headers of the design plus HSTS, on every kind of answer, and the two header files differ by HSTS alone
#   PROD-03  the client address: X-Forwarded-For counts from the trusted range only, in nginx and in the audit log
#   PROD-04  app has no route out of the host; nginx (on edge) has one, so the difference is the network
#   PROD-05  the php-fpm settings of §22 A-3 are in force, and the healthcheck reads the status page
#   PROD-06  the stack's shape: no bind mount of code, internal networks, nginx the only publisher, no dev service
#   PROD-07  the first organization and admin come from organization:create and user:create (db:seed is refused),
#            and that admin logs in through nginx
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
: "${NGINX_PORT:=8080}"
: "${TRUSTED_PROXY_CIDR:?set TRUSTED_PROXY_CIDR in .env}"
if [ "${COMPOSE_PROJECT_NAME:-secureflow}" = secureflow ] && [ "${CI:-}" != true ]; then
  echo "Refusing to run: this recreates nginx and spends the login limit. Use a separate project or CI." >&2
  exit 2
fi
export COMPOSE_FILE=compose.prod.yaml
BASE=http://127.0.0.1:$NGINX_PORT
work=$(mktemp -d)
restore() {
  # Back to the trusted range of .env, whatever happened in PROD-03.
  docker compose up -d --wait --no-deps --force-recreate nginx > /dev/null 2>&1 < /dev/null
  rm -rf "$work"
}
trap restore EXIT

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else ng "$1"; fi; }

header() { # name file
  awk -v name="$(printf '%s' "$1" | tr 'A-Z' 'a-z')" '{ line = $0; sub(/\r$/, "", line); split(line, parts, ":"); if (tolower(parts[1]) == name) { sub(/^[^:]*:[ \t]*/, "", line); print line } }' "$2"
}
fetch() { STATUS=$(curl -s -o "$work/b" -D "$work/h" -w '%{http_code}' --max-time 20 "$@"); }
in_app() { docker compose exec -T app sh -c "$1"; }
sql() { docker compose exec -T -e PGPASSWORD="$DB_PASSWORD" postgres psql -h 127.0.0.1 -U "$DB_USERNAME" -d "$DB_DATABASE" --no-psqlrc -tAc "$1"; }

HSTS='max-age=31536000; includeSubDomains'
CSP="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
headers_of() { # label
  is "$1: Strict-Transport-Security" "$(header Strict-Transport-Security "$work/h")" "$HSTS"
  is "$1: Content-Security-Policy" "$(header Content-Security-Policy "$work/h")" "$CSP"
  is "$1: X-Content-Type-Options" "$(header X-Content-Type-Options "$work/h")" nosniff
  is "$1: X-Frame-Options" "$(header X-Frame-Options "$work/h")" DENY
  is "$1: Referrer-Policy" "$(header Referrer-Policy "$work/h")" no-referrer
  is "$1: Cross-Origin-Opener-Policy" "$(header Cross-Origin-Opener-Policy "$work/h")" same-origin
}

echo "== PROD-01: what is in the images =="
check "no development dependency (pest) in the image" "in_app 'test ! -e vendor/pestphp'"
check "no tests in the image" "in_app 'test ! -e tests'"
check "no .env in the image" "in_app 'test ! -e .env && test ! -e .env.testing'"
check "the configuration cache was built at start" "in_app 'test -f bootstrap/cache/config.php'"
check "the route cache was built at start" "in_app 'ls bootstrap/cache/routes-*.php'"
check "the code is owned by the running user, not root" "in_app 'test \"\$(stat -c %U artisan)\" = \"\$(id -un)\"'"
check "no PCOV in the production image" "! in_app 'php -m' | grep -qi pcov"
is "opcache does not look at timestamps" "$(in_app 'php -r "echo ini_get(\"opcache.validate_timestamps\");"')" 0
is "the application runs as production, with the mock" "$(in_app 'php artisan env' | tr -d '\r' | sed -n 's/.*\[\(.*\)\].*/\1/p')" production
check "the web image holds the SPA" "docker compose exec -T nginx test -f /usr/share/nginx/html/index.html"
check "the web image holds no source" "docker compose exec -T nginx sh -c 'test ! -e /usr/share/nginx/html/src && test ! -e /usr/share/nginx/html/package.json'"
is "php-fpm runs as a user, not root" "$(in_app 'id -u' | tr -d '\r')" "$(in_app 'stat -c %u artisan' | tr -d '\r')"
check "and that user is not root" "[ \"\$(in_app 'id -u' | tr -d '\r')\" != 0 ]"
is "nginx runs as the nginx user, master process included" "$(docker compose exec -T nginx sh -c "tr '\\0' ' ' < /proc/1/cmdline | grep -q 'nginx: master' && id -u" | tr -d '\r')" 101

echo "== PROD-02: the headers, with HSTS, on every kind of answer =="
fetch "$BASE/"; is "the page" "$STATUS" 200; headers_of "the page"
fetch "$BASE/api/health/live"; is "health" "$STATUS" 200; headers_of "health"
fetch "$BASE/api/health/ready"; is "readiness" "$STATUS" 200
fetch -H 'Accept: application/json' "$BASE/api/v1/auth/me"; is "an API answer" "$STATUS" 401; headers_of "an API answer"
fetch "$BASE/assets/no-such-file.js"; is "a missing asset" "$STATUS" 404; headers_of "a missing asset"
head -c 2200000 /dev/zero > "$work/big"
fetch -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' --data-binary "@$work/big" "$BASE/api/v1/analyses"
is "nginx's own answer" "$STATUS" 413; headers_of "nginx's own answer"
check "the production header file differs from the development one by HSTS alone" \
  "diff <(grep -v '^#' docker/nginx/snippets/security-headers.conf) <(grep -v '^#' docker/nginx/prod/security-headers.conf | grep -v Strict-Transport-Security)"
is "and it sends exactly that HSTS" "$(grep -c "^add_header Strict-Transport-Security \"$HSTS\" always;\$" docker/nginx/prod/security-headers.conf)" 1

echo "== PROD-03: the client address from the trusted range only =="
# The application: a refused login is an audit event with the client's address (the role may read audit_logs).
login() { # forwarded-for
  rm -f "$work/jar"
  curl -s -o /dev/null -c "$work/jar" --max-time 20 ${1:+-H "X-Forwarded-For: $1"} "$BASE/sanctum/csrf-cookie"
  token=$(awk '$6 == "XSRF-TOKEN" { print $7 }' "$work/jar" | python3 -c 'import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))')
  curl -s -o /dev/null -b "$work/jar" --max-time 20 ${1:+-H "X-Forwarded-For: $1"} -H "X-XSRF-TOKEN: $token" \
    -H 'Accept: application/json' -H 'Content-Type: application/json' -H "Origin: http://${PUBLIC_HOST}" -H "Referer: http://${PUBLIC_HOST}/" \
    --data '{"email":"nobody@example.com","password":"a password that is wrong"}' "$BASE/api/v1/auth/login"
}
last_ip() { sql "SELECT host(ip_address) FROM audit_logs WHERE event_type = 'auth.login_failed' ORDER BY id DESC LIMIT 1"; }
recreate_nginx() { # trusted range, or nothing for the value of .env
  env ${1:+TRUSTED_PROXY_CIDR=$1} docker compose up -d --wait --no-deps --force-recreate nginx > /dev/null 2>&1 < /dev/null
}
rendered_range() { docker compose exec -T nginx sh -c 'sed -n "s/^set_real_ip_from \(.*\);/\1/p" /etc/nginx/conf.d/10-real-ip.conf' | tr -d '\r'; }

# What nginx sees as the connection's address: on this machine the host's bridge, in production the load balancer.
login ""
conn_ip=$(last_ip)
if [ -n "$conn_ip" ]; then ok "a refused login is in the audit log with the connection's address ($conn_ip)"; else ng "a refused login is in the audit log with the connection's address"; fi

# Trusted: nginx is told that this address is the proxy.
recreate_nginx "$conn_ip/32"
is "nginx came back trusting the connection's address" "$(rendered_range)" "$conn_ip/32"
# The csrf-cookie limit of nginx (60/min per address) is not reached when every request names another client ...
limited=0
for i in $(seq 1 75); do
  fetch -H "X-Forwarded-For: 203.0.113.$((i % 250 + 1))" "$BASE/sanctum/csrf-cookie"
  [ "$STATUS" = 429 ] && { limited=1; break; }
done
is "nginx counts the forwarded client, from the trusted range" "$limited" 0
login 198.51.100.7
is "the audit log records the forwarded client" "$(last_ip)" 198.51.100.7
login ""
is "the audit log records the connection itself without the header" "$(last_ip)" "$conn_ip"
# ... and is reached by one client that sends no header.
limited=0
for _ in $(seq 1 75); do
  fetch "$BASE/sanctum/csrf-cookie"
  [ "$STATUS" = 429 ] && { limited=1; break; }
done
is "nginx counts the connection itself without the header" "$limited" 1

# Untrusted: nginx trusts another range, so the same header must count for nothing.
recreate_nginx 192.0.2.0/24
is "nginx came back with another trusted range" "$(rendered_range)" 192.0.2.0/24
login 198.51.100.9
is "from an untrusted connection, the header is ignored" "$(last_ip)" "$conn_ip"
limited=0
for i in $(seq 1 75); do
  fetch -H "X-Forwarded-For: 203.0.113.$((i % 250 + 1))" "$BASE/sanctum/csrf-cookie"
  [ "$STATUS" = 429 ] && { limited=1; break; }
done
is "nginx does not count a header from an untrusted connection" "$limited" 1
recreate_nginx

echo "== PROD-04: app has no route out of the host =="
# fsockopen to an address, not a name: name resolution is not what is being tested. 1.1.1.1:443 answers from anywhere.
in_app 'php -r "exit(@fsockopen(\"1.1.1.1\", 443, \$e, \$s, 3) ? 1 : 0);"'
is "app cannot open a connection to the internet" "$?" 0
docker compose exec -T nginx nc -z -w 3 1.1.1.1 443 > /dev/null 2>&1
is "nginx (on edge) can, so the difference is the network, not this machine" "$?" 0
in_app 'php -r "exit(@fsockopen(\"postgres\", 5432, \$e, \$s, 3) ? 0 : 1);"'
is "app still reaches the database" "$?" 0

echo "== PROD-05: the php-fpm settings of §22 A-3 =="
fpm=$(in_app 'php-fpm -tt 2>&1')
is "request_terminate_timeout is 30 seconds" "$(printf '%s\n' "$fpm" | grep -c 'request_terminate_timeout = 30s')" 1
is "the status page listens on its own port" "$(printf '%s\n' "$fpm" | grep -c 'pm.status_listen = 127.0.0.1:9001')" 1
check "the healthcheck passes on the running app" "in_app secureflow-healthcheck"
is "the healthcheck reads the status page" "$(in_app 'SCRIPT_NAME=/fpm-status SCRIPT_FILENAME=/fpm-status REQUEST_METHOD=GET cgi-fcgi -bind -connect 127.0.0.1:9001' | grep -c '^listen queue:')" 1
check "the status page is not routed by nginx" "[ \"\$(curl -s -o /dev/null -w '%{http_code}' $BASE/fpm-status)\" = 200 ] && ! curl -s $BASE/fpm-status | grep -q '^pool:'"

echo "== PROD-06: the stack's shape =="
config=$(docker compose --profile tools --profile openai config --format json)
py() { python3 -c "import json, sys; c = json.load(sys.stdin); $1" <<< "$config"; }
is "no service mounts code from the host" "$(py 'print(sum(1 for s in c["services"].values() for v in s.get("volumes", []) if v.get("type") == "bind" and "/docker/" not in v["source"]))')" 0
is "no service builds an image" "$(py 'print(sum(1 for s in c["services"].values() if "build" in s))')" 0
is "data and web are internal" "$(py 'print(all(c["networks"][n].get("internal") is True for n in ("data", "web")))')" True
is "edge is not" "$(py 'print(c["networks"]["edge"].get("internal") is not True)')" True
is "nginx alone publishes a port" "$(py 'print(sorted(n for n, s in c["services"].items() if s.get("ports")))')" "['nginx']"
is "nginx publishes port 80 only" "$(py 'print([p["target"] for p in c["services"]["nginx"]["ports"]])')" "[80]"
is "only nginx is on edge" "$(py 'print(sorted(n for n, s in c["services"].items() if "edge" in s.get("networks", {})))')" "['nginx']"
is "app is on data and web" "$(py 'print(sorted(c["services"]["app"]["networks"]))')" "['data', 'web']"
is "no frontend and no test service" "$(py 'print(sorted(set(c["services"]) & {"frontend", "test"}))')" "[]"
is "APP_DEBUG is false" "$(py 'print(c["services"]["app"]["environment"]["APP_DEBUG"])')" false
is "the owner role reaches migrate only" "$(py 'print(sorted(n for n, s in c["services"].items() if "DB_MIGRATOR_PASSWORD" in s.get("environment", {})))')" "['migrate', 'postgres']"
check "no container healthcheck or restart depends on the readiness endpoint" "! docker compose config | grep -q 'health/ready'"
check "every container is healthy" "[ -z \"\$(docker compose ps --format '{{.Name}} {{.Health}}' | grep -v ' healthy$')\" ]"

echo "== PROD-07: the first organization and admin, in production =="
is "db:seed is refused in production (docs/database-design.md §4.5)" "$(in_app 'php artisan db:seed --force 2>&1' | grep -ci 'prohibited')" 1
is "and seeded nothing" "$(sql "SELECT count(*) FROM organizations WHERE name = 'Default Organization'")" 0
check "organization:create makes the first organization" "in_app \"php artisan organization:create --name='Prod Org'\""
check "and refuses the same name again" "! in_app \"php artisan organization:create --name='Prod Org'\""
is "the organization has its default settings" "$(sql "SELECT monthly_token_limit FROM organization_settings s JOIN organizations o ON o.id = s.organization_id WHERE o.name = 'Prod Org'")" 1000000
ADMIN=admin-$$@example.com; PW='prod stack passphrase 01'
check "user:create makes an admin, with the password on stdin only" \
  "printf '%s\n%s\n' \"\$PW\" \"\$PW\" | docker compose exec -T app php artisan user:create --organization='Prod Org' --name=Admin --email=$ADMIN --role=admin"
rm -f "$work/jar"
curl -s -o /dev/null -c "$work/jar" --max-time 20 "$BASE/sanctum/csrf-cookie"
token=$(awk '$6 == "XSRF-TOKEN" { print $7 }' "$work/jar" | python3 -c 'import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))')
STATUS=$(curl -s -o "$work/b" -b "$work/jar" -c "$work/jar" --max-time 20 -H "X-XSRF-TOKEN: $token" -w '%{http_code}' \
  -H 'Accept: application/json' -H 'Content-Type: application/json' -H "Origin: http://${PUBLIC_HOST}" -H "Referer: http://${PUBLIC_HOST}/" \
  --data "{\"email\":\"$ADMIN\",\"password\":\"$PW\"}" "$BASE/api/v1/auth/login")
is "the admin logs in through nginx" "$STATUS" 200
STATUS=$(curl -s -o "$work/b" -b "$work/jar" --max-time 20 -w '%{http_code}' -H 'Accept: application/json' -H "Origin: http://${PUBLIC_HOST}" -H "Referer: http://${PUBLIC_HOST}/" "$BASE/api/v1/auth/me")
is "and the session works" "$STATUS" 200
is "as admin" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["data"]["role"])' "$work/b" 2>/dev/null)" admin
is "the login is in the audit log with the connection's address" "$(sql "SELECT host(ip_address) FROM audit_logs WHERE event_type = 'auth.login' ORDER BY id DESC LIMIT 1")" "$conn_ip"

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
