#!/usr/bin/env bash
# SecureFlow AI — what nginx answers by itself under /api/ (docs/test-strategy.md §29): the headers of the design on every
# kind of answer, and RFC 9457 for its own errors. It stops the app for a moment, so it runs only on a throwaway stack: a
# project other than the default one, or CI.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
: "${NGINX_PORT:=8080}"
if [ "${COMPOSE_PROJECT_NAME:-secureflow}" = secureflow ] && [ "${CI:-}" != true ]; then
  echo "Refusing to run: this stops the app. Use a separate project (README: 複数環境の同時起動) or CI." >&2
  exit 2
fi
BASE=http://127.0.0.1:$NGINX_PORT
work=$(mktemp -d)
restore() { docker compose up -d --wait --no-deps app > /dev/null 2>&1 < /dev/null; rm -rf "$work"; }
trap restore EXIT

pass=0; fail=0
ok() { echo "  [PASS] $1"; pass=$((pass+1)); }
ng() { echo "  [FAIL] $1"; fail=$((fail+1)); }
is() { if [ "$2" = "$3" ]; then ok "$1"; else ng "$1 (got '$2', want '$3')"; fi; }

CSP="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

header() { # name file
  awk -v name="$(printf '%s' "$1" | tr 'A-Z' 'a-z')" 'BEGIN { IGNORECASE = 1 } { line = $0; sub(/\r$/, "", line); split(line, parts, ":"); if (tolower(parts[1]) == name) { sub(/^[^:]*:[ \t]*/, "", line); print line } }' "$2"
}
# Sets STATUS, and fills $work/h and $work/b.
fetch() {
  STATUS=$(curl -s -o "$work/b" -D "$work/h" -w '%{http_code}' --max-time 20 "$@")
}
headers_of() { # label
  is "$1: Content-Security-Policy" "$(header Content-Security-Policy "$work/h")" "$CSP"
  is "$1: X-Content-Type-Options" "$(header X-Content-Type-Options "$work/h")" nosniff
  is "$1: X-Frame-Options" "$(header X-Frame-Options "$work/h")" DENY
  is "$1: Referrer-Policy" "$(header Referrer-Policy "$work/h")" no-referrer
  is "$1: Permissions-Policy" "$(header Permissions-Policy "$work/h")" 'camera=(), microphone=(), geolocation=(), payment=()'
  is "$1: Cross-Origin-Opener-Policy" "$(header Cross-Origin-Opener-Policy "$work/h")" same-origin
}
problem() { # label status code
  is "$1: the status" "$STATUS" "$2"
  is "$1: the format" "$(header Content-Type "$work/h")" application/problem+json
  is "$1: the code" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["code"])' "$work/b")" "$3"
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["status"]==int(sys.argv[2]) and d["trace_id"] and d["title"] and d["detail"] else 1)' "$work/b" "$2"; then ok "$1: all its fields"; else ng "$1: all its fields"; fi
  if grep -qiE 'nginx|<html|fastcgi|/var/www' "$work/b"; then ng "$1: nothing internal"; else ok "$1: nothing internal"; fi
  headers_of "$1"
}

echo "== the headers, on every kind of answer =="
fetch "$BASE/"; is "the page" "$STATUS" 200; headers_of "the page"
asset=$(grep -oE '/assets/[^"]+\.js' frontend/dist/index.html | head -1)
fetch "$BASE$asset"; is "an asset" "$STATUS" 200; headers_of "an asset"
fetch "$BASE/assets/no-such-file.js"; is "a missing asset" "$STATUS" 404; headers_of "a missing asset"
fetch "$BASE/api/health/live"; is "health" "$STATUS" 200; headers_of "health"
is "health: not kept" "$(header Cache-Control "$work/h")" 'no-store, private'
fetch -H 'Accept: application/json' "$BASE/api/v1/auth/me"; is "an API answer" "$STATUS" 401; headers_of "an API answer"
is "an API answer: not kept" "$(header Cache-Control "$work/h")" 'no-store, private'
is "an API answer: the format" "$(header Content-Type "$work/h")" application/problem+json
fetch -H 'Accept: application/json' "$BASE/api/v1/no-such-thing"; is "no such route" "$STATUS" 404; is "no such route: the code" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["code"])' "$work/b")" NOT_FOUND
fetch -X DELETE -H 'Accept: application/json' "$BASE/api/health/live"
is "a wrong method" "$STATUS" 405
if grep -q '"code":"METHOD_NOT_ALLOWED"\|"message"' "$work/b"; then ok "a wrong method says little"; else ng "a wrong method says little"; fi
fetch "$BASE/.env"; is "a hidden file" "$STATUS" 404
if grep -q 'APP_KEY' "$work/b"; then ng "and nothing of it"; else ok "and nothing of it"; fi

echo "== what nginx answers by itself =="
head -c 2200000 /dev/zero > "$work/big"
fetch -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' --data-binary "@$work/big" "$BASE/api/v1/analyses"
problem "too large" 413 PAYLOAD_TOO_LARGE

limited=0
for _ in $(seq 1 80); do
  fetch -H 'Accept: application/json' "$BASE/sanctum/csrf-cookie"
  [ "$STATUS" = 429 ] && { limited=1; break; }
done
is "csrf-cookie has a limit" "$limited" 1
problem "the limit of nginx" 429 RATE_LIMITED
[ -n "$(header Retry-After "$work/h")" ] && ok "the limit of nginx: Retry-After" || ng "the limit of nginx: Retry-After"
is "the limit of nginx: not kept" "$(header Cache-Control "$work/h")" 'no-store'

docker compose stop app > /dev/null 2>&1 < /dev/null
fetch -H 'Accept: application/json' "$BASE/api/v1/auth/me"
# Refused (502) or not answered within fastcgi_connect_timeout (504): which one depends on the network.
if [ "$STATUS" = 504 ]; then problem "the app is down" 504 GATEWAY_TIMEOUT; else problem "the app is down" 502 BAD_GATEWAY; fi
is "the app is down: not kept" "$(header Cache-Control "$work/h")" 'no-store'
fetch "$BASE/"
is "the page still comes" "$STATUS" 200

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
