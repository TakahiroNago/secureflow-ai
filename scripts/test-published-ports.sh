#!/usr/bin/env bash
# SecureFlow AI — negative tests for scripts/check-published-ports.sh (P0-NET-01).
# Saved records cover every address form; throwaway containers prove it against real Docker.
# The containers only run `sleep` and carry a test label; nothing else is touched.
set -uo pipefail
cd "$(dirname "$0")/.."

CHECK=scripts/check-published-ports.sh
IMAGE=nginx:1.30.6-alpine3.24 # the pinned compose image; EXPOSEs 80
PREFIX="sf-port-policy-$$"

pass=0; fail=0; skip=0
containers=()
tmp=$(mktemp -d)
cleanup() {
  [ ${#containers[@]} -eq 0 ] || docker rm -f "${containers[@]}" >/dev/null 2>&1
  rm -rf "$tmp"
}
trap cleanup EXIT

expect() { # description expected_rc expected_text(may be empty) args...
  local desc=$1 want_rc=$2 want_text=$3 out rc; shift 3
  out=$(bash "$CHECK" "$@" 2>&1); rc=$?
  if [ "$rc" -eq "$want_rc" ] && { [ -z "$want_text" ] || grep -qF -- "$want_text" <<< "$out"; }; then
    echo "  [PASS] $desc"; pass=$((pass+1))
  else
    echo "  [FAIL] $desc (rc=$rc, want $want_rc, want text '$want_text')"; echo "$out" | sed 's/^/         /'; fail=$((fail+1))
  fi
}
records() { printf '%b' "$1" > "$tmp/records"; }

ALLOW=(--allow "nginx 80/tcp 8080" --allow "frontend 5173/tcp 5173")
mode() { echo "MODE|/c|$1|bridge|false\n"; }
bind() { echo "BIND|/c|$1|runtime|$2|$3|$4\n"; }

echo "== saved records =="
records "$(mode nginx)$(bind nginx 80/tcp 127.0.0.1 8080)"
expect "allowed port on 127.0.0.1 passes" 0 "OK:" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode redis)"
expect "container with no published port passes" 0 "OK:" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode nginx)$(bind nginx 80/tcp 0.0.0.0 8080)"
expect "IPv4 0.0.0.0 fails, even for an allowed port" 1 "all IPv4" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode nginx)$(bind nginx 80/tcp :: 8080)"
expect "IPv6 :: fails, even for an allowed port" 1 "all IPv6" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode nginx)$(bind nginx 80/tcp '[::]' 8080)"
expect "IPv6 [::] fails" 1 "all IPv6" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode nginx)$(bind nginx 80/tcp '' 8080)"
expect "empty host address fails" 1 "all interfaces" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode nginx)$(bind nginx 80/tcp ::1 8080)"
expect "IPv6 loopback ::1 fails (policy is 127.0.0.1 only)" 1 "not bound to 127.0.0.1" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode nginx)$(bind nginx 80/tcp 192.168.1.10 8080)"
expect "specific LAN address fails" 1 "not bound to 127.0.0.1" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode postgres)$(bind postgres 5432/tcp 127.0.0.1 5432)"
expect "unexpected service on 127.0.0.1 fails" 1 "not on the allow list" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode nginx)$(bind nginx 80/tcp 127.0.0.1 9999)"
expect "allowed service on an unexpected host port fails" 1 "not on the allow list" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode nginx)$(bind nginx 443/tcp 127.0.0.1 8080)"
expect "unexpected container port fails" 1 "not on the allow list" "${ALLOW[@]}" --records "$tmp/records"
records "$(mode nginx)$(bind nginx 80/tcp 127.0.0.1 8080)$(bind nginx 80/tcp 0.0.0.0 8080)"
expect "one bad binding next to a good one fails" 1 "all IPv4" "${ALLOW[@]}" --records "$tmp/records"
records "MODE|/c|nginx|host|false\n"
expect "host network mode fails" 1 "network mode" "${ALLOW[@]}" --records "$tmp/records"
records "MODE|/c|nginx|bridge|true\n"
expect "publish-all fails" 1 "publish-all" "${ALLOW[@]}" --records "$tmp/records"
records ""
expect "empty records cannot pass" 2 "" "${ALLOW[@]}" --records "$tmp/records"
records "$(bind nginx 80/tcp 127.0.0.1 8080)"
expect "bindings without a container record cannot pass" 2 "" "${ALLOW[@]}" --records "$tmp/records"
records "GARBAGE|x\n"
expect "malformed records cannot pass" 2 "" "${ALLOW[@]}" --records "$tmp/records"

echo "== real containers =="
start() { # suffix docker-run-args...
  local name="$PREFIX-$1"; shift
  docker run -d --name "$name" --label secureflow.port-policy-test=1 "$@" "$IMAGE" sleep 300 >/dev/null 2>"$tmp/run.err" || return 1
  containers+=("$name")
  echo "$name"
}

# The number has to be explicit, because the policy refuses a port Docker picks. Anything on the host can already
# be using it, and then another one is tried. A container that failed to start keeps its name.
for attempt in 1 2 3 4 5; do
  port=$((30000 + RANDOM % 10000))
  c=$(start ok -p "127.0.0.1:$port:80") && break
  c=''
  grep -qE 'address already in use|port is already allocated' "$tmp/run.err" || break
  docker rm -f "$PREFIX-ok" > /dev/null 2>&1
done
if [ -n "$c" ]; then
  expect "real: allowed 127.0.0.1 binding passes" 0 "OK:" --allow "$c 80/tcp $port" "$c"
  expect "real: the same binding fails without an allow entry" 1 "not on the allow list" "$c"
  expect "real: the same binding fails with the wrong host port" 1 "not on the allow list" --allow "$c 80/tcp 1" "$c"
else
  echo "  [FAIL] could not start the positive container: $(cat "$tmp/run.err")"; fail=$((fail+1))
fi
if c=$(start v4 -p "0.0.0.0::80"); then
  expect "real: 0.0.0.0 fails" 1 "all IPv4" "$c"
else
  echo "  [FAIL] could not start the 0.0.0.0 container: $(cat "$tmp/run.err")"; fail=$((fail+1))
fi
if c=$(start v6 -p "[::]::80"); then
  expect "real: [::] fails" 1 "all IPv6" "$c"
else
  # Hosts without IPv6 cannot create this binding; saved records still cover it.
  echo "  [SKIP] real: [::] (not supported by this Docker host: $(head -c 160 "$tmp/run.err"))"; skip=$((skip+1))
fi
if c=$(start all -p 80); then
  expect "real: -p 80 (all interfaces) fails" 1 "VIOLATION" "$c"
else
  echo "  [FAIL] could not start the -p 80 container: $(cat "$tmp/run.err")"; fail=$((fail+1))
fi
if c=$(start publishall -P); then
  expect "real: -P fails" 1 "publish-all" "$c"
else
  echo "  [FAIL] could not start the -P container: $(cat "$tmp/run.err")"; fail=$((fail+1))
fi
if c=$(start hostnet --network host); then
  expect "real: --network host fails" 1 "network mode" "$c"
else
  echo "  [FAIL] could not start the host network container: $(cat "$tmp/run.err")"; fail=$((fail+1))
fi
if c=$(start none); then
  expect "real: container without published ports passes" 0 "OK:" "$c"
else
  echo "  [FAIL] could not start the unpublished container: $(cat "$tmp/run.err")"; fail=$((fail+1))
fi
expect "real: unknown container cannot pass" 2 "" "$PREFIX-does-not-exist"
expect "real: no containers cannot pass" 2 ""

echo
echo "Result: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
