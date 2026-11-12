#!/usr/bin/env bash
# SecureFlow AI — write /etc/secureflow/.env from the parameter store (docs/security-design.md §18, step 5-1).
#
# Every parameter under the path (default /secureflow/prod/) becomes one line NAME=value: the parameter name's last
# segment is the variable. SecureString values are decrypted with the instance role; nothing is printed. The file is
# owned by root with mode 600 and read by docker compose with --env-file. Run as root on the host.
#
#   fetch-env.sh [--path /secureflow/prod] [--out /etc/secureflow/.env]
set -euo pipefail

path=/secureflow/prod
out=/etc/secureflow/.env
while [ $# -gt 0 ]; do
  case "$1" in
    --path) path=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root: the file must be unreadable to other users" >&2; exit 2; }

umask 077
mkdir -p "$(dirname "$out")"
tmp=$(mktemp "$(dirname "$out")/.env.XXXXXX")
trap 'rm -f "$tmp"' EXIT

# One page at a time; the names are the last path segment. A value with a newline cannot be an .env line.
aws ssm get-parameters-by-path --path "$path" --recursive --with-decryption --output json \
  | python3 -c '
import json, re, sys
out = []
for p in json.load(sys.stdin)["Parameters"]:
    name = p["Name"].rsplit("/", 1)[-1]
    value = p["Value"]
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
        sys.exit(f"parameter name is not a variable name: {p[\"Name\"]}")
    if "\n" in value or "\r" in value:
        sys.exit(f"parameter value spans lines: {p[\"Name\"]}")
    out.append(f"{name}={value}")
print("\n".join(sorted(out)))
' > "$tmp"

for required in APP_KEY APP_URL PUBLIC_HOST TRUSTED_PROXY_CIDR POSTGRES_PASSWORD DB_DATABASE DB_TEST_DATABASE DB_USERNAME DB_PASSWORD \
                DB_MIGRATOR_USERNAME DB_MIGRATOR_PASSWORD REDIS_PASSWORD; do
  grep -q "^$required=." "$tmp" || { echo "missing in the parameter store: $required" >&2; exit 1; }
done
if grep -qE '^[A-Z_]+=change-me' "$tmp"; then
  echo "placeholder values in the parameter store" >&2; exit 1
fi

chmod 600 "$tmp"
mv "$tmp" "$out"
trap - EXIT
echo "$out written ($(wc -l < "$out") variables)."
