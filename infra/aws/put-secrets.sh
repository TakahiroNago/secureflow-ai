#!/usr/bin/env bash
# SecureFlow AI — the secrets of the public environment, generated here and written to the parameter store once
# (docs/security-design.md §18, docs/operations.md §6.2). Run by the operator on their own machine, with the profile
# Terraform uses; never on the host, never in CI. Terraform does not see the values, so they are not in its state.
#
#   put-secrets.sh [--profile <aws profile>] [--path /secureflow/prod] [--key-alias alias/secureflow-prod]
#
# A parameter that already exists is left alone: the database passwords are set into the database on its first
# start, and a new value here would lock the application out. To rotate one, change it in the database first, then
# `aws ssm put-parameter --overwrite` by hand. Nothing is printed but the names.
set -euo pipefail

path=/secureflow/prod
key=alias/secureflow-prod
profile=()
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) profile=(--profile "$2"); shift 2 ;;
    --path) path=$2; shift 2 ;;
    --key-alias) key=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# The same way as scripts/init-env.sh.
generate() {
  case "$1" in
    APP_KEY) printf 'base64:%s' "$(openssl rand -base64 32)" ;;
    *) openssl rand -hex 24 ;;
  esac
}

umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

written=0; kept=0
for name in APP_KEY POSTGRES_PASSWORD DB_PASSWORD DB_MIGRATOR_PASSWORD DB_TEST_PASSWORD DB_TEST_MIGRATOR_PASSWORD REDIS_PASSWORD; do
  if aws "${profile[@]}" ssm get-parameter --name "$path/$name" --query Parameter.Name --output text > /dev/null 2>&1; then
    echo "  kept    $path/$name (exists)"
    kept=$((kept + 1))
    continue
  fi
  # The value goes through a file, not the command line.
  python3 - "$path/$name" "$key" "$(generate "$name")" > "$work/input.json" <<'PY'
import json, sys
name, key, value = sys.argv[1:]
print(json.dumps({"Name": name, "Type": "SecureString", "KeyId": key, "Value": value, "Overwrite": False, "Tier": "Standard"}))
PY
  aws "${profile[@]}" ssm put-parameter --cli-input-json "file://$work/input.json" > /dev/null
  rm -f "$work/input.json"
  echo "  written $path/$name"
  written=$((written + 1))
done
echo "done: $written written, $kept kept."
