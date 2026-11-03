#!/usr/bin/env bash
# SecureFlow AI — create a local .env from .env.example with freshly generated secrets.
# Used for local setup and by CI (CI-only throwaway secrets). Never overwrites an existing .env.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo ".env already exists; leaving it unchanged."
  exit 0
fi

umask 077
cp .env.example .env

rand() { openssl rand -hex 24; }
set_kv() { sed -i "s|^$1=.*|$1=$2|" .env; }

set_kv POSTGRES_PASSWORD    "$(rand)"
set_kv DB_PASSWORD          "$(rand)"
set_kv DB_MIGRATOR_PASSWORD "$(rand)"
set_kv REDIS_PASSWORD       "$(rand)"
set_kv APP_KEY              "base64:$(openssl rand -base64 32)"
set_kv HOST_UID             "$(id -u)"
set_kv HOST_GID             "$(id -g)"

if grep -qE '^[A-Z_]+=change-me' .env; then
  echo "ERROR: placeholder values remain in .env" >&2
  exit 1
fi
chmod 600 .env
echo ".env created (permissions 600). Secrets were generated locally and are not printed."
