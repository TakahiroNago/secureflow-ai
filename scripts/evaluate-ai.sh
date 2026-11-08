#!/usr/bin/env bash
# SecureFlow AI — the evaluation set against the real provider (docs/test-strategy.md §34). It starts the relay
# (COMPOSE_PROFILES=openai), runs `ai:evaluate` in the worker's container, and leaves the report (Markdown and JSON
# without any text) and the dump (the requests and what the AI wrote, for a person to read) in OUT_DIR on the host.
# Nothing is written into the repository. The .env of the environment must hold the real provider's settings
# (docs/security-design.md §6.1); the key is never printed.
#
# It spends money and sends the attacks of the set to the model, so it refuses to run unless the caller names this
# exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/evaluate-ai.sh [ai:evaluate options]
#
# OUT_DIR defaults to ~/tmp/ai-evaluation/<timestamp>. Not in CI.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; then
  echo "Refusing to run: name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION." >&2
  exit 2
fi
if [ "${AI_PROVIDER:-mock}" != openai ]; then
  echo "Refusing to run: AI_PROVIDER is not openai in .env. For the mock, run ai:evaluate --mock directly." >&2
  exit 2
fi
export COMPOSE_PROFILES=openai

stamp=$(date -u +%Y%m%dT%H%M%SZ)
OUT_DIR=${OUT_DIR:-$HOME/tmp/ai-evaluation/$stamp}
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"
# Inside the container, under the bind mount, and moved out at the end: storage/ is not committed.
work=storage/app/ai-evaluation-$stamp
mkdir -p "backend/$work"
trap 'rm -rf "backend/$work"' EXIT

docker compose up -d --wait worker ai-egress < /dev/null > /dev/null 2>&1 || { echo 'could not start the relay' >&2; exit 2; }
echo "Target: $P, output in $OUT_DIR"

docker compose run --rm --no-deps -T worker php artisan ai:evaluate \
  --json="/var/www/html/$work/results.json" --dump="/var/www/html/$work/texts.json" "$@" < /dev/null \
  | tee "$OUT_DIR/report.md"
rc=${PIPESTATUS[0]}

for f in results.json texts.json; do
  [ -f "backend/$work/$f" ] && mv "backend/$work/$f" "$OUT_DIR/$f"
done
chmod 600 "$OUT_DIR"/* 2>/dev/null || true
echo "Files: $(ls "$OUT_DIR" | tr '\n' ' ')"
exit "$rc"
