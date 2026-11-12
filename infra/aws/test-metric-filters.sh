#!/usr/bin/env bash
# SecureFlow AI — the log filters of metric-filters.json against CloudWatch's own parser (docs/test-strategy.md §37,
# INFRA-02). `aws logs test-metric-filter` needs no resource and changes nothing; the operator runs it with the
# Terraform profile before the first apply, and after any change to the patterns or to what the application logs.
#
#   test-metric-filters.sh [--profile <aws profile>]
set -euo pipefail
cd "$(dirname "$0")"

profile=()
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) profile=(--profile "$2"); shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

AWS_PROFILE_ARGS="${profile[*]:-}" python3 - <<'PY'
import json, os, subprocess, sys

spec = json.load(open("metric-filters.json", encoding="utf-8"))
names = list(spec["samples"])
messages = [spec["samples"][n] for n in names]
profile = os.environ["AWS_PROFILE_ARGS"].split()

passed = failed = 0
for name, f in spec["filters"].items():
    want = sorted(f["matches"])
    request = json.dumps({"filterPattern": f["pattern"], "logEventMessages": messages})
    run = subprocess.run(["aws", *profile, "logs", "test-metric-filter", "--cli-input-json", request, "--output", "json"],
                         capture_output=True, text=True)
    if run.returncode != 0:
        print(f"  [FAIL] {name}: {run.stderr.strip()[-300:]}")
        failed += 1
        continue
    got = sorted(names[m["eventNumber"] - 1] for m in json.loads(run.stdout)["matches"])
    if got == want:
        print(f"  [PASS] {name} matches exactly {', '.join(want)}")
        passed += 1
    else:
        print(f"  [FAIL] {name}: matched {got}, want {want}")
        failed += 1

print(f"\nResult: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
PY
