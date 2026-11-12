#!/usr/bin/env bash
# SecureFlow AI — the Semgrep rules themselves (SAST-02, docs/test-strategy.md §31): every rule fires on a probe
# that holds what it forbids, and none fires on clean code. Runs in CI before the real scan, and locally:
#
#   bash scripts/test-semgrep-rules.sh
#
# Needs Docker. Uses the same pinned image as .github/workflows/ci.yml.
set -euo pipefail
cd "$(dirname "$0")/.."

SEMGREP_IMAGE=${SEMGREP_IMAGE:-semgrep/semgrep:1.183.0@sha256:2e45517a85e13a9cca14a2a00df6bb48affd66b8ebfae1b0991cd57578362fb0}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/backend/app/Ai" "$work/backend/app/Domain" "$work/backend/routes" "$work/frontend/src"

# One file per rule, with what it forbids. Each is expected to produce exactly the findings listed in EXPECTED.
cat > "$work/backend/app/Domain/RawSql.php" <<'PHP'
<?php
$a = DB::raw('count(*)');
$b = $query->whereRaw('id = '.$id);
$c = DB::select('SELECT * FROM users WHERE id = '.$id);
$d = DB::connection('pgsql')->statement($sql);
$ok1 = DB::select('SELECT 1 WHERE id = ?', [$id]);
$ok2 = DB::connection()->statement('SET search_path TO public');
PHP
cat > "$work/backend/app/Domain/Scope.php" <<'PHP'
<?php
$a = Workflow::query()->withoutGlobalScope(OrganizationScope::class)->get();
$b = Workflow::query()->withoutGlobalScopes()->get();
PHP
cat > "$work/backend/app/Domain/Dangerous.php" <<'PHP'
<?php
eval($code);
exec($command);
shell_exec($command);
system($command);
$p = proc_open($command, [], $pipes);
$u = unserialize($payload);
Process::run($command);
PHP
cat > "$work/backend/app/Domain/Tls.php" <<'PHP'
<?php
$a = Http::withoutVerifying()->get($url);
$b = Http::withOptions(['verify' => false])->get($url);
PHP
cat > "$work/backend/routes/api.php" <<'PHP'
<?php
Route::withoutMiddleware(Foo::class)->get('/x', fn () => null);
Route::get('/y', fn () => null)->withoutMiddleware('auth');
$middleware->validateCsrfTokens(except: ['/webhook']);
PHP
cat > "$work/backend/app/Ai/Tools.php" <<'PHP'
<?php
$body = ['model' => $model, 'tools' => [['type' => 'function']], 'input' => $input];
$other = ['model' => $model, 'tool_choice' => 'auto'];
PHP
cat > "$work/frontend/src/html.ts" <<'TS'
export function bad(el: HTMLElement, s: string) {
  el.innerHTML = s
  el.outerHTML = s
  el.insertAdjacentHTML('beforeend', s)
  document.write(s)
  eval(s)
  const f = new Function(s)
  localStorage.setItem('token', s)
  const t = window.sessionStorage
  return f
}
TS
cat > "$work/frontend/src/Html.tsx" <<'TSX'
export const Html = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: html }} />
TSX
# Clean code: nothing fires.
cat > "$work/backend/app/Domain/Clean.php" <<'PHP'
<?php
// Across organizations on purpose, for the probe of the comment form.
// nosemgrep: secureflow.php.without-global-scope
$a = Workflow::query()->withoutGlobalScope(OrganizationScope::class)->get();
$b = Workflow::query()->where('status', $status)->update(['status' => $next]);
$c = DB::select('SELECT 1 WHERE id = ?', [$id]);
$d = $request->user()->update(['name' => $name]);
PHP
cat > "$work/frontend/src/clean.tsx" <<'TSX'
export const Text = ({ text }: { text: string }) => <p>{text}</p>
TSX

docker run --rm -v "$work:/probe:ro" -v "$PWD/.semgrep:/rules:ro" -w /probe "$SEMGREP_IMAGE" \
  semgrep scan --config /rules/secureflow.yml --metrics=off --json --quiet backend frontend > "$work/out.json" 2>/dev/null || true

python3 - "$work/out.json" <<'PY'
import collections
import json
import sys

results = json.load(open(sys.argv[1]))["results"]
found = collections.Counter((r["path"], r["check_id"].split(".secureflow.")[-1]) for r in results)

expected = {
    ("backend/app/Domain/RawSql.php", "php.raw-sql"): 4,
    ("backend/app/Domain/Scope.php", "php.without-global-scope"): 2,
    ("backend/app/Domain/Dangerous.php", "php.dangerous-call"): 7,
    ("backend/app/Domain/Tls.php", "php.tls-verification-off"): 2,
    ("backend/routes/api.php", "php.middleware-bypass"): 3,
    ("backend/app/Ai/Tools.php", "php.ai-tools-parameter"): 2,
    ("frontend/src/html.ts", "ts.html-rendering"): 8,
    ("frontend/src/Html.tsx", "ts.dangerously-set-inner-html"): 1,
}

failed = False
for key, count in expected.items():
    actual = found.pop(key, 0)
    status = "ok " if actual == count else "BAD"
    failed = failed or actual != count
    print(f"{status} {key[1]:35s} {key[0]:40s} expected {count} found {actual}")
for key, count in found.items():
    failed = True
    print(f"BAD unexpected finding {key[1]} in {key[0]} ({count})")
print("semgrep rule probes:", "FAILED" if failed else "all rules fire, clean code is clean")
sys.exit(1 if failed else 0)
PY
