#!/usr/bin/env bash
# SecureFlow AI — every tuning variable in docs/architecture.md §11 must reach the containers, with the
# default that backend/config uses. A variable missing from compose.yaml is silently ignored otherwise.
# Reads configuration only: nothing is started, and .env is not used.
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sed -e 's/^APP_KEY=.*/APP_KEY=base64:dummy/' .env.example > "$work/env"

WORK=$work python3 - <<'PY'
import json, os, re, subprocess, sys

PATTERN = re.compile(r'`((?:AUDIT|PASSWORD|LOG_AGGREGATION)_[A-Z_]+|DB_(?:UNAVAILABLE|CONNECT|STATEMENT|LOCK|IDLE|KEEPALIVES|TCP)_[A-Z_]+'
                     r'|REDIS_(?:TIMEOUT|READ_TIMEOUT|MAX_RETRIES)|AI_(?:TIMEOUT|MAX)_[A-Z_]+|SESSION_(?:IDLE|ABSOLUTE)_[A-Z_]+)`')
SERVICES = ('app', 'worker', 'scheduler')

names = sorted({m for line in open('docs/architecture.md', encoding='utf-8') if line.startswith('|') for m in PATTERN.findall(line)})
if len(names) < 20:
    sys.exit(f'[FAIL] found only {len(names)} variables in docs/architecture.md: the pattern no longer matches the table')

config = ''
for path in ('audit', 'database', 'session', 'ai'):
    config += open(f'backend/config/{path}.php', encoding='utf-8').read()


def rendered(extra):
    env = {k: v for k, v in os.environ.items() if k not in names}
    env.update(extra)
    out = subprocess.run(['docker', 'compose', '--env-file', f"{os.environ['WORK']}/env", '-f', 'compose.yaml', 'config', '--format', 'json'],
                         capture_output=True, text=True, env=env, check=True).stdout
    return json.loads(out)['services']


fails = []
sentinels = {name: str(70000 + i) for i, name in enumerate(names)}
plain, marked = rendered({}), rendered(sentinels)
for name in names:
    match = re.search(r"env\('" + name + r"',\s*'?(\d+)'?\)", config)
    if match is None:
        fails.append(f'{name}: no numeric default in backend/config')
        continue
    for service in SERVICES:
        got = plain[service]['environment'].get(name)
        if got != match[1]:
            fails.append(f'{name}: {service} default is {got!r}, backend/config says {match[1]!r}')
        if marked[service]['environment'].get(name) != sentinels[name]:
            fails.append(f'{name}: a value set in the environment does not reach {service}')

# docs/architecture.md §10: AI calls < the job's limit = the worker's limit < retry_after.
job = open('backend/app/Jobs/AnalyzeWorkflowJob.php', encoding='utf-8').read()
queue = open('backend/config/queue.php', encoding='utf-8').read()
job_limit = int(re.search(r'public int \$timeout = (\d+);', job)[1])
retry_after = int(re.search(r"'database' => \[.*?'retry_after' => (\d+),", queue, re.S)[1])
worker = plain['worker']['command']
worker_limit = next((int(arg.split('=')[1]) for arg in worker if arg.startswith('--timeout=')), None)
if worker_limit != job_limit:
    fails.append(f'worker --timeout is {worker_limit}, the job says {job_limit}')
if not job_limit < retry_after:
    fails.append(f'retry_after {retry_after} must be above the job limit {job_limit}')
if worker[2:4] != ['queue:work', 'database']:
    fails.append(f'the worker must use the database queue: {worker[2:4]}')

for line in fails:
    print('  [FAIL]', line)
print(f'{len(names)} variables, {len(SERVICES)} services, {len(fails)} failures')
sys.exit(1 if fails else 0)
PY
