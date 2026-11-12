#!/usr/bin/env bash
# SecureFlow AI — every tuning variable in docs/architecture.md §11 must reach the containers, with the
# default that backend/config uses. A variable missing from compose.yaml is silently ignored otherwise.
# compose.prod.yaml (the public environment) is held to the same table, so the two files cannot drift apart.
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


# What compose.prod.yaml needs besides .env.example (the images by digest, the public host, the load balancer's range).
PROD_EXTRA = {'SECUREFLOW_PHP_IMAGE': 'php@sha256:0', 'SECUREFLOW_WEB_IMAGE': 'web@sha256:0',
              'APP_URL': 'https://secureflow.example', 'PUBLIC_HOST': 'secureflow.example', 'TRUSTED_PROXY_CIDR': '10.0.0.0/16'}


def rendered(extra, compose_file='compose.yaml'):
    env = {k: v for k, v in os.environ.items() if k not in names}
    if compose_file == 'compose.prod.yaml':
        env.update(PROD_EXTRA)
    env.update(extra)
    out = subprocess.run(['docker', 'compose', '--env-file', f"{os.environ['WORK']}/env", '-f', compose_file, 'config', '--format', 'json'],
                         capture_output=True, text=True, env=env, check=True).stdout
    return json.loads(out)['services']


fails = []
sentinels = {name: str(70000 + i) for i, name in enumerate(names)}
job = open('backend/app/Jobs/AnalyzeWorkflowJob.php', encoding='utf-8').read()
queue = open('backend/config/queue.php', encoding='utf-8').read()
job_limit = int(re.search(r'public int \$timeout = (\d+);', job)[1])
retry_after = int(re.search(r"'database' => \[.*?'retry_after' => (\d+),", queue, re.S)[1])
if not job_limit < retry_after:
    fails.append(f'retry_after {retry_after} must be above the job limit {job_limit}')

for compose_file in ('compose.yaml', 'compose.prod.yaml'):
    plain, marked = rendered({}, compose_file), rendered(sentinels, compose_file)
    for name in names:
        match = re.search(r"env\('" + name + r"',\s*'?(\d+)'?\)", config)
        if match is None:
            if compose_file == 'compose.yaml':
                fails.append(f'{name}: no numeric default in backend/config')
            continue
        for service in SERVICES:
            got = plain[service]['environment'].get(name)
            if got != match[1]:
                fails.append(f'{compose_file}: {name}: {service} default is {got!r}, backend/config says {match[1]!r}')
            if marked[service]['environment'].get(name) != sentinels[name]:
                fails.append(f'{compose_file}: {name}: a value set in the environment does not reach {service}')

    # docs/architecture.md §10: AI calls < the job's limit = the worker's limit < retry_after.
    worker = plain['worker']['command']
    worker_limit = next((int(arg.split('=')[1]) for arg in worker if arg.startswith('--timeout=')), None)
    if worker_limit != job_limit:
        fails.append(f'{compose_file}: worker --timeout is {worker_limit}, the job says {job_limit}')
    if worker[2:4] != ['queue:work', 'database']:
        fails.append(f'{compose_file}: the worker must use the database queue: {worker[2:4]}')
    # Whatever .env says, the migrations never get the real provider or its key.
    migrate = rendered({'COMPOSE_PROFILES': 'tools', 'AI_PROVIDER': 'openai', 'OPENAI_API_KEY': 'a-key', 'OPENAI_MODEL': 'gpt-6-luna'}, compose_file)['migrate']['environment']
    if migrate.get('AI_PROVIDER') != 'mock' or migrate.get('OPENAI_API_KEY'):
        fails.append(f'{compose_file}: migrate must have the mock and no key, whatever .env says')

# The public environment (docs/architecture.md §4.3): the same application variables, a few fixed values, no dev service.
prod = rendered({'APP_DEBUG': 'true'}, 'compose.prod.yaml')
dev_keys = set(rendered({})['app']['environment'])
# The one addition of the public environment: JSON log lines for the CloudWatch filters (infra/aws/metric-filters.json).
PROD_ONLY = {'LOG_STDERR_FORMATTER': 'Monolog\\Formatter\\JsonFormatter'}
if set(prod['app']['environment']) - set(PROD_ONLY) != dev_keys:
    fails.append(f"compose.prod.yaml: app's variables differ from compose.yaml's: {sorted((set(prod['app']['environment']) - set(PROD_ONLY)) ^ dev_keys)}")
for name, value in PROD_ONLY.items():
    for service in SERVICES:
        if prod[service]['environment'].get(name) != value:
            fails.append(f'compose.prod.yaml: {name} of {service} must be {value!r} whatever .env says')
    if name in dev_keys:
        fails.append(f'compose.yaml: {name} is for the public environment only (the development logs stay readable)')
if prod['app']['environment'].get('APP_DEBUG') != 'false':
    fails.append('compose.prod.yaml: APP_DEBUG must be false whatever .env says')
if prod['app']['environment'].get('SANCTUM_STATEFUL_DOMAINS') != PROD_EXTRA['PUBLIC_HOST']:
    fails.append('compose.prod.yaml: SANCTUM_STATEFUL_DOMAINS must be PUBLIC_HOST alone')
if set(prod) & {'frontend', 'test'}:
    fails.append('compose.prod.yaml: no frontend and no test service')

plain = rendered({})

# docs/security-design.md §6.1: the relay exists only when asked for, and the worker has no way out of its own.
if 'ai-egress' in plain:
    fails.append('the relay must not start unless COMPOSE_PROFILES=openai')
with_relay = rendered({'COMPOSE_PROFILES': 'openai'})
relay = with_relay.get('ai-egress')
if relay is None:
    fails.append('COMPOSE_PROFILES=openai must start the relay')
else:
    if set(relay['networks']) != {'data', 'ai-egress'} or relay['networks']['data'].get('aliases') != ['api.openai.com']:
        fails.append(f"the relay must be api.openai.com on data, and on ai-egress: {relay['networks']}")
    if relay.get('ports'):
        fails.append('the relay must publish no port')
    if relay.get('environment'):
        fails.append('the relay must have no environment: no key, and no password')
    if relay.get('read_only') is not True or relay.get('cap_drop') != ['ALL']:
        fails.append('the relay must be read-only, with no capabilities')
for name, service in with_relay.items():
    if name != 'ai-egress' and 'ai-egress' in (service.get('networks') or {}):
        fails.append(f'{name} must not be on the ai-egress network')
if set(with_relay['worker']['networks']) != {'data'}:
    fails.append(f"the worker must stay on data only: {with_relay['worker']['networks']}")
# Whatever .env says, the tests never get the real provider or its key (the migrations: above, for both files).
tools = rendered({'COMPOSE_PROFILES': 'tools', 'AI_PROVIDER': 'openai', 'OPENAI_API_KEY': 'a-key', 'OPENAI_MODEL': 'gpt-6-luna'})
environment = tools['test']['environment']
if environment.get('AI_PROVIDER') != 'mock' or environment.get('OPENAI_API_KEY'):
    fails.append('test must have the mock and no key, whatever .env says')
conf = subprocess.run(['docker', 'run', '--rm', '-v', os.getcwd() + '/docker/ai-egress/nginx.conf:/etc/nginx/nginx.conf:ro', relay['image'] if relay else 'nginx', 'nginx', '-t'],
                      capture_output=True, text=True)
if conf.returncode != 0:
    fails.append('docker/ai-egress/nginx.conf does not load: ' + conf.stderr[-200:])

for line in fails:
    print('  [FAIL]', line)
print(f'{len(names)} variables, {len(SERVICES)} services, {len(fails)} failures')
sys.exit(1 if fails else 0)
PY
