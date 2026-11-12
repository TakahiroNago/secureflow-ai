#!/usr/bin/env python3
"""SecureFlow AI — infra/aws/metric-filters.json against the code that writes the lines (docs/test-strategy.md §37, INFRA-01).

Reads only. The CloudWatch filters select on fields of the JSON lines the application writes; this keeps the sample
lines, the patterns and the code in agreement, so that a rename in the code fails CI before it silences an alarm.
The patterns themselves are parsed by CloudWatch alone: infra/aws/test-metric-filters.sh asks it (the operator,
with credentials). scripts/test-prod-stack.sh PROD-08 checks the running application writes the gauge in this shape.
"""
import json
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parent.parent
spec = json.loads((root / 'infra/aws/metric-filters.json').read_text(encoding='utf-8'))
fails = []

samples = spec['samples']
records = {}
for name, line in samples.items():
    try:
        records[name] = json.loads(line)
    except ValueError:
        continue  # the lines of php-fpm and nginx are there to be matched by nothing
for name, record in records.items():
    for key in ('message', 'context', 'level', 'level_name', 'channel', 'datetime', 'extra'):
        if key not in record:
            fails.append(f'sample {name}: no {key} (Monolog JsonFormatter writes it)')
if len(records) == len(samples):
    fails.append('no non-JSON sample: the filters must be seen to ignore the lines of php-fpm and nginx')

for name, f in spec['filters'].items():
    if not f['matches']:
        fails.append(f'filter {name}: matches nothing')
    for s in f['matches']:
        if s not in samples:
            fails.append(f'filter {name}: unknown sample {s}')
        elif s not in records:
            fails.append(f'filter {name}: {s} is not a JSON line')
    for field in re.findall(r'\$\.([A-Za-z_.]+)', f['pattern']):
        if not any(field.split('.')[0] in r for r in records.values()):
            fails.append(f'filter {name}: no sample has the field {field}')

app = root / 'backend/app'
source = '\n'.join(p.read_text(encoding='utf-8') for p in sorted(app.rglob('*.php')))

# The gauge: the fields AuditHousekeepingCommand writes are the sample's.
gauge = (app / 'Console/Commands/AuditHousekeepingCommand.php').read_text(encoding='utf-8')
block = re.search(r"Log::info\('audit\.unavailable', \[(.*?)\]\);", gauge, re.S)
written = set(re.findall(r"'([a-z_]+)' =>", block[1])) if block else set()
if written != set(records['gauge_ok']['context']):
    fails.append(f"gauge_ok: the code writes {sorted(written)}, the sample has {sorted(records['gauge_ok']['context'])}")

# Every metric named outright in a pattern is still a string in the code, and the suffixes the regexes expect exist.
named = set()
for f in spec['filters'].values():
    named |= set(re.findall(r'\$\.context\.metric = "([^"]+)"', f['pattern']))
literals = set(re.findall(r"'([a-z_.]+)'", source))
for metric in sorted(named):
    if metric not in literals:
        fails.append(f'the code no longer writes the metric {metric}')
if "'.outage_started'" not in source:
    fails.append('OutageLog no longer emits <subject>.outage_started')
if "SCOPE_DB_SUSPECTED = 'db_suspected'" not in source:
    fails.append('the storage scope db_suspected changed name')
if not re.search(r"'[a-z_]+_unrecorded'", source) or not re.search(r"'[a-z.]+_not_recorded'", source):
    fails.append('no *_unrecorded or *_not_recorded outcome in the code any more')

for line in fails:
    print('  [FAIL]', line)
print(f"{len(spec['filters'])} filters, {len(samples)} samples, {len(fails)} failures")
sys.exit(1 if fails else 0)
