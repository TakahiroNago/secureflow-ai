#!/usr/bin/env python3
"""Writes plan-hash-vectors.json with an implementation independent of PHP (docs/security-design.md §9.2).

If PlanHasher and this disagree, one of them does not follow the specification. Run with python3 -I from
anywhere; the output does not depend on the machine.
"""
import hashlib
import json
import os
import unicodedata

ORG = '0193a000-0000-7000-8000-000000000001'
WORKFLOW = '0193a000-0000-7000-8000-000000000002'
TASK_KEYS = ['position', 'title', 'description', 'action_type', 'steps', 'priority', 'target_data', 'impact_summary', 'permissions', 'policy_decision']


def task(position, **overrides):
    return {
        'position': position,
        'title': 'Title',
        'description': 'Description',
        'action_type': 'report.draft',
        'steps': ['one', 'two'],
        'priority': 'medium',
        'target_data': 'Target',
        'impact_summary': 'Impact',
        'permissions': ['ai.text.read', 'report.draft.write'],
        'policy_decision': 'allowed',
        **overrides,
    }


def plan(*tasks, revision_no=1, organization_id=ORG):
    return {
        'hash_version': 1,
        'organization_id': organization_id,
        'workflow_id': WORKFLOW,
        'revision_no': revision_no,
        'policy_version': '2026.11.1',
        'tasks': list(tasks),
    }


def text(value):
    return unicodedata.normalize('NFC', value.replace('\r\n', '\n').replace('\r', '\n'))


def normalize(raw):
    tasks = []
    for item in sorted(raw['tasks'], key=lambda t: t['position']):
        entry = {key: text(item[key]) for key in TASK_KEYS if isinstance(item[key], str)}
        entry['position'] = item['position']
        entry['steps'] = [text(step) for step in item['steps']]
        entry['permissions'] = sorted(text(permission) for permission in item['permissions'])
        tasks.append(entry)
    return {**raw, 'organization_id': raw['organization_id'].lower(), 'policy_version': text(raw['policy_version']), 'tasks': tasks}


CASES = {
    'one task': plan(task(1)),
    'no tasks': plan(),
    'empty steps and permissions': plan(task(1, steps=[], permissions=[])),
    'a later revision of the same content': plan(task(1), revision_no=2),
    'tasks out of order': plan(task(2, title='Second'), task(1, title='First')),
    'permissions out of order, steps kept in order': plan(task(1, permissions=['z.write', 'a.read', 'M.read'], steps=['z', 'a'])),
    'decomposed characters become NFC': plan(task(1, title='é ガ')),
    'line endings become LF': plan(task(1, description='a\r\nb\rc\nd')),
    'nothing is trimmed': plan(task(1, title='  spaced  ', description='\n')),
    'quotes, slashes and control characters': plan(task(1, title='"a"/\\b', description='\t\b\f\u0001\u001f\u007f')),
    'unicode is not escaped': plan(task(1, title='日本語 \U0001F600', description='line para end')),
    'uppercase ids become lowercase': plan(task(1), organization_id=ORG.upper()),
    'forbidden action': plan(task(1, action_type='shell.exec', permissions=['system.shell'], policy_decision='forbidden')),
}

vectors = []
for name, raw in CASES.items():
    canonical = json.dumps(normalize(raw), ensure_ascii=False, separators=(',', ':'), sort_keys=True)
    digest = hashlib.sha256(b'secureflow.plan.v1\n' + canonical.encode('utf-8')).hexdigest()
    vectors.append({'name': name, 'plan': raw, 'canonical': canonical, 'hash': digest})

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plan-hash-vectors.json')
with open(path, 'w', encoding='ascii', newline='\n') as out:
    json.dump(vectors, out, ensure_ascii=True, indent=1)
    out.write('\n')
print(f'{len(vectors)} vectors')
