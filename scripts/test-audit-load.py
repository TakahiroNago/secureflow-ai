#!/usr/bin/env python3
"""SecureFlow AI — AUDIT-LOAD-01 (docs/test-strategy.md §17). Measures; it decides nothing and is not part of CI.

It creates thousands of users, changes PostgreSQL settings, recreates containers and freezes services, so it
needs a freshly migrated and seeded throwaway stack, and refuses to run unless the caller names that project:

    SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> python3 scripts/test-audit-load.py load
    SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> python3 scripts/test-audit-load.py failures [scenario...]

"load" must run first: it creates the users. Results go to $AUDIT_LOAD_RESULTS (default ~/tmp/secureflow-load-results).
"""
import hashlib, http.client, json, os, random, re, subprocess, sys, threading, time, urllib.parse, uuid
from datetime import datetime, timezone

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

ENV = {}
for line in open('.env'):
    m = re.match(r'^(COMPOSE_PROJECT_NAME|DB_DATABASE|DB_USERNAME|DB_PASSWORD|REDIS_PASSWORD|NGINX_PORT|FRONTEND_PORT)=(.*)$', line.strip())
    if m:
        ENV[m[1]] = m[2].strip('"\'')
PROJECT = ENV.get('COMPOSE_PROJECT_NAME', 'secureflow')
if PROJECT == 'secureflow' or os.environ.get('SECUREFLOW_ALLOW_FAILURE_INJECTION') != PROJECT:
    sys.exit('Refusing to run: name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION.')

HOST, PORT, VITE = 'localhost', int(ENV['NGINX_PORT']), int(ENV['FRONTEND_PORT'])
DB = ENV['DB_DATABASE']
PASSWORD = 'load test passphrase 9431 q'
OUT = os.environ.get('AUDIT_LOAD_RESULTS', os.path.expanduser('~/tmp/secureflow-load-results'))
SEED_SECONDS = int(os.environ.get('AUDIT_LOAD_SEED_SECONDS', 420))
os.makedirs(OUT, exist_ok=True)
RESULTS = {'project': PROJECT, 'started': datetime.now(timezone.utc).isoformat()}
RESULT_FILE = None


def save():
    with open(RESULT_FILE, 'w') as f:
        json.dump(RESULTS, f, indent=1, ensure_ascii=False)


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def compose(*args, input=None, env=None, check=True, timeout=300):
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run(['docker', 'compose', *args], input=input, capture_output=True, text=True, env=e, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f'compose {args[:3]} failed: {r.stderr[-800:]}')
    return r.stdout


def sql(q):
    return compose('exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', DB, '--no-psqlrc', '-tAc', q).strip()


def effective_config():
    php = ('chdir("/var/www/html"); require "vendor/autoload.php"; $a=require "bootstrap/app.php";'
           '$a->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap();'
           'echo config("audit.login_ip_limit_per_minute"),"|",config("audit.system_chain_limit_per_minute");')
    return compose('exec', '-T', 'app', 'php', '-r', php).strip().splitlines()[-1]


def wait_ready(seconds=120):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            c = http.client.HTTPConnection(HOST, PORT, timeout=5)
            c.request('GET', '/api/health/ready')
            if c.getresponse().status == 200:
                return True
        except OSError:
            pass
        time.sleep(2)
    return False


def flush_redis():
    compose('exec', '-T', '-e', f"REDISCLI_AUTH={ENV['REDIS_PASSWORD']}", 'redis', 'redis-cli', 'FLUSHALL')


def apply_limits(ip, system):
    e = {'AUDIT_LOGIN_IP_LIMIT_PER_MINUTE': str(ip), 'AUDIT_SYSTEM_CHAIN_LIMIT_PER_MINUTE': str(system)}
    compose('up', '-d', '--no-deps', '--force-recreate', '--wait', 'app', env=e)
    compose('restart', 'nginx', env=e)
    if not wait_ready():
        raise RuntimeError('app not ready')
    flush_redis()
    got = effective_config()
    if got != f'{ip}|{system}':
        raise RuntimeError(f'limits did not reach the app: {got}')
    log('limits', got)
    return got


class Client:
    def __init__(self, port=PORT, timeout=70):
        self.port, self.cookies, self.conn, self.timeout = port, {}, None, timeout

    def req(self, method, path, body=None):
        base = f'http://{HOST}:{self.port}'
        h = {'Accept': 'application/json', 'Origin': base, 'Referer': base + '/'}
        if self.cookies:
            h['Cookie'] = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
        if 'XSRF-TOKEN' in self.cookies:
            h['X-XSRF-TOKEN'] = urllib.parse.unquote(self.cookies['XSRF-TOKEN'])
        if body is not None:
            body = json.dumps(body)
            h['Content-Type'] = 'application/json'
        if self.conn is None:
            self.conn = http.client.HTTPConnection(HOST, self.port, timeout=self.timeout)
        t = time.perf_counter()
        try:
            self.conn.request(method, path, body, h)
            r = self.conn.getresponse()
            data = r.read()
        except Exception:
            self.conn.close()
            self.conn = None
            raise
        dt = time.perf_counter() - t
        for k, v in r.getheaders():
            if k.lower() == 'set-cookie':
                name, val = v.split(';', 1)[0].split('=', 1)
                self.cookies[name] = val
        return r.status, data, dt


def percentiles(lat):
    l = sorted(lat)
    q = lambda p: round(l[min(len(l) - 1, int(len(l) * p))] * 1000) if l else None
    return {'p50_ms': q(.5), 'p95_ms': q(.95), 'p99_ms': q(.99), 'max_ms': round(l[-1] * 1000) if l else None}


class Stream:
    def __init__(self, mode, n):
        self.mode, self.n = mode, n
        self.events, self.bodies, self.lock = [], {}, threading.Lock()

    def add(self, started, st, dt, data=b''):
        with self.lock:
            self.events.append((started, st, dt))
            if st == 401:
                b = hashlib.sha256(re.sub(rb'"trace_id":"[^"]+"', b'', data)).hexdigest()[:8]
                self.bodies[b] = self.bodies.get(b, 0) + 1

    def summary(self, secs):
        status = {}
        for _, st, _ in self.events:
            status[str(st)] = status.get(str(st), 0) + 1
        return {'mode': self.mode, 'clients': self.n, 'requests': len(self.events), 'rps': round(len(self.events) / secs, 2), 'status': status,
                **percentiles([e[2] for e in self.events]), 'body_variants_401': self.bodies}


def worker(stream, stop, pool, legit):
    c = Client()
    while time.time() < stop():
        started = time.time()
        try:
            if 'XSRF-TOKEN' not in c.cookies:
                st, _, dt = c.req('GET', '/sanctum/csrf-cookie')
                if st != 204 and st != 200:
                    stream.add(started, f'csrf_{st}', dt)
                    c.cookies.clear()
                    time.sleep(.2)
                    continue
                started = time.time()
            if stream.mode == 'unknown':
                email, pw = f'{uuid.uuid4().hex}@unknown.example', 'wrong password value'
            elif stream.mode == 'known_wrong':
                email, pw = random.choice(pool), 'wrong password value'
            else:
                email = legit.pop() if legit else None
                if email is None:
                    return
                pw = PASSWORD
            st, data, dt = c.req('POST', '/api/v1/auth/login', {'email': email, 'password': pw})
            stream.add(started, st, dt, data)
            if st in (419, 200):
                c.cookies.clear()
        except TimeoutError:
            stream.add(started, 'client_timeout', time.time() - started)
        except Exception as e:
            stream.add(started, type(e).__name__, time.time() - started)
            time.sleep(.1)


def stats_sample():
    r = subprocess.run(['docker', 'stats', '--no-stream', '--format', '{{.Name}} {{.CPUPerc}} {{.MemUsage}}'], capture_output=True, text=True)
    return [l for l in r.stdout.splitlines() if l.startswith(f'{PROJECT}-') and re.search(r'-(app|postgres|redis)-', l)]


def logs_since(service, since):
    return compose('logs', '--no-color', '--no-log-prefix', '--since', since, service, timeout=120)


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def pg_findings(since):
    t = logs_since('postgres', since)
    durs = sorted(((float(m[1]), m[2][:70]) for m in re.finditer(r'duration: ([\d.]+) ms\s+(?:statement|execute [^:]*): (.*)', t)), reverse=True)
    return {'lock_timeout_55P03': t.count('lock timeout'), 'statement_timeout_57014': t.count('statement timeout'), 'deadlocks': t.count('deadlock detected'),
            'still_waiting': t.count('still waiting for'), 'slow_statements': len(durs), 'slowest_ms': round(durs[0][0]) if durs else None}


def app_findings(since):
    t = logs_since('app', since)
    metrics = {}
    for m in re.findall(r'audit\.[a-z_.]+', t):
        metrics[m] = metrics.get(m, 0) + 1
    return {'metrics': metrics, 'max_children_reached': t.count('max_children'), 'redis_exception_lines': t.count('RedisException'),
            'log_bytes': len(t.encode()), 'log_lines': t.count('\n')}


def chains():
    return dict(l.split('|') for l in sql("select case when organization_id is null then 'system' else 'org' end, count(*) from audit_logs group by 1").splitlines())


def run(name, spec, secs, pool=None, legit=None):
    log('run', name, spec, secs)
    since, before = now_iso(), chains()
    legit = list(legit) if legit else None
    streams, threads = [], []
    stop_at = time.time() + secs
    t0 = time.time()
    for mode, n in spec:
        s = Stream(mode, n)
        streams.append(s)
        for _ in range(n):
            th = threading.Thread(target=worker, args=(s, lambda: stop_at, pool, legit), daemon=True)
            th.start()
            threads.append(th)
    time.sleep(min(secs / 2, 10))
    sample = stats_sample()
    for th in threads:
        th.join()
    elapsed = time.time() - t0
    after = chains()
    res = {'seconds': round(elapsed, 1), 'streams': [s.summary(elapsed) for s in streams],
           'audit_delta': {k: int(after.get(k, 0)) - int(before.get(k, 0)) for k in set(after) | set(before)},
           'postgres': pg_findings(since), 'app': app_findings(since), 'docker_stats': sample}
    RESULTS.setdefault('http', {})[name] = res
    save()
    log(' ', json.dumps(res['streams'], ensure_ascii=False))
    return res


def pgbench(sample, clients, secs, org=None):
    target = f"'{org}'::uuid" if org else 'NULL::uuid'
    script = ("SELECT audit_append(gen_random_uuid(), %s, 'anonymous', NULL::uuid, '%s', NULL::text, NULL::uuid, 'failure', '%s', '172.18.0.1'::inet, gen_random_uuid(), '{\"reason_code\":\"UNKNOWN_ACCOUNT\"}'::jsonb);\n"
              % (target, sample['event_type'], sample['severity']))
    out = compose('exec', '-T', '-e', f"PGPASSWORD={ENV['DB_PASSWORD']}", 'postgres', 'pgbench', '-n', '-h', '127.0.0.1', '-U', ENV['DB_USERNAME'],
                  '-d', DB, '-c', str(clients), '-j', str(clients), '-f', '-', '-T', str(secs), input=script, check=False, timeout=1500)
    get = lambda p: (lambda m: float(m[1]) if m else None)(re.search(p, out))
    return {'clients': clients, 'tps': get(r'tps = ([\d.]+)'), 'latency_avg_ms': get(r'latency average = ([\d.]+) ms'),
            'processed': get(r'actually processed: (\d+)'), 'failed': get(r'failed transactions: (\d+)')}


def verify():
    t = time.time()
    r = subprocess.run(['docker', 'compose', 'exec', '-T', 'app', 'sh', '-c', 'php artisan audit:verify --all; echo EXIT=$?'], capture_output=True, text=True, timeout=1500)
    return {'seconds': round(time.time() - t, 1), 'tail': r.stdout[-300:]}


def load():
    log('does a value in the environment reach the app?')
    RESULTS['env_passthrough'] = {'set': '31|601', 'effective': apply_limits(31, 601)}
    save()

    log('users and logging')
    compose('exec', '-T', 'app', 'php', 'artisan', 'user:create', '--organization=Default Organization', '--name=template',
            '--email=template@load.example', '--role=member', input=f'{PASSWORD}\n{PASSWORD}\n')
    cols = sql("select string_agg(column_name, ',' order by ordinal_position) from information_schema.columns where table_schema='public' and table_name='users'").split(',')
    sel = [{'id': 'gen_random_uuid()', 'name': 'p||i', 'email': "p||i||'@load.example'"}.get(c, c) for c in cols]
    for prefix, n in (('legit', 400), ('wrong', 3000)):
        sql(f"insert into users ({','.join(cols)}) select {','.join(sel)} from users, (select '{prefix}' p, generate_series(1,{n}) i) g where email='template@load.example'")
    pool = [f'wrong{i}@load.example' for i in range(1, 3001)]
    legit = [f'legit{i}@load.example' for i in range(1, 401)]
    sql('alter system set log_min_duration_statement = 20')
    sql('alter system set log_lock_waits = on')
    sql('select pg_reload_conf()')

    log('where requests come from (real limits)')
    apply_limits(30, 600)
    source = {}
    for label, port in (('published_port_nginx', PORT), ('vite_proxy', VITE)):
        c = Client(port)
        c.req('GET', '/sanctum/csrf-cookie')
        st, _, _ = c.req('POST', '/api/v1/auth/login', {'email': f'{label}@unknown.example', 'password': 'wrong password value'})
        source[label] = {'status': st, 'ip_address': sql('select host(ip_address) from audit_logs order by id desc limit 1')}
    RESULTS['source'] = source
    save()
    log(source)
    row = sql("select event_type||'|'||severity from audit_logs where organization_id is null and actor_type='anonymous' order by id desc limit 1").split('|')
    sample = {'event_type': row[0], 'severity': row[1]}

    log('normal logins from one address at the real limit')
    flush_redis()
    run('login_burst_real_limit_60users_c10', [('legit', 10)], 45, legit=legit[:60])
    flush_redis()
    c, ok, t0 = Client(), {}, time.time()
    for i in range(25):
        c.cookies.clear()
        c.req('GET', '/sanctum/csrf-cookie')
        st, _, _ = c.req('POST', '/api/v1/auth/login', {'email': legit[100 + i], 'password': PASSWORD})
        ok[str(st)] = ok.get(str(st), 0) + 1
        time.sleep(max(0, t0 + (i + 1) * 2.4 - time.time()))
    RESULTS['login_paced_25_per_minute'] = ok
    save()

    log('system chain throughput, without the caps')
    apply_limits(10_000_000, 1_000_000_000)
    run('warmup', [('unknown', 2)], 5)
    for n in (1, 5, 10, 20, 40):
        run(f'system_chain_c{n}', [('unknown', n)], 30)

    log('same organization, and chain separation over HTTP')
    run('org_baseline_c2', [('known_wrong', 2)], 30, pool=pool)
    flush_redis()
    run('org_c2_plus_system_c8', [('known_wrong', 2), ('unknown', 8)], 30, pool=pool)
    flush_redis()
    run('org_c10_same_load', [('known_wrong', 10)], 30, pool=pool)
    for n in (5, 10, 20, 40):
        flush_redis()
        run(f'org_failures_c{n}_with_legit_c2', [('known_wrong', n), ('legit', 2)], 30, pool=pool, legit=legit[130:400])

    log('the database alone, without Argon2id or php-fpm')
    org = sql('select id from organizations limit 1')
    db = {'system': [pgbench(sample, n, 15) for n in (1, 4, 8, 16, 32)], 'org_alone_c1': pgbench(sample, 1, 15, org=org)}
    box = {}
    th = threading.Thread(target=lambda: box.update(s=pgbench(sample, 16, 15)))
    th.start()
    time.sleep(1)
    db['org_c1_while_system_c16'] = pgbench(sample, 1, 12, org=org)
    th.join()
    db['system_c16_during_that'] = box['s']
    RESULTS['db_only'] = db
    save()
    log(db)

    log('over the real cap')
    apply_limits(10_000_000, 600)
    time.sleep(61 - time.time() % 60)  # start on a window boundary
    t_start = sql('select now()')
    res = run('over_cap_two_windows', [('unknown', 20)], 118)
    time.sleep(130)  # the scheduler records ended windows
    sent = res['streams'][0]['status'].get('401', 0)
    recorded = int(sql(f"select count(*) from audit_logs where actor_type='anonymous' and organization_id is null and occurred_at >= '{t_start}'"))
    rows = sql(f"select coalesce(string_agg(metadata->>'suppressed_count', ','), '') from audit_logs where event_type='audit.events_suppressed' and occurred_at >= '{t_start}'")
    total = sum(int(x) for x in rows.split(',') if x)
    RESULTS['over_cap'] = {'responses_401': sent, 'recorded_rows': recorded, 'suppressed_events': rows, 'suppressed_total': total,
                           'difference': recorded + total - sent, 'body_variants': res['streams'][0]['body_variants_401']}
    save()
    log(RESULTS['over_cap'])

    log('growth and audit:verify')
    size = lambda: {'rows': int(sql('select count(*) from audit_logs')), 'table_total_bytes': int(sql("select pg_total_relation_size('audit_logs')"))}
    g = {'before': size(), 'verify_before': verify()}
    g['seed'] = pgbench(sample, 8, SEED_SECONDS)
    g['after'] = size()
    g['verify_after'] = verify()
    g['bytes_per_row'] = round((g['after']['table_total_bytes'] - g['before']['table_total_bytes']) / max(1, g['after']['rows'] - g['before']['rows']))
    RESULTS['growth'] = g
    save()
    log(g)


def health():
    return subprocess.run(['docker', 'inspect', '-f', '{{.State.Health.Status}}', f'{PROJECT}-app-1'], capture_output=True, text=True).stdout.strip()


def db_connections():
    # Established TCP connections from the app container to PostgreSQL (0x1538 = 5432).
    cmd = "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$3 ~ /:1538$/ && $4 == \"01\"' | wc -l"
    return int(compose('exec', '-T', 'app', 'sh', '-c', cmd).strip())


def bucket(events, a, b):
    chosen = [e for e in events if a <= e[0] < b]
    status = {}
    for _, st, _ in chosen:
        status[str(st)] = status.get(str(st), 0) + 1
    return {'requests': len(chosen), 'status': status, **percentiles([e[2] for e in chosen])}


def probe(path, every, sink, stop):
    while not stop.is_set():
        started = time.time()
        try:
            c = http.client.HTTPConnection(HOST, PORT, timeout=70)
            c.request('GET', path)
            st = c.getresponse().status
        except TimeoutError:
            st = 'client_timeout'
        except Exception as e:
            st = type(e).__name__
        sink.append((started, st, time.time() - started))
        stop.wait(max(0, every - (time.time() - started)))


def failure(name, inject, restore, clients, before, during, after):
    log('failure', name, 'clients', clients)
    if not wait_ready():
        raise RuntimeError('not ready before the failure')
    since = now_iso()
    stream = Stream('unknown', clients)
    stop_at = {'t': time.time() + before + during + after}
    threads = [threading.Thread(target=worker, args=(stream, lambda: stop_at['t'], None, None), daemon=True) for _ in range(clients)]
    live, ready, states, halt = [], [], [], threading.Event()
    probes = [threading.Thread(target=probe, args=('/api/health/live', 2, live, halt), daemon=True),
              threading.Thread(target=probe, args=('/api/health/ready', 4, ready, halt), daemon=True)]

    def watch():
        while not halt.wait(5):
            states.append((time.time(), health()))
    watcher = threading.Thread(target=watch, daemon=True)
    for t in threads + probes + [watcher]:
        t.start()
    time.sleep(before)
    try:
        inject()
        t_fault = time.time()
        log('  injected')
        time.sleep(during / 2)
        sample = stats_sample()
        connections = {'middle': db_connections()}
        time.sleep(during / 2)
        connections['end'] = db_connections()
    finally:
        restore()
    t_back = time.time()
    log('  restored')
    time.sleep(after)
    for t in threads:
        t.join()
    halt.set()
    for t in probes:
        t.join()
    end = time.time()

    def first_ok(events, ok):
        done = sorted(e[0] + e[2] for e in events if e[0] >= t_back and e[1] == ok)
        return round(done[0] - t_back, 1) if done else None

    def first_bad(events, limit):
        bad = sorted(e[0] for e in events if e[0] >= t_fault and e[0] < t_back and (e[1] != 200 or e[2] > limit))
        return round(bad[0] - t_fault, 1) if bad else None
    res = {'clients': clients, 'seconds': {'before': before, 'during': round(t_back - t_fault), 'after': after}, 'db_connections_from_app': connections,
           'load': {'before': bucket(stream.events, 0, t_fault), 'during': bucket(stream.events, t_fault, t_back), 'after': bucket(stream.events, t_back, end)},
           'seconds_to_first_401_after_restore': first_ok(stream.events, 401),
           'live': {'during': bucket(live, t_fault, t_back), 'after': bucket(live, t_back, end), 'first_failure_or_over_2s_after_fault': first_bad(live, 2)},
           'ready': {'during': bucket(ready, t_fault, t_back), 'after': bucket(ready, t_back, end), 'seconds_to_200_after_restore': first_ok(ready, 200)},
           'app_health_seen_during': sorted({s for t, s in states if t_fault <= t < t_back}), 'app_health_end': health(),
           'app': app_findings(since), 'postgres_state': pg_findings(since) if name.startswith('redis') else None, 'docker_stats_during': sample,
           'ready_within_120s': wait_ready()}
    RESULTS.setdefault('failures', {})[name] = res
    save()
    log(' ', json.dumps(res, ensure_ascii=False))


def failures():
    apply_limits(10_000_000, 1_000_000_000)
    stop_r, start_r = lambda: compose('stop', 'redis'), lambda: compose('up', '-d', '--wait', 'redis')
    pause = lambda s: (lambda: compose('pause', s))
    unpause = lambda s: (lambda: compose('unpause', s))
    scenarios = {
        'redis_stopped_c20': (stop_r, start_r, 20, 20, 60, 40),
        'redis_frozen_c20': (pause('redis'), unpause('redis'), 20, 20, 90, 40),
        'redis_frozen_c2': (pause('redis'), unpause('redis'), 2, 10, 60, 30),
        'db_frozen_c20': (pause('postgres'), unpause('postgres'), 20, 20, 150, 60),
        'db_frozen_c40': (pause('postgres'), unpause('postgres'), 40, 20, 150, 60),
        'db_frozen_c2': (pause('postgres'), unpause('postgres'), 2, 10, 90, 40),
    }
    try:
        for name in sys.argv[2:] or scenarios:
            failure(name, *scenarios[name])
    finally:
        compose('unpause', 'redis', check=False)
        compose('unpause', 'postgres', check=False)
        compose('up', '-d', 'redis', 'postgres', check=False)
    RESULTS['chain_after_failures'] = verify()
    save()
    log(RESULTS['chain_after_failures'])


COMMANDS = {'load': load, 'failures': failures}
if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS or (sys.argv[1] == 'load' and len(sys.argv) > 2):
    sys.exit(__doc__)
RESULT_FILE = f"{OUT}/{'-'.join(sys.argv[1:])}.json"
try:
    COMMANDS[sys.argv[1]]()
except Exception as e:
    RESULTS['error'] = repr(e)
    save()
    log('AUDIT_LOAD_FAILED', repr(e))
    raise
RESULTS['finished'] = datetime.now(timezone.utc).isoformat()
save()
log('AUDIT_LOAD_DONE', RESULT_FILE)
