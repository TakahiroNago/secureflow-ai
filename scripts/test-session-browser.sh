#!/usr/bin/env bash
# SecureFlow AI — the order of responses and the session cookie in real browsers (AUDIT-SESSION-03).
# Chromium, Firefox and WebKit in the Playwright image, each with its own cookie store. A small proxy in that
# container stands in for the network: it holds a finished response on its way to the browser, so the logout
# or the password change reaches the browser first. The application is not changed for this.
#
# It only talks to the nginx of this project, and creates users, so it refuses to run on the default project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-session-browser.sh
#
# Rounds named no-fetch-metadata remove Sec-Fetch-* on the way, like a client or a proxy that does not send them
# (browsers send them only to https and localhost): the framework then falls back to the CSRF token.
#
# ROUNDS=0 OTHER_ROUNDS=0 runs only the rounds where nothing is held, the part whose result depends on timing.
#
# Downloads the image and the playwright package on first use. Exits non-zero if a requirement fails.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
. scripts/lib/login-limit.sh
: "${NGINX_PORT:=8080}"
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; then
  echo "Refusing to run: this creates users. Name a throwaway project in SECUREFLOW_ALLOW_FAILURE_INJECTION." >&2
  exit 2
fi
nginx_id=$(docker compose ps -q nginx)
[ -n "$nginx_id" ] && [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$nginx_id")" = "$P" ] \
  || { echo "Refusing to run: nginx is not running in $P." >&2; exit 2; }
NET=${P}_web
[ "$(docker network inspect -f '{{index .Labels "com.docker.compose.project"}}' "$NET" 2>/dev/null)" = "$P" ] \
  || { echo "Refusing to run: network $NET is not in $P." >&2; exit 2; }

PW_VERSION=1.56.1
IMAGE=mcr.microsoft.com/playwright:v$PW_VERSION-noble@sha256:f1e7e01021efd65dd1a2c56064be399f3e4de00fd021ac561325f2bfbb2b837a
ROUNDS=${ROUNDS:-20}; OTHER_ROUNDS=${OTHER_ROUNDS:-5}; NATURAL_ROUNDS=${NATURAL_ROUNDS:-10}

mkdir -p "$HOME/tmp"
work=$(mktemp -d "$HOME/tmp/session-browser-XXXXXX")
chmod 700 "$work"
watcher=''
trap '[ -z "$watcher" ] || kill "$watcher" 2> /dev/null; rm -rf "$work"' EXIT
in_image() { docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$work:/work" -w /work "$@"; }

in_image "$IMAGE" npm install --silent --no-audit --no-fund --ignore-scripts "playwright@$PW_VERSION" > /dev/null \
  || { echo 'could not install playwright' >&2; exit 2; }

docker compose exec -T app php artisan db:seed --force > /dev/null 2>&1
needed=$(( 2 * (ROUNDS + 3 * OTHER_ROUNDS + NATURAL_ROUNDS) + 3 * OTHER_ROUNDS ))
echo "Target: $P through $NET. $ROUNDS Chromium and $OTHER_ROUNDS Firefox and WebKit rounds of each kind, $NATURAL_ROUNDS natural rounds of each kind, $needed users"
: > "$work/users.txt"
for ((i=0;i<needed;i++)); do
  email="browser-$$-$RANDOM-$RANDOM@example.com"; pw="start pass phrase $(cat /proc/sys/kernel/random/uuid)"
  printf '%s\n%s\n' "$pw" "$pw" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$email" --email="$email" --role=member > /dev/null 2>&1 \
    || { echo 'could not create a user' >&2; exit 2; }
  printf '%s\t%s\n' "$email" "$pw" >> "$work/users.txt"
done

cat > "$work/run.mjs" <<'JS'
import { chromium, firefox, webkit } from 'playwright';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { networkInterfaces } from 'node:os';

const PORT = Number(process.env.PORT);
const BASE = `http://localhost:${PORT}`;
const users = readFileSync('users.txt', 'utf8').trim().split('\n').map((l) => l.split('\t'));
const held = new Map();
let withoutFetchMetadata = false;
const hold = (name) => {
  if (!held.has(name)) {
    const h = {};
    h.finished = new Promise((r) => { h.finish = r; });
    h.released = new Promise((r) => { h.release = r; });
    held.set(name, h);
  }
  return held.get(name);
};
const proxy = http.createServer(async (req, res) => {
  if (req.url === '/__blank') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><title>t</title>'); return; }
  if (req.url === '/favicon.ico') { res.writeHead(204); res.end(); return; }
  const name = req.headers['x-test-hold'];
  delete req.headers['x-test-hold'];
  // Held on the way to the application: it sets out with the old cookie and arrives after the change.
  const late = req.headers['x-test-hold-request'];
  delete req.headers['x-test-hold-request'];
  if (late) {
    hold(late).finish();
    await hold(late).released;
  }
  if (withoutFetchMetadata) for (const h of Object.keys(req.headers)) if (h.startsWith('sec-fetch-')) delete req.headers[h];
  const up = http.request({ host: 'nginx', port: 80, method: req.method, path: req.url, headers: req.headers }, (answer) => {
    const chunks = [];
    answer.on('data', (c) => chunks.push(c));
    answer.on('end', async () => {
      const body = Buffer.concat(chunks);
      if (name) {
        const h = hold(name);
        h.finish((answer.headers['set-cookie'] ?? []).map((c) => c.split(';')[0]));
        await h.released;
      }
      const raw = [];
      for (let i = 0; i < answer.rawHeaders.length; i += 2) {
        if (!/^(transfer-encoding|connection|content-length)$/i.test(answer.rawHeaders[i])) raw.push(answer.rawHeaders[i], answer.rawHeaders[i + 1]);
      }
      raw.push('Content-Length', String(body.length));
      res.writeHead(answer.statusCode, raw);
      res.end(body);
    });
  });
  up.on('error', () => { res.writeHead(502); res.end(); });
  req.pipe(up);
});
await new Promise((r) => proxy.listen(PORT, 'localhost', r));

// This container cannot reach the store: the shell outside clears the limit for its address, on request.
const address = Object.values(networkInterfaces()).flat().find((i) => i.family === 'IPv4' && !i.internal).address;
const nextLoginWindow = async () => {
  writeFileSync('limit.request', address);
  for (let i = 0; i < 300 && existsSync('limit.request'); i++) await new Promise((r) => setTimeout(r, 100));
};
let logins = 0;
const paceLogin = async () => { if (++logins % 20 === 0) await nextLoginWindow(); };
await nextLoginWindow();
const inPage = (page, method, path, body, extra) => page.evaluate(async ({ method, path, body, extra, keep }) => {
  const token = document.cookie.split('; ').find((c) => c.startsWith('XSRF-TOKEN='));
  const headers = { Accept: 'application/json', ...(extra ?? {}) };
  if (token) headers['X-XSRF-TOKEN'] = decodeURIComponent(token.split('=')[1]);
  if (body) headers['Content-Type'] = 'application/json';
  const sent = fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin' }).then((r) => r.status);
  if (keep) { window.__held = sent; return null; }
  return sent;
}, { method, path, body: body ?? null, extra: extra ?? null, keep: false });
const startHeld = (page, name) => page.evaluate((name) => {
  const token = document.cookie.split('; ').find((c) => c.startsWith('XSRF-TOKEN='));
  const headers = { Accept: 'application/json', 'X-Test-Hold': name };
  if (token) headers['X-XSRF-TOKEN'] = decodeURIComponent(token.split('=')[1]);
  // Its own URL: Chromium makes a second GET of the same URL wait up to 20 seconds behind an unfinished one.
  window.__held = fetch('/api/v1/auth/me?held=1', { headers, credentials: 'same-origin' }).then((r) => r.status);
}, name);
const sessionOf = async (context) => (await context.cookies()).find((c) => /session/i.test(c.name));
const csrf = (page) => inPage(page, 'GET', '/sanctum/csrf-cookie');
const login = async (page, email, password) => { await paceLogin(); return inPage(page, 'POST', '/api/v1/auth/login', { email, password }); };
const changePassword = (page, current, next) => inPage(page, 'PATCH', '/api/v1/account/password', { current_password: current, new_password: next }, { 'Idempotency-Key': randomUUID() });

// What a person would do next: the sign-in form, with the cookies the browser ended up with.
async function again(context, page, email, password, row) {
  const before = (await sessionOf(context))?.value;
  await csrf(page);
  row.csrfChangedCookie = (await sessionOf(context))?.value !== before;
  row.relogin = await login(page, email, password);
  row.meAfterRelogin = await inPage(page, 'GET', '/api/v1/auth/me');
  if (row.relogin !== 200) {
    await context.clearCookies();
    await csrf(page);
    row.afterClearing = await login(page, email, password);
    row.meAfterClearing = await inPage(page, 'GET', '/api/v1/auth/me');
  }
}

const rows = [];
async function heldRound(browser, browserName, kind, round, strip = false) {
  withoutFetchMetadata = strip;
  const [email, password] = users.pop();
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${BASE}/__blank`);
  const row = { browser: browserName, kind: strip ? `${kind}-no-fetch-metadata` : kind, round };
  await csrf(page);
  row.login = await login(page, email, password);
  const old = await sessionOf(context);
  row.oldCookie = old.value; row.httpOnly = old.httpOnly;
  const name = randomUUID();
  await startHeld(page, name);
  const carried = await hold(name).finished;
  row.heldNotApplied = (await sessionOf(context)).value === old.value;
  const next = `changed pass phrase ${randomUUID()}`;
  row.action = kind === 'logout' ? await inPage(page, 'POST', '/api/v1/auth/logout') : await changePassword(page, password, next);
  const afterAction = await sessionOf(context);
  row.cookieAfterAction = afterAction === undefined ? 'removed' : afterAction.value === old.value ? 'unchanged' : 'replaced';
  row.newCookie = afterAction?.value ?? null;
  row.meBeforeArrival = await inPage(page, 'GET', '/api/v1/auth/me');
  const beforeArrival = (await sessionOf(context))?.value;
  hold(name).release();
  row.get = await page.evaluate(() => window.__held);
  const sent = carried.find((c) => /session/i.test(c.split('=')[0]));
  const final = await sessionOf(context);
  row.getSentCookie = sent !== undefined;
  row.overwritten = sent !== undefined && final?.value === sent.slice(sent.indexOf('=') + 1) && final?.value !== beforeArrival;
  row.meFinal = await inPage(page, 'GET', '/api/v1/auth/me');
  await again(context, page, email, kind === 'logout' ? password : next, row);
  await context.close();
  rows.push(row);
}
// A csrf-cookie that sets out before a password change and reaches the application after it: a retired id gets
// no cookies from this route either, so the browser keeps its new session.
async function lateCsrfRound(browser, browserName, round) {
  const [email, password] = users.pop();
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${BASE}/__blank`);
  const row = { browser: browserName, kind: 'late-csrf-cookie', round };
  await csrf(page);
  row.login = await login(page, email, password);
  row.oldCookie = (await sessionOf(context)).value;
  const name = randomUUID();
  await page.evaluate((name) => {
    window.__held = fetch('/sanctum/csrf-cookie', { headers: { Accept: 'application/json', 'X-Test-Hold-Request': name }, credentials: 'same-origin' }).then((r) => r.status);
  }, name);
  await hold(name).finished;
  const next = `changed pass phrase ${randomUUID()}`;
  row.action = await changePassword(page, password, next);
  row.newCookie = (await sessionOf(context)).value;
  row.meBeforeArrival = await inPage(page, 'GET', '/api/v1/auth/me');
  // Every response encrypts the cookie anew, so the value to compare with is the latest, not the one after the change.
  const beforeArrival = (await sessionOf(context))?.value;
  hold(name).release();
  row.get = await page.evaluate(() => window.__held);
  row.cookieAfterArrival = (await sessionOf(context))?.value === beforeArrival ? 'unchanged' : 'replaced';
  row.meFinal = await inPage(page, 'GET', '/api/v1/auth/me');
  await context.close();
  rows.push(row);
}
async function naturalRound(browser, kind, round) {
  const [email, password] = users.pop();
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${BASE}/__blank`);
  const row = { browser: 'chromium', kind: `natural-${kind}`, round };
  await csrf(page);
  row.login = await login(page, email, password);
  row.oldCookie = (await sessionOf(context)).value;
  const next = `changed pass phrase ${randomUUID()}`;
  const action = kind === 'logout' ? inPage(page, 'POST', '/api/v1/auth/logout') : changePassword(page, password, next);
  // A URL each, for the same reason as the held GET: on one URL, Chromium would run them one after another.
  const gets = [0, 50, 150, 300].map((ms) => new Promise((r) => setTimeout(r, ms)).then(() => inPage(page, 'GET', `/api/v1/auth/me?overlap=${ms}`)));
  row.action = await action;
  row.gets = await Promise.all(gets);
  row.meFinal = await inPage(page, 'GET', '/api/v1/auth/me');
  row.cookieIsOld = (await sessionOf(context))?.value === row.oldCookie;
  await context.close();
  rows.push(row);
}

const plan = [
  ['chromium', chromium, Number(process.env.ROUNDS)],
  ['firefox', firefox, Number(process.env.OTHER_ROUNDS)],
  ['webkit', webkit, Number(process.env.OTHER_ROUNDS)],
];
for (const [name, type, rounds] of plan) {
  const browser = await type.launch();
  for (const kind of ['logout', 'password']) {
    for (let r = 1; r <= rounds; r++) await heldRound(browser, name, kind, r);
  }
  for (let r = 1; r <= Number(process.env.OTHER_ROUNDS); r++) await lateCsrfRound(browser, name, r);
  if (name === 'chromium') {
    for (const kind of ['logout', 'password']) {
      for (let r = 1; r <= Number(process.env.OTHER_ROUNDS); r++) await heldRound(browser, name, kind, r, true);
    }
    withoutFetchMetadata = false;
    for (const kind of ['logout', 'password']) {
      for (let r = 1; r <= Number(process.env.NATURAL_ROUNDS); r++) await naturalRound(browser, kind, r);
    }
  }
  await browser.close();
}
writeFileSync('results.json', JSON.stringify(rows));
proxy.close();
process.exit(0);
JS

(
  while :; do
    if [ -f "$work/limit.request" ]; then
      next_login_window_for=$(cat "$work/limit.request")
      clear_login_limit "$next_login_window_for" || sleep 61
      rm -f "$work/limit.request"
    fi
    sleep 0.1
  done
) &
watcher=$!

in_image --network "$NET" -e PORT="$NGINX_PORT" -e ROUNDS="$ROUNDS" -e OTHER_ROUNDS="$OTHER_ROUNDS" -e NATURAL_ROUNDS="$NATURAL_ROUNDS" "$IMAGE" node run.mjs \
  || { echo 'the browser run failed' >&2; exit 1; }

# The store is asked here, about every old cookie and about each new session after a password change.
stored_all() {
  python3 -I -c 'import json,sys
for r in json.load(open(sys.argv[1])):
    print(r[sys.argv[2]] if r.get(sys.argv[2]) else "-")' "$work/results.json" "$1" | while read -r cookie; do
    if [ "$cookie" = - ]; then echo none; continue; fi
    docker compose exec -T app php -r '
      chdir("/var/www/html"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";
      $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
      $id = Illuminate\Cookie\CookieValuePrefix::remove(Illuminate\Support\Facades\Crypt::decrypt(urldecode($argv[1]), false));
      $data = app("session")->driver()->getHandler()->read($id);
      echo $data === "" ? "absent" : (str_contains($data, "login_web_") ? "login" : "empty");' "$cookie" 2>/dev/null < /dev/null
    echo
  done
}
stored_all oldCookie > "$work/old.txt"
stored_all newCookie > "$work/new.txt"

python3 -I - "$work/results.json" "$work/old.txt" "$work/new.txt" <<'PY'
import collections, json, sys
rows = json.load(open(sys.argv[1]))
old = open(sys.argv[2]).read().split()
new = open(sys.argv[3]).read().split()
for r, o, n in zip(rows, old, new):
    r['storedOld'], r['storedNew'] = o, n
fails = 0
def show(label, values):
    print(f'    {label}: ' + ', '.join(f'{k} x{v}' for k, v in sorted(collections.Counter(map(str, values)).items())))
def need(label, values, want):
    global fails
    bad = [v for v in values if v != want]
    if bad:
        fails += 1
    print(f"  [{'FAIL' if bad else 'PASS'}] {label}: {len(values) - len(bad)} of {len(values)} are {want}")
groups = collections.OrderedDict()
for r in rows:
    groups.setdefault((r['browser'], r['kind']), []).append(r)
for (browser, kind), g in groups.items():
    print(f'\n== {browser} {kind}: {len(g)} rounds ==')
    col = lambda k: [r.get(k) for r in g]
    need('login', col('login'), 200)
    need('the old id is not back', col('storedOld'), 'absent')
    if kind.startswith('natural'):
        need('the action', col('action'), 204 if 'logout' in kind else 200)
        show('GET answers', [s for r in g for s in r['gets']])
        show('the cookie store ended up with the old cookie', col('cookieIsOld'))
        show('auth/me afterwards', col('meFinal'))
        continue
    if kind == 'late-csrf-cookie':
        need('the password change', col('action'), 200)
        need('the new session worked before it arrived', col('meBeforeArrival'), 200)
        need('csrf-cookie answers', col('get'), 204)
        need('the session cookie after it arrived', col('cookieAfterArrival'), 'unchanged')
        need('auth/me afterwards', col('meFinal'), 200)
        need('the new session on the server afterwards', col('storedNew'), 'login')
        continue
    need('the response was held, not yet applied', col('heldNotApplied'), True)
    need('the action', col('action'), 204 if 'logout' in kind else 200)
    need('before the held response arrives', col('meBeforeArrival'), 401 if 'logout' in kind else 200)
    need('the held GET answers', col('get'), 200)
    need('it carried a session cookie', col('getSentCookie'), True)
    need('the cookie is HttpOnly', col('httpOnly'), True)
    show('the session cookie after the action', col('cookieAfterAction'))
    show('the held response replaced the session cookie', col('overwritten'))
    need('auth/me with what the browser ended up with', col('meFinal'), 401)
    if 'password' in kind:
        show('the new session on the server afterwards', col('storedNew'))
    need('csrf-cookie leaves the session cookie as it is', col('csrfChangedCookie'), False)
    # With Sec-Fetch-Site the framework does not compare the token. Without it, the token is the retired session's.
    if 'no-fetch-metadata' in kind:
        need('logging in again, cookies as they are', col('relogin'), 419)
        need('with the cookies cleared, logging in', col('afterClearing'), 200)
        need('and that login works', col('meAfterClearing'), 200)
    else:
        need('logging in again, cookies as they are', col('relogin'), 200)
        need('and that login works', col('meAfterRelogin'), 200)
print(f'\nResult: {fails} requirements failed')
sys.exit(1 if fails else 0)
PY
