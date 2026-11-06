#!/usr/bin/env bash
# SecureFlow AI — the real login screen in real browsers (AUTH-E2E-01): the built SPA as nginx serves it, with nginx's
# own headers. Chromium, Firefox and WebKit fill in the form and click, as a person does. A small TCP forwarder in the
# container gives them localhost:<NGINX_PORT>, which is what Sanctum's stateful domains list. It changes no bytes.
#
# It creates users, so it refuses to run unless the caller names this exact project:
#
#   SECUREFLOW_ALLOW_FAILURE_INJECTION=<COMPOSE_PROJECT_NAME> bash scripts/test-login-browser.sh
#
# CI runs it on its own stack, which is thrown away after the job. Needs a built frontend. Downloads the image and the playwright package on first use.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a; . ./.env; set +a
. scripts/lib/login-limit.sh
: "${NGINX_PORT:=8080}"
P=${COMPOSE_PROJECT_NAME:-secureflow}
if [ "${CI:-}" != true ] && { [ "$P" = secureflow ] || [ "${SECUREFLOW_ALLOW_FAILURE_INJECTION:-}" != "$P" ]; }; then
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

mkdir -p "$HOME/tmp"
work=$(mktemp -d "$HOME/tmp/login-browser-XXXXXX")
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT
in_image() { docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$work:/work" -w /work "$@"; }

in_image "$IMAGE" npm install --silent --no-audit --no-fund --ignore-scripts "playwright@$PW_VERSION" > /dev/null \
  || { echo 'could not install playwright' >&2; exit 2; }

docker compose exec -T app php artisan db:seed --force > /dev/null 2>&1
# A script before this one may have used up the limit per address. In CI this waits for the window to pass.
next_login_window
echo "Target: $P through $NET"
: > "$work/users.txt"
for name in chromium firefox webkit; do
  email="login-$$-$RANDOM-$name@example.com"; pw="start pass phrase $(cat /proc/sys/kernel/random/uuid)"
  printf '%s\n%s\n' "$pw" "$pw" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$email" --email="$email" --role=member > /dev/null 2>&1 \
    || { echo 'could not create a user' >&2; exit 2; }
  printf '%s\t%s\t%s\n' "$name" "$email" "$pw" >> "$work/users.txt"
done

cat > "$work/run.mjs" <<'JS'
import { chromium, firefox, webkit } from 'playwright';
import { readFileSync } from 'node:fs';
import net from 'node:net';

const PORT = Number(process.env.PORT);
const BASE = `http://localhost:${PORT}`;
const browsers = { chromium, firefox, webkit };
await new Promise((r) => net.createServer((c) => {
  const up = net.connect(80, 'nginx');
  c.pipe(up); up.pipe(c);
  c.on('error', () => up.destroy()); up.on('error', () => c.destroy());
}).listen(PORT, 'localhost', r));

let fails = 0;
const check = (label, ok, got = '') => {
  if (!ok) fails++;
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${label}${ok ? '' : ` (got ${got})`}`);
};
for (const line of readFileSync('users.txt', 'utf8').trim().split('\n')) {
  const [name, email, password] = line.split('\t');
  console.log(`\n== ${name} ==`);
  const browser = await browsers[name].launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  // Only what is sent after the login has answered: before that, 401 is the right answer.
  let loggedIn = false;
  const sentAfterLogin = new Set();
  const me = [];
  page.on('request', (q) => { if (loggedIn && q.url().endsWith('/api/v1/auth/me')) sentAfterLogin.add(q); });
  page.on('response', (r) => {
    if (r.url().endsWith('/api/v1/auth/login') && r.status() === 200) loggedIn = true;
    if (sentAfterLogin.has(r.request())) me.push(r.status());
  });

  const first = await page.goto(`${BASE}/`);
  check('the page keeps the Referrer-Policy of the design', first.headers()['referrer-policy'] === 'no-referrer', first.headers()['referrer-policy']);
  await page.getByRole('heading', { name: 'ログイン' }).waitFor();
  check('a visitor sees the login screen', new URL(page.url()).pathname === '/login', page.url());

  await page.getByLabel('メールアドレス').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.getByRole('button', { name: 'ログイン' }).click();
  const dashboard = page.getByRole('heading', { name: 'ダッシュボード' });
  await dashboard.waitFor({ timeout: 10000 }).catch(() => {});
  // The reported failure: the welcome screen shows for a moment, then the login screen comes back.
  await page.waitForTimeout(3000);
  check('after logging in, it stays on the dashboard', new URL(page.url()).pathname === '/', page.url());
  check('the dashboard is showing', await dashboard.isVisible());
  check('auth/me answered 200 every time', me.length > 0 && me.every((s) => s === 200), JSON.stringify(me));

  await page.reload();
  await page.waitForTimeout(1500);
  check('reloading keeps the login', new URL(page.url()).pathname === '/' && await dashboard.isVisible(), page.url());

  // From the input to an edit, on the real screens with the real worker, and back to the numbers.
  const problems = [];
  page.on('pageerror', (e) => problems.push(String(e)));
  await page.getByRole('link', { name: 'ワークフロー', exact: true }).click();
  await page.getByRole('link', { name: '新しく作成' }).click();
  check('the input screen warns', (await page.getByRole('alert').textContent()).includes('機密情報や個人情報を入力しないでください'));
  await page.getByLabel('依頼内容').fill('週次の報告を作成する');
  await page.getByRole('button', { name: '分析する' }).click();
  await page.getByRole('button', { name: '編集' }).first().waitFor({ timeout: 30000 }).catch(() => {});
  check('the analysis opens a workflow', /^\/workflows\/[0-9a-f-]{36}$/.test(new URL(page.url()).pathname), page.url());
  await page.getByRole('button', { name: '編集' }).first().click({ timeout: 5000 });
  await page.getByLabel('タイトル').fill('<b>画面から編集</b>');
  await page.getByRole('button', { name: '保存' }).click();
  await page.getByRole('heading', { name: '1. <b>画面から編集</b>' }).waitFor({ timeout: 10000 }).catch(() => {});
  check('an edit is saved, and drawn as text', await page.getByRole('heading', { name: '1. <b>画面から編集</b>' }).isVisible());
  await page.getByRole('link', { name: 'ダッシュボード' }).click();
  await page.getByText('今月の分析回数').waitFor({ timeout: 10000 }).catch(() => {});
  check('the dashboard counts it', (await page.locator('dt:text-is("ワークフロー数") + dd').textContent()) === '1');
  check('what does not exist yet is not a zero', (await page.locator('dt:text-is("セキュリティ警告") + dd').textContent()) === '未実装');
  await page.locator('.recharts-bar-rectangle').first().waitFor({ timeout: 5000 }).catch(() => {});
  check('the chart is drawn', (await page.locator('.recharts-bar-rectangle').count()) > 0);
  check('nothing failed on the page', problems.length === 0, problems.join('; '));
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.screenshot({ path: `dashboard-${name}.png`, fullPage: true });

  await page.getByRole('button', { name: 'ログアウト' }).click({ timeout: 5000 }).catch(() => check('there is a logout button', false, 'none'));
  await page.getByRole('heading', { name: 'ログイン' }).waitFor({ timeout: 10000 }).catch(() => {});
  check('logging out shows the login screen', new URL(page.url()).pathname === '/login', page.url());
  await page.reload();
  await page.waitForTimeout(1500);
  check('and after a reload it is still logged out', new URL(page.url()).pathname === '/login', page.url());
  await browser.close();
}
console.log(`\nResult: ${fails} failed`);
process.exit(fails ? 1 : 0);
JS

in_image --network "$NET" -e PORT="$NGINX_PORT" "$IMAGE" node run.mjs
status=$?
# To look at the screens: BROWSER_SCREENSHOTS=<directory>
[ -z "${BROWSER_SCREENSHOTS:-}" ] || cp "$work"/dashboard-*.png "$BROWSER_SCREENSHOTS"/
exit "$status"
