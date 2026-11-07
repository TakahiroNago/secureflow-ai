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
  admin="approver-$$-$RANDOM-$name@example.com"; admin_pw="start pass phrase $(cat /proc/sys/kernel/random/uuid)"
  printf '%s\n%s\n' "$admin_pw" "$admin_pw" | docker compose exec -T app php artisan user:create \
    --organization='Default Organization' --name="$admin" --email="$admin" --role=admin > /dev/null 2>&1 \
    || { echo 'could not create an admin' >&2; exit 2; }
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$email" "$pw" "$admin" "$admin_pw" >> "$work/users.txt"
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
  const [name, email, password, adminEmail, adminPassword] = line.split('\t');
  console.log(`\n== ${name} ==`);
  const browser = await browsers[name].launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  // A page that breaks the CSP goes on working, so this has to be looked for.
  const violations = [];
  page.on('console', (m) => { if (/Content Security Policy|Content-Security-Policy/i.test(m.text())) violations.push(m.text().slice(0, 160)); });
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
  const notComplete = page.getByText('検出は完全ではないため', { exact: false });
  await notComplete.waitFor({ timeout: 10000 }).catch(() => {});
  check('the input screen says detection is not complete', await notComplete.isVisible());

  // Built here, so that the repository holds nothing shaped like a key for secret scanners to find.
  const secret = 'gh' + 'p_' + 'A1b2C3d4'.repeat(4) + 'A1b2';
  await page.getByLabel('依頼内容').fill('担当 user@example.com の件');
  await page.getByRole('button', { name: '送信前に確認' }).click();
  const masked = page.getByText('担当 [EMAIL_REDACTED] の件');
  await masked.waitFor({ timeout: 10000 }).catch(() => {});
  check('the check before sending shows the masked text', await masked.isVisible());
  check('and what a scan cannot find', await page.getByText('検出されなかった情報が存在しないことは保証されません', { exact: false }).isVisible());

  const typed = '😀前の文 ' + secret + ' 後の文';
  await page.getByLabel('依頼内容').fill(typed);
  await page.getByRole('button', { name: '分析する' }).click();
  const stopped = page.getByText('検査により処理を停止しました', { exact: false });
  await stopped.waitFor({ timeout: 10000 }).catch(() => {});
  check('a secret stops the analysis', await stopped.isVisible());
  check('and stays where it is, on this screen', new URL(page.url()).pathname === '/analyses/new', page.url());
  check('what was typed is kept', (await page.getByLabel('依頼内容').inputValue()) === typed);
  await page.getByRole('button', { name: '該当箇所を選択' }).click();
  const selected = await page.getByLabel('依頼内容').evaluate((field) => field.value.slice(field.selectionStart, field.selectionEnd));
  check('the place is selected', selected === secret, selected);

  await page.getByLabel('依頼内容').fill('週次の報告を作成する');
  await page.getByRole('button', { name: '分析する' }).click();
  await page.getByRole('button', { name: '編集' }).first().waitFor({ timeout: 30000 }).catch(() => {});
  check('the analysis opens a workflow', /^\/workflows\/[0-9a-f-]{36}$/.test(new URL(page.url()).pathname), page.url());
  const workflowPath = new URL(page.url()).pathname;
  await page.getByRole('button', { name: '編集' }).first().click({ timeout: 5000 });
  await page.getByLabel('タイトル').fill('<b>画面から編集</b>');
  await page.getByLabel('説明').fill('<img src=x onerror="window.pwned=1"><script>window.pwned=1</script>');
  await page.getByRole('button', { name: '保存' }).click();
  await page.getByRole('heading', { name: '1. <b>画面から編集</b>' }).waitFor({ timeout: 10000 }).catch(() => {});
  check('an edit is saved, and drawn as text', await page.getByRole('heading', { name: '1. <b>画面から編集</b>' }).isVisible());
  check('markup is never markup in a page', (await page.locator('main img, section img').count()) === 0 && (await page.evaluate(() => window.pwned)) === undefined);
  await page.getByRole('link', { name: 'ダッシュボード' }).click();
  await page.getByText('今月の分析回数').waitFor({ timeout: 10000 }).catch(() => {});
  check('the dashboard counts it', (await page.locator('dt:text-is("ワークフロー数") + dd').textContent()) === '1');
  check('the mock counts no tokens', (await page.locator('dt:text-is("AI トークン") + dd').textContent()) === '0');
  check('no warning was raised', (await page.locator('dt:text-is("セキュリティ警告") + dd').textContent()) === '0');
  check('what the scans found is counted', Number(await page.locator('dt:text-is("検出されたリスク") + dd').textContent()) >= 2);
  await page.locator('.recharts-bar-rectangle').first().waitFor({ timeout: 5000 }).catch(() => {});
  check('the chart is drawn', (await page.locator('.recharts-bar-rectangle').count()) > 0);
  check('nothing failed on the page', problems.length === 0, problems.join('; '));
  await page.setViewportSize({ width: 1280, height: 900 });
  // caret 'initial': hiding the caret makes Playwright add a <style>, which the CSP refuses as it should.
  await page.screenshot({ path: `dashboard-${name}.png`, fullPage: true, caret: 'initial' });

  // Asking for an approval, on the real screens.
  await page.goto(`${BASE}${workflowPath}`);
  await page.getByRole('button', { name: '承認を依頼する' }).click({ timeout: 10000 });
  await page.getByText('承認待ち', { exact: true }).waitFor({ timeout: 10000 }).catch(() => {});
  check('the owner submits it', await page.getByText('承認待ち', { exact: true }).isVisible());
  check('and there is someone to approve it', !(await page.getByText('承認可能な管理者がいないため', { exact: false }).isVisible()));
  check('a member has no list of approvals', (await page.getByRole('link', { name: '承認待ち' }).count()) === 0);

  await page.getByRole('button', { name: 'ログアウト' }).click({ timeout: 5000 }).catch(() => check('there is a logout button', false, 'none'));
  await page.getByRole('heading', { name: 'ログイン' }).waitFor({ timeout: 10000 }).catch(() => {});
  check('logging out shows the login screen', new URL(page.url()).pathname === '/login', page.url());
  await page.reload();
  await page.waitForTimeout(1500);
  check('and after a reload it is still logged out', new URL(page.url()).pathname === '/login', page.url());

  // The other person, deciding on what the first one sent.
  await page.getByLabel('メールアドレス').fill(adminEmail);
  await page.getByLabel('パスワード').fill(adminPassword);
  await page.getByRole('button', { name: 'ログイン' }).click();
  await page.getByRole('link', { name: '承認待ち' }).click({ timeout: 10000 });
  const item = page.locator(`a[href="${workflowPath}/approval"]`);
  await item.waitFor({ timeout: 10000 }).catch(() => {});
  check('the admin finds it in the list', await item.isVisible());
  await item.click({ timeout: 5000 });
  const approve = page.getByRole('button', { name: '承認する' });
  await approve.waitFor({ timeout: 10000 }).catch(() => {});
  for (const label of ['実行する処理', '使用する AI 機能', '対象データ', '必要な権限', '実行による影響']) {
    check(`the approval screen shows: ${label}`, await page.getByText(label, { exact: true }).first().isVisible());
  }
  check('and the result of the scan, with what it cannot find', await page.getByText('検出されなかった情報が存在しないことは保証されません', { exact: false }).isVisible());
  check('and the hash being approved', (await page.getByText(/^[0-9a-f]{64}$/).count()) === 1);
  check('and the edit, as text', await page.getByRole('heading', { name: '1. <b>画面から編集</b>' }).isVisible());
  if (await page.getByRole('checkbox').count()) await page.getByRole('checkbox').check();
  await page.getByLabel('コメント（任意）').fill('<img src=x onerror="window.pwned=1"> 担当 reviewer@example.com');
  await approve.click({ timeout: 5000 });
  const decided = page.getByText('承認済み', { exact: true });
  await decided.waitFor({ timeout: 10000 }).catch(() => {});
  check('it is approved', await decided.isVisible());
  check('the comment is kept masked', await page.getByText('担当 [EMAIL_REDACTED]', { exact: false }).isVisible());
  check('and as text', (await page.locator('main img, section img').count()) === 0 && (await page.evaluate(() => window.pwned)) === undefined);

  // Running it, as the same admin. The worker is real.
  await page.getByRole('button', { name: '模擬実行する' }).click({ timeout: 5000 });
  const finished = page.getByText('リビジョン 2：完了');
  await finished.waitFor({ timeout: 30000 }).catch(() => {});
  check('it runs, and the history says so', await finished.isVisible());
  check('the result says it was only simulated', await page.getByText('模擬実行。外部への操作はありません', { exact: false }).first().isVisible());
  check('the button is gone', (await page.getByRole('button', { name: '模擬実行する' }).count()) === 0);

  // The record of all this, as the same admin.
  await page.getByRole('link', { name: '監査ログ' }).click({ timeout: 5000 });
  const logged = page.locator('td:text-is("execution.started")').first();
  await logged.waitFor({ timeout: 10000 }).catch(() => {});
  check('the audit log shows what happened', await logged.isVisible());
  check('and what a verification cannot show', await page.getByText('改ざんがないことの保証ではありません', { exact: false }).isVisible());
  await page.getByRole('button', { name: 'チェーンを検証' }).click({ timeout: 5000 });
  const verified = page.getByText('矛盾は見つかりませんでした', { exact: false });
  await verified.waitFor({ timeout: 15000 }).catch(() => {});
  check('verifying finds nothing wrong', await verified.isVisible());
  check('still nothing failed on the page', problems.length === 0, problems.join('; '));
  check('the CSP was never broken, on any screen', violations.length === 0, violations.join('; '));
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`${BASE}${workflowPath}/approval`);
  await page.getByRole('heading', { name: /^承認：/ }).waitFor({ timeout: 10000 }).catch(() => {});
  await page.screenshot({ path: `approval-${name}.png`, fullPage: true, caret: 'initial' });
  await browser.close();
}
console.log(`\nResult: ${fails} failed`);
process.exit(fails ? 1 : 0);
JS

in_image --network "$NET" -e PORT="$NGINX_PORT" "$IMAGE" node run.mjs
status=$?
# To look at the screens: BROWSER_SCREENSHOTS=<directory>
[ -z "${BROWSER_SCREENSHOTS:-}" ] || cp "$work"/dashboard-*.png "$work"/approval-*.png "$BROWSER_SCREENSHOTS"/
exit "$status"
