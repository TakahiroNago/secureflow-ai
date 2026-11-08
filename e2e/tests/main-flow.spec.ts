import { expect, test, verifyChain } from '../fixtures'

/*
| E2E-01 (docs/test-strategy.md §10, §33): the scenario of requirement 9 in Chromium, Firefox and WebKit, on the
| built SPA as nginx serves it, with the real worker. A member logs in, sees what a scan cannot find, is stopped by a
| secret, has a workflow made, edits it with markup that stays text, submits it; an admin approves it, runs it, and
| finds all of it in the audit log. CSP violations and page errors fail the test (CSP-01).
*/

test('E2E-01: from the login to the audit log, as a member and then an admin', async ({ page, users, watch }, testInfo) => {
  const browser = testInfo.project.name

  // Only what is sent after the login has answered: before that, 401 is the right answer.
  let loggedIn = false
  const sentAfterLogin = new Set<unknown>()
  const me: number[] = []
  page.on('request', (request) => {
    if (loggedIn && request.url().endsWith('/api/v1/auth/me')) sentAfterLogin.add(request)
  })
  page.on('response', (response) => {
    if (response.url().endsWith('/api/v1/auth/login') && response.status() === 200) loggedIn = true
    if (sentAfterLogin.has(response.request())) me.push(response.status())
  })

  watch.at('the first page')
  const first = await page.goto('/')
  expect(first?.headers()['referrer-policy'], 'the page keeps the Referrer-Policy of the design').toBe('no-referrer')
  await page.getByRole('heading', { name: 'ログイン' }).waitFor()
  expect(new URL(page.url()).pathname, 'a visitor sees the login screen').toBe('/login')
  await watch.screenshot(`login-${browser}.png`)

  watch.at('the login')
  await page.getByLabel('メールアドレス').fill(users.member.email)
  await page.getByLabel('パスワード').fill(users.member.password)
  await page.getByRole('button', { name: 'ログイン' }).click()
  const dashboard = page.getByRole('heading', { name: 'ダッシュボード' })
  await expect(dashboard).toBeVisible({ timeout: 15_000 })
  // The reported failure of step 1-2: the welcome screen shows for a moment, then the login screen comes back.
  await page.waitForTimeout(3000)
  expect(new URL(page.url()).pathname, 'after logging in, it stays on the dashboard').toBe('/')
  expect(me.length > 0 && me.every((status) => status === 200), `auth/me answered 200 every time: ${JSON.stringify(me)}`).toBe(true)
  await page.reload()
  await expect(dashboard).toBeVisible()
  expect(new URL(page.url()).pathname, 'reloading keeps the login').toBe('/')

  // From the input to an edit, on the real screens with the real worker, and back to the numbers.
  watch.at('the input screen')
  await page.getByRole('link', { name: 'ワークフロー', exact: true }).click()
  await page.getByRole('link', { name: '新しく作成' }).click()
  await expect(page.getByText('検出は完全ではないため', { exact: false }), 'the input screen says detection is not complete').toBeVisible()

  watch.at('the check before sending')
  await page.getByLabel('依頼内容').fill('担当 user@example.com の件')
  await page.getByRole('button', { name: '送信前に確認' }).click()
  await expect(page.getByText('担当 [EMAIL_REDACTED] の件'), 'the check before sending shows the masked text').toBeVisible()
  await expect(page.getByText('検出されなかった情報が存在しないことは保証されません', { exact: false }), 'and what a scan cannot find').toBeVisible()

  // Built here, so that the repository holds nothing shaped like a key for secret scanners to find.
  watch.at('a secret in the input')
  const secret = 'gh' + 'p_' + 'A1b2C3d4'.repeat(4) + 'A1b2'
  const typed = '😀前の文 ' + secret + ' 後の文'
  await page.getByLabel('依頼内容').fill(typed)
  await page.getByRole('button', { name: '分析する' }).click()
  await expect(page.getByText('検査により処理を停止しました', { exact: false }), 'a secret stops the analysis').toBeVisible()
  expect(new URL(page.url()).pathname, 'and stays where it is, on this screen').toBe('/analyses/new')
  expect(await page.getByLabel('依頼内容').inputValue(), 'what was typed is kept').toBe(typed)
  await page.getByRole('button', { name: '該当箇所を選択' }).click()
  const selected = await page.getByLabel('依頼内容').evaluate((field) => {
    const input = field as HTMLTextAreaElement
    return input.value.slice(input.selectionStart, input.selectionEnd)
  })
  expect(selected, 'the place is selected').toBe(secret)

  watch.at('the analysis')
  await page.getByLabel('依頼内容').fill('週次の報告を作成する')
  await page.getByRole('button', { name: '分析する' }).click()
  await expect(page.getByRole('button', { name: '編集' }).first()).toBeVisible({ timeout: 30_000 })
  const workflowPath = new URL(page.url()).pathname
  expect(workflowPath, 'the analysis opens a workflow').toMatch(/^\/workflows\/[0-9a-f-]{36}$/)

  watch.at('an edit with markup')
  await page.getByRole('button', { name: '編集' }).first().click()
  await page.getByLabel('タイトル').fill('<b>画面から編集</b>')
  await page.getByLabel('説明').fill('<img src=x onerror="window.pwned=1"><script>window.pwned=1</script>')
  await page.getByRole('button', { name: '保存' }).click()
  await expect(page.getByRole('heading', { name: '1. <b>画面から編集</b>' }), 'an edit is saved, and drawn as text').toBeVisible()
  expect(await page.locator('main img, section img').count(), 'markup is never markup in a page').toBe(0)
  expect(await page.evaluate(() => (window as unknown as { pwned?: unknown }).pwned)).toBeUndefined()
  await watch.screenshot(`workflow-${browser}.png`)

  watch.at('the dashboard after the analysis')
  await page.getByRole('link', { name: 'ダッシュボード' }).click()
  await expect(page.getByText('今月の分析回数')).toBeVisible()
  await expect(page.locator('dt:text-is("ワークフロー数") + dd'), 'the dashboard counts it').toHaveText('1')
  await expect(page.locator('dt:text-is("AI トークン") + dd'), 'the mock counts no tokens').toHaveText('0')
  await expect(page.locator('dt:text-is("セキュリティ警告") + dd'), 'no warning was raised').toHaveText('0')
  expect(Number(await page.locator('dt:text-is("検出されたリスク") + dd').textContent()), 'what the scans found is counted').toBeGreaterThanOrEqual(2)
  await expect(page.locator('.recharts-bar-rectangle').first(), 'the chart is drawn').toBeVisible()
  await watch.screenshot(`dashboard-${browser}.png`)

  // Asking for an approval, on the real screens.
  watch.at('the submission')
  await page.goto(workflowPath)
  await page.getByRole('button', { name: '承認を依頼する' }).click()
  await expect(page.getByText('承認待ち', { exact: true }), 'the owner submits it').toBeVisible()
  await expect(page.getByText('承認可能な管理者がいないため', { exact: false }), 'and there is someone to approve it').toHaveCount(0)
  await expect(page.getByRole('link', { name: '承認待ち' }), 'a member has no list of approvals').toHaveCount(0)

  watch.at('the logout')
  await page.getByRole('button', { name: 'ログアウト' }).click()
  await expect(page.getByRole('heading', { name: 'ログイン' })).toBeVisible()
  expect(new URL(page.url()).pathname, 'logging out shows the login screen').toBe('/login')
  await page.reload()
  await page.waitForTimeout(1500)
  expect(new URL(page.url()).pathname, 'and after a reload it is still logged out').toBe('/login')

  // The other person, deciding on what the first one sent.
  watch.at('the admin login')
  await page.getByLabel('メールアドレス').fill(users.admin.email)
  await page.getByLabel('パスワード').fill(users.admin.password)
  await page.getByRole('button', { name: 'ログイン' }).click()
  await page.getByRole('link', { name: '承認待ち' }).click()
  const item = page.locator(`a[href="${workflowPath}/approval"]`)
  await expect(item, 'the admin finds it in the list').toBeVisible()
  await item.click()

  watch.at('the approval screen')
  const approve = page.getByRole('button', { name: '承認する' })
  await expect(approve).toBeVisible()
  for (const label of ['実行する処理', '使用する AI 機能', '対象データ', '必要な権限', '実行による影響']) {
    await expect(page.getByText(label, { exact: true }).first(), `the approval screen shows: ${label}`).toBeVisible()
  }
  await expect(page.getByText('検出されなかった情報が存在しないことは保証されません', { exact: false }), 'and the result of the scan, with what it cannot find').toBeVisible()
  await expect(page.getByText(/^[0-9a-f]{64}$/), 'and the hash being approved').toHaveCount(1)
  await expect(page.getByRole('heading', { name: '1. <b>画面から編集</b>' }), 'and the edit, as text').toBeVisible()
  await watch.screenshot(`approval-${browser}.png`)
  if (await page.getByRole('checkbox').count()) await page.getByRole('checkbox').check()
  await page.getByLabel('コメント（任意）').fill('<img src=x onerror="window.pwned=1"> 担当 reviewer@example.com')
  await approve.click()
  await expect(page.getByText('承認済み', { exact: true }), 'it is approved').toBeVisible()
  await expect(page.getByText('担当 [EMAIL_REDACTED]', { exact: false }), 'the comment is kept masked').toBeVisible()
  expect(await page.locator('main img, section img').count(), 'and as text').toBe(0)
  expect(await page.evaluate(() => (window as unknown as { pwned?: unknown }).pwned)).toBeUndefined()

  // Running it, as the same admin. The worker is real.
  watch.at('the execution')
  await page.getByRole('button', { name: '模擬実行する' }).click()
  await expect(page.getByText('リビジョン 2：完了'), 'it runs, and the history says so').toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('模擬実行。外部への操作はありません', { exact: false }).first(), 'the result says it was only simulated').toBeVisible()
  await expect(page.getByRole('button', { name: '模擬実行する' }), 'the button is gone').toHaveCount(0)

  // The record of all this, as the same admin.
  watch.at('the audit log')
  await page.getByRole('link', { name: '監査ログ' }).click()
  await expect(page.locator('td:text-is("execution.started")').first(), 'the audit log shows what happened').toBeVisible()
  await expect(page.getByText('改ざんがないことの保証ではありません', { exact: false }), 'and what a verification cannot show').toBeVisible()
  await verifyChain(page)
  await watch.screenshot(`audit-log-${browser}.png`)
})
