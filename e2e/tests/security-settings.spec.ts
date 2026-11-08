import { expect, login, logout, test } from '../fixtures'

/*
| E2E-05 (step 2-10 on the real stack): what the scans found is on the security screen, an admin changes its status
| with a note that comes back masked, changes a limit that is saved, and a member changes their own password and
| logs in with it.
*/

test('E2E-05: the security and settings screens, as an admin and a member', async ({ page, users, watch }) => {
  watch.at('a member is stopped by a secret')
  await login(page, users.member)
  await page.getByRole('link', { name: 'ワークフロー', exact: true }).click()
  await page.getByRole('link', { name: '新しく作成' }).click()
  const secret = 'gh' + 'p_' + 'Z9y8X7w6'.repeat(4) + 'Z9y8'
  await page.getByLabel('依頼内容').fill('鍵は ' + secret + ' です')
  await page.getByRole('button', { name: '分析する' }).click()
  await expect(page.getByText('検査により処理を停止しました', { exact: false })).toBeVisible()

  watch.at('the member sees the finding, without a way to change it')
  await page.getByRole('link', { name: 'セキュリティ' }).click()
  const rows = page.locator('table:has(th:text-is("対策状況")) tbody tr')
  await expect(rows.first()).toBeVisible()
  await expect(rows.first()).toContainText('未対応')
  await expect(page.getByText(secret, { exact: false }), 'the secret itself is never shown').toHaveCount(0)
  await expect(page.getByRole('button', { name: '対策状況を変更' })).toHaveCount(0)
  await logout(page)

  watch.at('the admin changes the status with a note')
  await login(page, users.admin)
  await page.getByRole('link', { name: 'セキュリティ' }).click()
  await expect(rows.first()).toContainText('未対応')
  await rows.first().getByRole('button', { name: '対策状況を変更' }).click()
  const form = page.getByRole('form', { name: '対策状況の変更' })
  await form.getByLabel('新しい状態').selectOption('acknowledged')
  await form.getByLabel('メモ', { exact: false }).fill('担当 owner@example.com が確認 <img src=x onerror="window.pwned=1">')
  await form.getByRole('button', { name: '更新' }).click()
  await expect(rows.first()).toContainText('確認済み')
  await expect(rows.first(), 'the note comes back masked').toContainText('担当 [EMAIL_REDACTED] が確認')
  expect(await page.locator('main img, section img').count(), 'and as text').toBe(0)
  await watch.screenshot('security-findings.png')

  watch.at('the admin changes a limit')
  await page.getByRole('link', { name: '設定' }).click()
  const limits = page.getByRole('form', { name: 'API 利用制限' })
  await expect(limits).toBeVisible()
  const field = limits.getByLabel('利用者ごとの 1 日の分析回数上限')
  const before = Number(await field.inputValue())
  const after = before === 77 ? 78 : 77
  await field.fill(String(after))
  await limits.getByRole('button', { name: '保存' }).click()
  await expect(page.getByText('保存しました。')).toBeVisible()
  await expect(page.getByText('最終更新：', { exact: false })).toBeVisible()
  await page.reload()
  await expect(page.getByRole('form', { name: 'API 利用制限' }).getByLabel('利用者ごとの 1 日の分析回数上限')).toHaveValue(String(after))
  await watch.screenshot('settings.png')
  await logout(page)

  watch.at('a member changes their password and logs in with it')
  await login(page, users.extra)
  await page.getByRole('link', { name: '設定' }).click()
  const change = page.getByRole('form', { name: 'パスワードの変更' })
  const next = 'next pass phrase ' + crypto.randomUUID()
  await change.getByLabel('現在のパスワード').fill(users.extra.password)
  await change.getByLabel('新しいパスワード（12 文字以上', { exact: false }).fill(next)
  await change.getByLabel('新しいパスワード（確認）').fill(next)
  await change.getByRole('button', { name: '変更' }).click()
  await expect(page.getByText('パスワードを変更しました。', { exact: false })).toBeVisible()
  await logout(page)
  await page.getByLabel('メールアドレス').fill(users.extra.email)
  await page.getByLabel('パスワード').fill(users.extra.password)
  await page.getByRole('button', { name: 'ログイン' }).click()
  await expect(page.getByRole('alert'), 'the old password is refused').toBeVisible()
  await login(page, { email: users.extra.email, password: next })
})
