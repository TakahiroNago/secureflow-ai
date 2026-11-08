import { expect, login, logout, test, verifyChain } from '../fixtures'

/*
| E2E-06 (ST-06 on the screens): what each role is shown. An auditor reads and verifies the audit log but has no
| approvals, cannot make a workflow and cannot start the self-test; a member who opens the audit log by its address
| is told they may not, and is never shown the link.
*/

test('E2E-06: an auditor reads and verifies; a member is kept out of the audit log', async ({ page, users, watch }) => {
  watch.at('the auditor')
  await login(page, users.auditor)
  const nav = page.getByRole('navigation', { name: 'メイン' })
  await expect(nav.getByRole('link', { name: '監査ログ' })).toBeVisible()
  await expect(nav.getByRole('link', { name: '承認待ち' }), 'no approvals for an auditor').toHaveCount(0)
  await nav.getByRole('link', { name: 'ワークフロー', exact: true }).click()
  await expect(page.getByRole('link', { name: '新しく作成' }), 'an auditor makes nothing').toHaveCount(0)
  await nav.getByRole('link', { name: 'セキュリティ' }).click()
  await expect(page.getByRole('heading', { name: 'セキュリティ管理' })).toBeVisible()
  await expect(page.getByRole('button', { name: '自己診断を実行' }), 'and starts no self-test').toHaveCount(0)
  await expect(page.getByRole('button', { name: '対策状況を変更' }), 'and changes no status').toHaveCount(0)

  watch.at('the audit log as the auditor')
  await nav.getByRole('link', { name: '監査ログ' }).click()
  await expect(page.locator('td:text-is("auth.login")').first(), 'the auditor sees the records').toBeVisible()
  await verifyChain(page)
  await watch.screenshot('audit-log-auditor.png')
  await logout(page)

  watch.at('the member')
  await login(page, users.member)
  await expect(nav.getByRole('link', { name: '監査ログ' }), 'a member is never shown the link').toHaveCount(0)
  await page.goto('/audit-logs')
  await expect(page.getByRole('alert').filter({ hasText: 'この操作を行う権限がありません。' }), 'and is told so by its address').toBeVisible()
  await expect(page.locator('td:text-is("auth.login")'), 'with no record shown').toHaveCount(0)
})
