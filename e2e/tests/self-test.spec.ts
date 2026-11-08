import { expect, login, logout, test } from '../fixtures'

/*
| E2E-04 (SELFTEST-UI-01 on the real stack): an admin starts the self-test from the security screen, the worker runs
| the 26 cases, the screen follows it to the end and shows the results and the CI-only cases; the dashboard shows the
| latest result to a member, who has no button to start one.
*/

test('E2E-04: the self-test runs from the screen and every case passes', async ({ page, users, watch }) => {
  watch.at('the security screen before any run')
  await login(page, users.admin)
  await page.getByRole('link', { name: 'セキュリティ' }).click()
  await expect(page.getByRole('heading', { name: 'セキュリティ自己診断' })).toBeVisible()

  watch.at('the start')
  const start = page.getByRole('button', { name: '自己診断を実行' })
  await start.click()
  await expect(page.getByText('実行中です。結果は自動で更新されます。')).toBeVisible()
  await expect(start).toBeDisabled()

  watch.at('the completion')
  const latest = page.locator('dt:text-is("最新の結果") + dd')
  await expect(latest).toHaveText(/26 \/ 26 合格/, { timeout: 90_000 })
  await expect(latest).not.toContainText('失敗')
  await expect(start).toBeEnabled()
  const results = page.getByRole('table', { name: '自己診断の結果' })
  await expect(results.locator('tbody tr')).toHaveCount(26)
  await expect(results.locator('tbody tr').first()).toContainText('ST-')
  const ciOnly = page.locator('summary', { hasText: 'CI でのみ検証するケース（13 件）' })
  await expect(ciOnly).toBeVisible()
  await ciOnly.click()
  await expect(page.getByText('ST-05：', { exact: false })).toBeVisible()
  await watch.screenshot('security-self-test.png')

  watch.at('the dashboard tile')
  await page.getByRole('link', { name: 'ダッシュボード' }).click()
  await expect(page.locator('dt:text-is("自己診断") + dd')).toContainText('26 / 26 合格')
  await logout(page)

  watch.at('a member sees the result and cannot start one')
  await login(page, users.member)
  await page.getByRole('link', { name: 'セキュリティ' }).click()
  await expect(page.locator('dt:text-is("最新の結果") + dd')).toContainText('26 / 26 合格')
  await expect(page.getByRole('button', { name: '自己診断を実行' })).toHaveCount(0)
})
