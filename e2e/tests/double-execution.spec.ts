import { analyseFromScreen, approveFromScreen, expect, login, logout, test } from '../fixtures'

/*
| E2E-03 (ST-22, docs/test-strategy.md §8): two requests to run the same approval at the same time, from the
| browser's own session, with two keys. One is accepted, the other is refused, and the history shows one execution.
*/

test('E2E-03: two execution requests at once make one execution', async ({ page, users, watch }) => {
  watch.at('a workflow is made, submitted and approved')
  await login(page, users.member)
  const workflowPath = await analyseFromScreen(page, '在庫の棚卸しの結果をまとめる')
  await page.getByRole('button', { name: '承認を依頼する' }).click()
  await expect(page.getByText('承認待ち', { exact: true })).toBeVisible()
  await logout(page)
  await login(page, users.admin)
  await approveFromScreen(page, workflowPath)

  watch.at('two requests at once')
  const executePath = `/api/v1${workflowPath}/execute`
  const statuses = await page.evaluate(async (path) => {
    const cookie = document.cookie.split('; ').find((c) => c.startsWith('XSRF-TOKEN='))
    const token = cookie === undefined ? '' : decodeURIComponent(cookie.slice('XSRF-TOKEN='.length))
    const send = () =>
      fetch(path, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-XSRF-TOKEN': token, 'Idempotency-Key': crypto.randomUUID() },
        body: '{}',
      }).then((response) => response.status)
    return Promise.all([send(), send()])
  }, executePath)
  const sorted = [...statuses].sort((a, b) => a - b)
  expect(sorted[0], 'one request is accepted').toBeLessThan(300)
  expect(sorted[1], 'the other is refused').toBe(409)

  watch.at('the history')
  await page.goto(workflowPath)
  await expect(page.getByText('リビジョン 1：完了')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByRole('region', { name: '実行の履歴' }).locator('li > p'), 'there is one execution').toHaveCount(1)
  await expect(page.getByRole('button', { name: '模擬実行する' })).toHaveCount(0)
})
