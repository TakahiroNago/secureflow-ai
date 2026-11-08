import { analyseFromScreen, approveFromScreen, expect, login, logout, test } from '../fixtures'

/*
| E2E-02 (ST-09 on the screens): an edit after the approval puts the workflow back to a draft, the approval is gone
| and so is the button to run it; a second submission and approval are needed before it runs.
*/

test('E2E-02: an edit after the approval needs a new approval before it runs', async ({ page, users, watch }) => {
  watch.at('the member makes a workflow and submits it')
  await login(page, users.member)
  const workflowPath = await analyseFromScreen(page, '月次の請求書を確認する')
  await page.getByRole('button', { name: '承認を依頼する' }).click()
  await expect(page.getByText('承認待ち', { exact: true })).toBeVisible()
  await logout(page)

  watch.at('the admin approves it')
  await login(page, users.admin)
  await approveFromScreen(page, workflowPath)
  await logout(page)

  watch.at('the member edits the approved workflow')
  await login(page, users.member)
  await page.goto(workflowPath)
  await expect(page.getByText('承認済み', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: '編集' }).first().click()
  await page.getByLabel('タイトル').fill('承認の後に直した')
  await page.getByRole('button', { name: '保存' }).click()
  await expect(page.getByRole('heading', { name: '1. 承認の後に直した' })).toBeVisible()
  await expect(page.getByText('下書き', { exact: true }), 'it is a draft again').toBeVisible()
  await expect(page.getByText('承認済み', { exact: true }), 'the approval is gone').toHaveCount(0)
  await expect(page.getByRole('button', { name: '模擬実行する' }), 'and it cannot be run').toHaveCount(0)
  await expect(page.locator('dt:text-is("リビジョン") + dd'), 'the edit is a new revision').toHaveText('2')

  watch.at('the member submits it again')
  await page.getByRole('button', { name: '承認を依頼する' }).click()
  await expect(page.getByText('承認待ち', { exact: true })).toBeVisible()
  await logout(page)

  watch.at('the admin approves the new revision and runs it')
  await login(page, users.admin)
  await approveFromScreen(page, workflowPath)
  await expect(page.getByRole('heading', { name: '1. 承認の後に直した' }), 'what was approved is the edited plan').toBeVisible()
  await page.getByRole('button', { name: '模擬実行する' }).click()
  await expect(page.getByText('リビジョン 2：完了'), 'the new revision runs').toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('リビジョン 1：', { exact: false }), 'the first revision never ran').toHaveCount(0)
})
