import { test as base, expect, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'

/**
 * Users created by scripts/test-e2e.sh on the throwaway stack: one set per browser project, so that the counts a
 * flow checks (its own workflows, its own findings) are its own.
 */
export interface Credentials {
  email: string
  password: string
}

export interface UserSet {
  member: Credentials
  admin: Credentials
  auditor: Credentials
  /** A member of its own for the password change, which no other flow may share. */
  extra: Credentials
}

function loadUsers(): Record<string, UserSet> {
  const path = process.env['E2E_USERS']
  if (path === undefined) throw new Error('E2E_USERS is not set: run through scripts/test-e2e.sh')
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, UserSet>
}

/** What a page must never do, collected from the start of the test: a CSP violation, an uncaught error. */
export class PageWatch {
  readonly violations: string[] = []
  readonly errors: string[] = []
  private step = 'the start'
  private shooting = false

  constructor(private readonly page: Page) {
    // A page that breaks the CSP goes on working, so this has to be looked for.
    page.on('console', (message) => {
      if (/Content.Security.Policy/i.test(message.text()) && !this.shooting) {
        this.violations.push(`after "${this.step}" on ${new URL(page.url()).pathname}: ${message.text().slice(0, 160)}`)
      }
    })
    page.on('pageerror', (error) => this.errors.push(`after "${this.step}": ${String(error)}`))
  }

  at(step: string): void {
    this.step = step
  }

  /** A screenshot in WebKit adds a <style> of Playwright's own, which the CSP refuses as it should: not the app's. */
  async screenshot(path: string): Promise<void> {
    this.shooting = true
    try {
      await this.page.screenshot({ path: `output/screenshots/${path}`, fullPage: true })
      await this.page.waitForTimeout(200)
    } finally {
      this.shooting = false
    }
  }

  assertClean(): void {
    expect(this.errors, 'nothing failed on the page').toEqual([])
    expect(this.violations, 'the CSP was never broken, on any screen').toEqual([])
  }
}

export const test = base.extend<{ users: UserSet; watch: PageWatch }>({
  users: async ({}, use, testInfo) => {
    const all = loadUsers()
    const set = all[testInfo.project.name]
    if (set === undefined) throw new Error(`no users for project ${testInfo.project.name}`)
    await use(set)
  },
  watch: async ({ page }, use) => {
    const watch = new PageWatch(page)
    await use(watch)
    watch.assertClean()
  },
})

export { expect }

export async function login(page: Page, user: Credentials): Promise<void> {
  await page.goto('/login')
  await page.getByRole('heading', { name: 'ログイン' }).waitFor()
  await page.getByLabel('メールアドレス').fill(user.email)
  await page.getByLabel('パスワード').fill(user.password)
  await page.getByRole('button', { name: 'ログイン' }).click()
  await expect(page.getByRole('heading', { name: 'ダッシュボード' })).toBeVisible({ timeout: 15_000 })
}

export async function logout(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'ログアウト' }).click()
  await expect(page.getByRole('heading', { name: 'ログイン' })).toBeVisible()
}

/** A request from the page itself, with the session cookie and the CSRF token the app would send. */
export async function apiFromPage(page: Page, method: string, path: string, headers: Record<string, string> = {}): Promise<{ status: number; body: unknown }> {
  return page.evaluate(
    async ({ method, path, headers }) => {
      const cookie = document.cookie.split('; ').find((c) => c.startsWith('XSRF-TOKEN='))
      const token = cookie === undefined ? '' : decodeURIComponent(cookie.slice('XSRF-TOKEN='.length))
      const response = await fetch(path, {
        method,
        credentials: 'same-origin',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-XSRF-TOKEN': token, ...headers },
        body: method === 'GET' ? undefined : '{}',
      })
      return { status: response.status, body: (await response.json().catch(() => null)) as unknown }
    },
    { method, path, headers },
  )
}

/** A workflow from an ordinary request, on the real screens with the real worker: the detail page's path. */
export async function analyseFromScreen(page: Page, request: string): Promise<string> {
  await page.getByRole('link', { name: 'ワークフロー', exact: true }).click()
  await page.getByRole('link', { name: '新しく作成' }).click()
  await page.getByLabel('依頼内容').fill(request)
  await page.getByRole('button', { name: '分析する' }).click()
  await expect(page.getByRole('button', { name: '編集' }).first()).toBeVisible({ timeout: 30_000 })
  const path = new URL(page.url()).pathname
  expect(path).toMatch(/^\/workflows\/[0-9a-f-]{36}$/)
  return path
}

/**
 * Verifies the organization's chain from the audit log screen. The verification is limited to three a minute per
 * organization, and the browsers of one run share an organization: on the limit's answer it waits and tries again.
 */
export async function verifyChain(page: Page): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    await page.getByRole('button', { name: 'チェーンを検証' }).click()
    const outcome = page.getByText('矛盾は見つかりませんでした', { exact: false }).or(page.getByRole('alert').filter({ hasText: '回数の上限に達しました' }))
    await expect(outcome.first()).toBeVisible({ timeout: 15_000 })
    if (await page.getByText('矛盾は見つかりませんでした', { exact: false }).isVisible()) return
    expect(attempt, 'the verification limit does not lift').toBeLessThan(5)
    await page.waitForTimeout(21_000)
  }
}

/** The admin decides on what waits, on the approval screen. */
export async function approveFromScreen(page: Page, workflowPath: string): Promise<void> {
  await page.goto(`${workflowPath}/approval`)
  const approve = page.getByRole('button', { name: '承認する' })
  await expect(approve).toBeVisible()
  if (await page.getByRole('checkbox').count()) await page.getByRole('checkbox').check()
  await approve.click()
  await expect(page.getByText('承認済み', { exact: true })).toBeVisible()
}
