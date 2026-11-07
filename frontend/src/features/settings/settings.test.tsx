import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from '../../App'

/* SET-UI-01 (docs/test-strategy.md §30): the settings screen, the key that is never shown, and the password form's idempotency key. */

const user = (role: string) => ({
  id: '019a0000-0000-7000-8000-000000000001',
  name: 'Example User',
  email: 'user@example.com',
  role,
  organization: { id: '019a0000-0000-7000-8000-000000000002', name: 'Example Org' },
})

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const problem = (status: number, code: string, detail = 'x', extra = {}) => json({ type: 'about:blank', title: code, status, code, detail, trace_id: 't', ...extra }, status)

const ai = { provider: 'mock', model: null, api_key_configured: true, timeout_seconds: 30, max_output_tokens: 2000 }

const limits = (overrides = {}) => ({ monthly_token_limit: 1000000, user_daily_request_limit: 100, max_input_chars: 4000, updated_at: null, updated_by: null, ...overrides })

const security = {
  policy_version: '2026.11.1',
  ruleset_version: '2026.11.1/2026.11.2',
  prompt_version: '2026.11.2',
  input_actions: { pii: 'mask_continue', secret: 'block', masking_failure: 'block', injection: { low: 'record', medium: 'warn', high: 'block', critical: 'block' } },
  approval: { approver_role: 'admin', self_approval: 'forbidden', risk_acknowledgement_from: 'medium', decisions_per_revision: 1 },
}

function server(routes: Record<string, (init?: RequestInit) => Response>, role = 'admin') {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const key = `${init?.method ?? 'GET'} ${String(input as string)}`
    if (key === 'GET /api/health/live') {
      return Promise.resolve(json({ status: 'ok' }))
    }
    if (key === 'GET /api/v1/auth/me') {
      return Promise.resolve(json({ data: user(role) }))
    }
    if (key === 'GET /sanctum/csrf-cookie') {
      document.cookie = 'XSRF-TOKEN=token; path=/'
      return Promise.resolve(new Response(null, { status: 204 }))
    }
    const handler = routes[key]
    return handler ? Promise.resolve(handler(init)) : Promise.reject(new Error(`unexpected request: ${key}`))
  })
}

const adminRoutes = {
  'GET /api/v1/settings/ai': () => json({ data: ai }),
  'GET /api/v1/settings/limits': () => json({ data: limits() }),
  'GET /api/v1/settings/security': () => json({ data: security }),
}

function open(path: string) {
  window.history.pushState({}, '', path)
  render(<App />)
}

function fillPasswordForm(current: string, next: string, confirm = next) {
  fireEvent.change(screen.getByLabelText(/^現在のパスワード/), { target: { value: current } })
  fireEvent.change(screen.getByLabelText(/^新しいパスワード（12/), { target: { value: next } })
  fireEvent.change(screen.getByLabelText(/^新しいパスワード（確認）/), { target: { value: confirm } })
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function keyOf(call: Parameters<typeof fetch> | undefined): string {
  const headers = call?.[1]?.headers as Record<string, string> | undefined
  return headers?.['Idempotency-Key'] ?? ''
}

afterEach(() => {
  vi.restoreAllMocks()
  window.history.pushState({}, '', '/')
})

describe('the settings screen', () => {
  it('shows an admin the provider without the key, the limits and the policy', async () => {
    server(adminRoutes)
    open('/settings')

    expect(await screen.findByText('設定済み')).toBeInTheDocument()
    expect(screen.getByText('mock')).toBeInTheDocument()
    expect(screen.getByText('2026.11.1')).toBeInTheDocument()
    expect(screen.getByText('インジェクション（高）')).toBeInTheDocument()
    expect(screen.getByText(/自己承認は禁止/)).toBeInTheDocument()
    expect(screen.getByText('既定値を使用しています。')).toBeInTheDocument()
    expect(screen.getByLabelText('利用者ごとの 1 日の分析回数上限')).toHaveValue(100)
    expect(screen.getByRole('link', { name: '設定' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'セキュリティ' })).toBeInTheDocument()
  })

  it('sends only the limits that changed', async () => {
    const fetchSpy = server({
      ...adminRoutes,
      'PATCH /api/v1/settings/limits': () => json({ data: limits({ user_daily_request_limit: 5, updated_at: '2026-11-07T00:00:00Z', updated_by: { id: 'a', name: '管理者' } }) }),
    })
    open('/settings')
    const form = await screen.findByRole('form', { name: 'API 利用制限' })

    fireEvent.change(within(form).getByLabelText('利用者ごとの 1 日の分析回数上限'), { target: { value: '5' } })
    fireEvent.click(within(form).getByRole('button', { name: '保存' }))

    expect(await screen.findByText('保存しました。')).toBeInTheDocument()
    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    expect(JSON.parse(String(patch?.[1]?.body))).toEqual({ user_daily_request_limit: 5 })
  })

  it('refuses a limit out of range before sending it', async () => {
    const fetchSpy = server(adminRoutes)
    open('/settings')
    const form = await screen.findByRole('form', { name: 'API 利用制限' })

    fireEvent.change(within(form).getByLabelText('入力の最大文字数'), { target: { value: '20001' } })
    fireEvent.click(within(form).getByRole('button', { name: '保存' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('入力の最大文字数は 1 から 20000 までの整数で')
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false)
  })

  it('shows a member only the account section, and asks the server for nothing else', async () => {
    const fetchSpy = server({}, 'member')
    open('/settings')

    expect(await screen.findByRole('form', { name: 'パスワードの変更' })).toBeInTheDocument()
    expect(screen.queryByText('AI プロバイダ')).not.toBeInTheDocument()
    expect(screen.queryByText('API 利用制限')).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([input]) => String(input as string).startsWith('/api/v1/settings/'))).toBe(false)
  })

  it('changes the password with an idempotency key, and clears the form', async () => {
    const fetchSpy = server({ ...adminRoutes, 'PATCH /api/v1/account/password': () => json({ data: { password_changed_at: '2026-11-07T00:00:00Z' } }) })
    open('/settings')
    await screen.findByRole('form', { name: 'パスワードの変更' })

    fillPasswordForm('old password phrase', 'new password phrase 1')
    fireEvent.click(screen.getByRole('button', { name: 'パスワードを変更' }))

    expect(await screen.findByText(/パスワードを変更しました/)).toBeInTheDocument()
    const call = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    expect(keyOf(call)).toMatch(UUID)
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ current_password: 'old password phrase', new_password: 'new password phrase 1' })
    expect(screen.getByLabelText(/^現在のパスワード/)).toHaveValue('')
    expect(screen.getByLabelText(/^新しいパスワード（12/)).toHaveValue('')
  })

  it('keeps the key for a retry after a 503, and changes it when the content changes', async () => {
    const detail = 'パスワード変更の結果を確認できませんでした。同じ内容・同じ冪等性キーで再試行してください。'
    const fetchSpy = server({ ...adminRoutes, 'PATCH /api/v1/account/password': () => problem(503, 'SERVICE_UNAVAILABLE', detail) })
    open('/settings')
    await screen.findByRole('form', { name: 'パスワードの変更' })

    fillPasswordForm('old password phrase', 'new password phrase 1')
    fireEvent.click(screen.getByRole('button', { name: 'パスワードを変更' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(detail)
    fireEvent.click(screen.getByRole('button', { name: 'パスワードを変更' }))
    await waitFor(() => {
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(2)
    })

    fireEvent.change(screen.getByLabelText(/^現在のパスワード/), { target: { value: 'old password phrase 2' } })
    fireEvent.click(screen.getByRole('button', { name: 'パスワードを変更' }))
    await waitFor(() => {
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(3)
    })

    const keys = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH').map((call) => keyOf(call))
    expect(keys[0]).toMatch(UUID)
    expect(keys[1]).toBe(keys[0])
    expect(keys[2]).not.toBe(keys[0])
  })

  it('says what the server said about the password, and sends nothing when the confirmation differs', async () => {
    const fetchSpy = server({
      ...adminRoutes,
      'PATCH /api/v1/account/password': () => problem(422, 'CURRENT_PASSWORD_INVALID', '現在のパスワードが正しくありません。'),
    })
    open('/settings')
    await screen.findByRole('form', { name: 'パスワードの変更' })

    fillPasswordForm('old password phrase', 'new password phrase 1', 'something else entirely')
    fireEvent.click(screen.getByRole('button', { name: 'パスワードを変更' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('新しいパスワードが確認と一致しません。')
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false)

    fillPasswordForm('old password phrase', 'new password phrase 1')
    fireEvent.click(screen.getByRole('button', { name: 'パスワードを変更' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('現在のパスワードが正しくありません。')
  })
})
