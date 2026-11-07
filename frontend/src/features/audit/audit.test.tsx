import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from '../../App'

const user = (role: string) => ({
  id: '019a0000-0000-7000-8000-000000000001',
  name: 'Example User',
  email: 'user@example.com',
  role,
  organization: { id: '019a0000-0000-7000-8000-000000000002', name: 'Example Org' },
})

const entry = (overrides = {}) => ({
  event_id: '019a0000-0000-7000-8000-00000000000e',
  chain_seq: 7,
  event_type: 'approval.denied',
  result: 'denied',
  severity: 'medium',
  actor: { type: 'user', id: 'u', name: '申請者' },
  resource: { type: 'workflow', id: 'w' },
  ip_address: '203.0.113.10',
  request_id: 'r',
  metadata: { reason_code: 'SELF_APPROVAL_FORBIDDEN' },
  occurred_at: '2026-11-07T00:00:00Z',
  ...overrides,
})

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const page = (data: unknown[], next: string | null = null) => json({ data, meta: { next_cursor: next } })

function server(routes: Record<string, () => Response>, role = 'auditor') {
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
    return handler ? Promise.resolve(handler()) : Promise.reject(new Error(`unexpected request: ${key}`))
  })
}

function open(path: string) {
  window.history.pushState({}, '', path)
  render(<App />)
}

afterEach(() => {
  vi.restoreAllMocks()
  window.history.pushState({}, '', '/')
})

describe('the audit log screen', () => {
  it('shows the records', async () => {
    server({ 'GET /api/v1/audit-logs': () => page([entry()]) })
    open('/audit-logs')

    expect(await screen.findByText('申請者')).toBeInTheDocument()
    expect(screen.getAllByText('approval.denied')).toHaveLength(2)
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(screen.getByText('reason_code: SELF_APPROVAL_FORBIDDEN')).toBeInTheDocument()
  })

  it('says who it was when nobody is logged in, or it was the system', async () => {
    server({
      'GET /api/v1/audit-logs': () => page([entry({ event_id: 'a', actor: { type: 'system', id: null, name: null } }), entry({ event_id: 'b', actor: { type: 'anonymous', id: null, name: null } })]),
    })
    open('/audit-logs')

    expect(await screen.findByText('システム')).toBeInTheDocument()
    expect(screen.getByText('未認証')).toBeInTheDocument()
  })

  it('draws what was recorded as text', async () => {
    const markup = '<img src=x onerror=alert(1)>'
    server({ 'GET /api/v1/audit-logs': () => page([entry({ event_type: markup, actor: { type: 'user', id: 'u', name: markup }, metadata: { route: markup } })]) })
    open('/audit-logs')

    expect(await screen.findByText(`route: ${markup}`)).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
  })

  it('sends the filters, and whole days', async () => {
    const filtered = '/api/v1/audit-logs?event_type=authz.denied&result=denied&severity=low&from=2026-11-01T00%3A00%3A00Z&to=2026-11-07T23%3A59%3A59Z'
    const spy = server({ 'GET /api/v1/audit-logs': () => page([entry()]), [`GET ${filtered}`]: () => page([]) })
    open('/audit-logs')
    await screen.findByText('申請者')

    fireEvent.change(screen.getByLabelText('種類'), { target: { value: 'authz.denied' } })
    fireEvent.change(screen.getByLabelText('結果'), { target: { value: 'denied' } })
    fireEvent.change(screen.getByLabelText('重大度'), { target: { value: 'low' } })
    fireEvent.change(screen.getByLabelText('開始日（UTC）'), { target: { value: '2026-11-01' } })
    fireEvent.change(screen.getByLabelText('終了日（UTC）'), { target: { value: '2026-11-07' } })
    fireEvent.click(screen.getByRole('button', { name: '絞り込む' }))

    expect(await screen.findByText('該当する記録はありません。')).toBeInTheDocument()
    expect(spy.mock.calls.some(([input]) => String(input as string) === filtered)).toBe(true)
  })

  it('pages through', async () => {
    server({
      'GET /api/v1/audit-logs': () => page([entry()], 'next'),
      'GET /api/v1/audit-logs?cursor=next': () => page([entry({ event_id: 'older', chain_seq: 6 })]),
    })
    open('/audit-logs')

    fireEvent.click(await screen.findByRole('button', { name: 'さらに表示' }))

    expect(await screen.findByText('6')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'さらに表示' })).not.toBeInTheDocument()
  })

  it('always says what a verification cannot show', async () => {
    server({ 'GET /api/v1/audit-logs': () => page([]) })
    open('/audit-logs')

    expect(await screen.findByText('改ざんがないことの保証ではありません', { exact: false })).toBeInTheDocument()
  })

  it('does not call a good result proof', async () => {
    server({ 'GET /api/v1/audit-logs': () => page([]), 'POST /api/v1/audit-logs/verify': () => json({ data: { valid: true, checked_count: 51, first_broken_seq: null, reason_code: null } }) })
    open('/audit-logs')

    fireEvent.click(await screen.findByRole('button', { name: 'チェーンを検証' }))

    expect(await screen.findByText('矛盾は見つかりませんでした（51 件を確認）。')).toBeInTheDocument()
    expect(screen.getByText('改ざんがないことの保証ではありません', { exact: false })).toBeInTheDocument()
  })

  it('says where the chain broke', async () => {
    server({ 'GET /api/v1/audit-logs': () => page([]), 'POST /api/v1/audit-logs/verify': () => json({ data: { valid: false, checked_count: 2, first_broken_seq: 3, reason_code: 'HASH_MISMATCH' } }) })
    open('/audit-logs')

    fireEvent.click(await screen.findByRole('button', { name: 'チェーンを検証' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('3 番目')
    expect(alert).toHaveTextContent('HASH_MISMATCH')
  })

  it('says when verifying was refused for too many tries', async () => {
    server({
      'GET /api/v1/audit-logs': () => page([]),
      'POST /api/v1/audit-logs/verify': () => new Response(JSON.stringify({ code: 'RATE_LIMITED', detail: 'server text that is not shown' }), { status: 429 }),
    })
    open('/audit-logs')

    fireEvent.click(await screen.findByRole('button', { name: 'チェーンを検証' }))

    expect(await screen.findByText('回数の上限に達しました', { exact: false })).toBeInTheDocument()
    expect(screen.queryByText('server text that is not shown')).not.toBeInTheDocument()
  })

  it('refuses a response of the wrong shape', async () => {
    server({ 'GET /api/v1/audit-logs': () => json({ data: [{ event_id: 'x' }], meta: { next_cursor: null } }) })
    open('/audit-logs')

    expect(await screen.findByRole('alert')).toBeInTheDocument()
  })

  it('says it to a member, who is refused', async () => {
    server({ 'GET /api/v1/audit-logs': () => new Response(JSON.stringify({ code: 'FORBIDDEN' }), { status: 403 }) }, 'member')
    open('/audit-logs')

    expect(await screen.findByText('この操作を行う権限がありません。')).toBeInTheDocument()
  })

  it.each([
    ['admin', true],
    ['auditor', true],
    ['member', false],
  ])('is in the menu according to the role: %s', async (role, shown) => {
    server({ 'GET /api/v1/dashboard/summary': () => new Response(null, { status: 503 }) }, role)
    open('/')

    await waitFor(() => { expect(screen.getByRole('navigation', { name: 'メイン' })).toBeInTheDocument() })
    expect(screen.queryByRole('link', { name: '監査ログ' }) !== null).toBe(shown)
  })
})
