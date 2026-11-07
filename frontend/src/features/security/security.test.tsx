import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from '../../App'

/* SEC-UI-01 (docs/test-strategy.md §30): the security screen draws everything as text, and only an admin can change a status. */

const user = (role: string) => ({
  id: '019a0000-0000-7000-8000-000000000001',
  name: 'Example User',
  email: 'user@example.com',
  role,
  organization: { id: '019a0000-0000-7000-8000-000000000002', name: 'Example Org' },
})

const finding = (overrides = {}) => ({
  id: '019a0000-0000-7000-8000-00000000000f',
  category: 'injection',
  rule_id: 'IJ-HEU-001',
  severity: 'medium',
  action: 'warn',
  message: '攻撃の可能性がある表現を検出しました',
  masked_excerpt: '<img src=x onerror=alert(1)>',
  field: null,
  status: 'open',
  status_note: null,
  status_changed_by: null,
  status_changed_at: null,
  created_at: '2026-11-07T00:00:00Z',
  scan: { id: 's', target_type: 'input', target_id: null, decision: 'warn', block_reason: null, max_severity: 'medium', created_at: '2026-11-07T00:00:00Z' },
  ...overrides,
})

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const problem = (status: number, code: string) => json({ type: 'about:blank', title: code, status, code, detail: 'x', trace_id: 't' }, status)

const page = (data: unknown[], next: string | null = null) => json({ data, meta: { next_cursor: next } })

function server(routes: Record<string, (init?: RequestInit) => Response>, role = 'member') {
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

function open(path: string) {
  window.history.pushState({}, '', path)
  render(<App />)
}

afterEach(() => {
  vi.restoreAllMocks()
  window.history.pushState({}, '', '/')
})

describe('the security screen', () => {
  it('draws the findings as text, with the notice, and a member cannot change anything', async () => {
    server({ 'GET /api/v1/security/findings': () => page([finding()]) })
    open('/security')

    expect(await screen.findByText('抜粋：<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
    expect(screen.getByText('攻撃の可能性がある表現を検出しました')).toBeInTheDocument()
    expect(within(screen.getByRole('table')).getByText('未対応')).toBeInTheDocument()
    expect(screen.getByText(/検出は完全ではなく/)).toBeInTheDocument()
    expect(screen.getByText(/自分の入力と計画に対する検出のみ/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '対策状況を変更' })).not.toBeInTheDocument()
    expect(screen.getByText(/未実装（アプリ内の自己診断は工程3-3/)).toBeInTheDocument()
  })

  it('sends the filters as the query, and nothing else', async () => {
    const fetchSpy = server({
      'GET /api/v1/security/findings': () => page([finding()]),
      'GET /api/v1/security/findings?severity=critical&status=resolved': () => page([]),
    })
    open('/security')
    await screen.findByText('未対応')

    fireEvent.change(screen.getByLabelText('重大度'), { target: { value: 'critical' } })
    fireEvent.change(screen.getByLabelText('対策状況'), { target: { value: 'resolved' } })
    fireEvent.click(screen.getByRole('button', { name: '絞り込む' }))

    expect(await screen.findByText(/該当する検出はありません/)).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledWith('/api/v1/security/findings?severity=critical&status=resolved', expect.anything())
  })

  it('lets an admin change a status with a note, and shows the result', async () => {
    let changed = false
    const fetchSpy = server(
      {
        'GET /api/v1/security/findings': () => page([changed ? finding({ status: 'acknowledged', status_note: '担当 [EMAIL_REDACTED]', status_changed_by: { id: 'a', name: '管理者' }, status_changed_at: '2026-11-07T01:00:00Z' }) : finding()]),
        'PATCH /api/v1/security/findings/019a0000-0000-7000-8000-00000000000f': () => {
          changed = true
          return json({ data: finding({ status: 'acknowledged' }) })
        },
      },
      'admin',
    )
    open('/security')

    fireEvent.click(await screen.findByRole('button', { name: '対策状況を変更' }))
    const form = screen.getByRole('form', { name: '対策状況の変更' })
    fireEvent.change(within(form).getByLabelText('新しい状態'), { target: { value: 'acknowledged' } })
    fireEvent.change(within(form).getByLabelText(/メモ/), { target: { value: '担当 a@example.com' } })
    fireEvent.click(within(form).getByRole('button', { name: '更新' }))

    expect(await screen.findByText('確認済み')).toBeInTheDocument()
    expect(screen.getByText('担当 [EMAIL_REDACTED]')).toBeInTheDocument()
    expect(screen.getByText(/管理者・2026-11-07T01:00:00Z/)).toBeInTheDocument()

    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    expect(patch).toBeDefined()
    expect(JSON.parse(String(patch?.[1]?.body))).toEqual({ status: 'acknowledged', status_note: '担当 a@example.com' })
  })

  it('offers only the next statuses, and says so when the server refuses the change', async () => {
    server(
      {
        'GET /api/v1/security/findings': () => page([finding({ status: 'resolved' })]),
        'PATCH /api/v1/security/findings/019a0000-0000-7000-8000-00000000000f': () => problem(409, 'INVALID_STATUS_TRANSITION'),
      },
      'admin',
    )
    open('/security')

    fireEvent.click(await screen.findByRole('button', { name: '対策状況を変更' }))
    const select = screen.getByLabelText('新しい状態')
    expect(within(select).getAllByRole('option').map((option) => option.textContent)).toEqual(['未対応'])

    fireEvent.click(screen.getByRole('button', { name: '更新' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('現在の対策状況からその状態には変更できません')
  })

  it('pages with the cursor', async () => {
    server({
      'GET /api/v1/security/findings': () => page([finding()], 'next'),
      'GET /api/v1/security/findings?cursor=next': () => page([finding({ id: 'second', message: '二件目' })]),
    })
    open('/security')

    fireEvent.click(await screen.findByRole('button', { name: 'さらに表示' }))

    expect(await screen.findByText('二件目')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'さらに表示' })).not.toBeInTheDocument()
    })
  })

  it('refuses a response of the wrong shape', async () => {
    server({ 'GET /api/v1/security/findings': () => page([{ ...finding(), status: 'deleted' }]) })
    open('/security')

    expect(await screen.findByRole('alert')).toHaveTextContent('処理に失敗しました')
  })
})
