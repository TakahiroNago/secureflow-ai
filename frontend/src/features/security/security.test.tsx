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
    if (key === 'GET /api/v1/security/test-runs' && !(key in routes)) {
      return Promise.resolve(page([]))
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
    expect(await screen.findByText('まだ実行されていません。')).toBeInTheDocument()
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

describe('the self-test section', () => {
  const run = (overrides = {}) => ({
    id: '019a0000-0000-7000-8000-0000000000aa',
    status: 'completed',
    total: 25,
    passed: 25,
    failed: 0,
    ruleset_version: '2026.11.1/2026.11.2',
    policy_version: '2026.11.1',
    error_code: null,
    triggered_by: { id: 'a', name: '管理者' },
    created_at: '2026-11-08T00:00:00Z',
    started_at: '2026-11-08T00:00:01Z',
    finished_at: '2026-11-08T00:00:05Z',
    ...overrides,
  })
  const result = (overrides = {}) => ({
    case_id: 'ST-21',
    category: 'workflow',
    name: '自己承認（Policy と DB トリガー）',
    expected: 'アプリでも DB でも拒否される',
    actual: 'Policy と DB が拒否',
    passed: true,
    duration_ms: 12,
    details: {},
    ...overrides,
  })
  const detail = (overrides = {}, results: unknown[] = [result()]) => json({ data: { ...run(overrides), results, ci_only_cases: [{ case_id: 'ST-05', name: '未認証の API アクセスが 401 になる' }] } })

  it('shows a member the latest run, its results with failures first, and the CI-only cases, without a start button', async () => {
    server({
      'GET /api/v1/security/findings': () => page([]),
      'GET /api/v1/security/test-runs': () => page([run({ passed: 24, failed: 1 })]),
      'GET /api/v1/security/test-runs/019a0000-0000-7000-8000-0000000000aa': () =>
        detail({ passed: 24, failed: 1 }, [result(), result({ case_id: 'ST-08', name: '未承認の実行', actual: 'failed: verifier_refuses <b>x</b>', passed: false })]),
    })
    open('/security')

    expect(await screen.findByText('24 / 25 合格（1 件失敗）')).toBeInTheDocument()
    expect(screen.getByText('管理者')).toBeInTheDocument()
    const rows = within(screen.getByRole('table', { name: '自己診断の結果' })).getAllByRole('row').slice(1)
    expect(rows[0]).toHaveTextContent('ST-08')
    expect(rows[0]).toHaveTextContent('失敗')
    expect(screen.getByText('failed: verifier_refuses <b>x</b>')).toBeInTheDocument()
    expect(document.querySelector('b')).toBeNull()
    expect(screen.getByText(/CI でのみ検証するケース（1 件）/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '自己診断を実行' })).not.toBeInTheDocument()
  })

  it('says never run when there is no run', async () => {
    server({ 'GET /api/v1/security/findings': () => page([]), 'GET /api/v1/security/test-runs': () => page([]) })
    open('/security')
    expect(await screen.findByText('まだ実行されていません。')).toBeInTheDocument()
  })

  it('lets an admin start a run, then follows it until it completes', async () => {
    let polled = 0
    const fetchSpy = server(
      {
        'GET /api/v1/security/findings': () => page([]),
        'GET /api/v1/security/test-runs': () => page([]),
        'POST /api/v1/security/test-runs': () => json({ data: run({ status: 'queued', total: 0, passed: 0, failed: 0, finished_at: null, started_at: null }) }, 202),
        'GET /api/v1/security/test-runs/019a0000-0000-7000-8000-0000000000aa': () => {
          polled += 1
          return polled < 2 ? detail({ status: 'running', total: 0, passed: 3, failed: 0, finished_at: null }, []) : detail()
        },
      },
      'admin',
    )
    open('/security')

    fireEvent.click(await screen.findByRole('button', { name: '自己診断を実行' }))

    expect(await screen.findByText('実行中')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '自己診断を実行' })).toBeDisabled()
    expect(await screen.findByText('25 / 25 合格', {}, { timeout: 5000 })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '自己診断を実行' })).not.toBeDisabled()
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true)
  })

  it('says why a run cannot start', async () => {
    server(
      {
        'GET /api/v1/security/findings': () => page([]),
        'GET /api/v1/security/test-runs': () => page([run({ status: 'completed' })]),
        'GET /api/v1/security/test-runs/019a0000-0000-7000-8000-0000000000aa': () => detail(),
        'POST /api/v1/security/test-runs': () => problem(409, 'SELF_TEST_RUNNING'),
      },
      'admin',
    )
    open('/security')

    fireEvent.click(await screen.findByRole('button', { name: '自己診断を実行' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('自己診断を実行中です')
  })
})
