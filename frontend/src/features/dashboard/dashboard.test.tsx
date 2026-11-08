import { fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from '../../App'

const user = {
  id: '019a0000-0000-7000-8000-000000000001',
  name: 'Example User',
  email: 'user@example.com',
  role: 'member',
  organization: { id: '019a0000-0000-7000-8000-000000000002', name: 'Example Org' },
}

const summary = (overrides = {}) => ({
  workflows: { total: 6, by_status: { draft: 3, pending: 2, approved: 0, running: 0, completed: 1, rejected: 0, failed: 0 } },
  executed: 1,
  pending_approval: 2,
  analyses_this_month: 5,
  security: { warnings: null, findings: null, available_from_step: '2-3' },
  ai_usage: { tokens: null, estimated_cost: null, available_from_step: '2-8' },
  self_test: { latest: null },
  recent_operations: [
    { id: 'a', event_type: 'workflow.updated', actor: { id: 'u', name: '操作した人' }, resource_type: 'workflow', resource_id: 'wf-1', result: 'success', occurred_at: '2026-11-06T07:00:00Z' },
    { id: 'b', event_type: 'auth.login', actor: { id: 'u', name: '操作した人' }, resource_type: null, resource_id: null, result: 'success', occurred_at: '2026-11-06T06:00:00Z' },
  ],
  ...overrides,
})

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function server(dashboard: () => Response) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const key = `${init?.method ?? 'GET'} ${String(input as string)}`
    const responses: Record<string, () => Response> = {
      'GET /api/health/live': () => json({ status: 'ok' }),
      'GET /api/v1/auth/me': () => json({ data: user }),
      'GET /api/v1/dashboard/summary': dashboard,
    }
    const handler = responses[key]
    return handler ? Promise.resolve(handler()) : Promise.reject(new Error(`unexpected request: ${key}`))
  })
}

const tile = (label: string) => screen.getByText(label).parentElement as HTMLElement

afterEach(() => {
  vi.restoreAllMocks()
})

describe('dashboard', () => {
  it('shows the numbers from the server', async () => {
    server(() => json({ data: summary() }))
    render(<App />)

    await screen.findByText('ワークフロー数')
    expect(within(tile('ワークフロー数')).getByText('6')).toBeInTheDocument()
    expect(within(tile('実行済みワークフロー')).getByText('1')).toBeInTheDocument()
    expect(within(tile('承認待ちワークフロー')).getByText('2')).toBeInTheDocument()
    expect(within(tile('今月の分析回数')).getByText('5')).toBeInTheDocument()
  })

  it('says not implemented for what does not exist yet, and never a zero', async () => {
    server(() => json({ data: summary() }))
    render(<App />)

    await screen.findByText('セキュリティ警告')
    for (const label of ['セキュリティ警告', '検出されたリスク', 'AI トークン', 'AI 推定費用']) {
      expect(within(tile(label)).getByText('未実装')).toBeInTheDocument()
      expect(within(tile(label)).queryByText('0')).not.toBeInTheDocument()
    }
  })

  it('shows a real zero as a zero', async () => {
    server(() => json({ data: summary({ executed: 0 }) }))
    render(<App />)

    await screen.findByText('実行済みワークフロー')
    expect(within(tile('実行済みワークフロー')).getByText('0')).toBeInTheDocument()
  })

  it('has every count of the chart in a table too, in the order of a workflow\'s life', async () => {
    server(() => json({ data: summary() }))
    render(<App />)

    const table = await screen.findByRole('table', { hidden: true })
    const rows = within(table).getAllByRole('row', { hidden: true }).slice(1)

    expect(rows.map((row) => row.textContent)).toEqual(['下書き3', '承認待ち2', '承認済み0', '実行中0', '完了1', '却下0', '失敗0'])
    fireEvent.click(screen.getByText('表で見る'))
  })

  it('has no chart to draw when there is nothing', async () => {
    server(() => json({ data: summary({ workflows: { total: 0, by_status: { draft: 0, pending: 0, approved: 0, running: 0, completed: 0, rejected: 0, failed: 0 } } }) }))
    render(<App />)

    expect(await screen.findByText('ワークフローはまだありません。')).toBeInTheDocument()
    expect(screen.queryByText('表で見る')).not.toBeInTheDocument()
  })

  it('lists recent operations, linking to the workflow, and draws names as text', async () => {
    const attack = '<img src=x onerror="window.pwned=1">'
    server(() =>
      json({
        data: summary({
          recent_operations: [{ id: 'a', event_type: 'workflow.updated', actor: { id: 'u', name: attack }, resource_type: 'workflow', resource_id: 'wf-1', result: 'success', occurred_at: '2026-11-06T07:00:00Z' }],
        }),
      }),
    )
    render(<App />)

    expect(await screen.findByRole('link', { name: 'ワークフローを更新' })).toHaveAttribute('href', '/workflows/wf-1')
    expect(screen.getByText(attack)).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
  })

  it('shows an unknown event with a fixed word, not what the server sent', async () => {
    server(() =>
      json({
        data: summary({
          recent_operations: [{ id: 'a', event_type: '<b>odd</b>', actor: null, resource_type: null, resource_id: null, result: 'success', occurred_at: '2026-11-06T07:00:00Z' }],
        }),
      }),
    )
    render(<App />)

    expect(await screen.findByText('操作')).toBeInTheDocument()
    expect(screen.queryByText('<b>odd</b>')).not.toBeInTheDocument()
  })

  it('treats a response of the wrong shape as an error, and shows no numbers', async () => {
    server(() => json({ data: { workflows: { total: 'many' } } }))
    render(<App />)

    expect(await screen.findByRole('alert')).toHaveTextContent('処理に失敗しました')
    expect(screen.queryByText('ワークフロー数')).not.toBeInTheDocument()
  })

  it('treats a missing null as an error rather than as a zero', async () => {
    const withoutSecurity = summary() as Record<string, unknown>
    delete withoutSecurity.security
    server(() => json({ data: withoutSecurity }))
    render(<App />)

    expect(await screen.findByRole('alert')).toBeInTheDocument()
  })

  it('names the user, the role and the organization around the screen', async () => {
    server(() => json({ data: summary() }))
    render(<App />)

    expect(await screen.findByText('Example User（メンバー）・Example Org')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'ワークフロー' })).toHaveAttribute('href', '/workflows')
  })
})

describe('the self-test tile', () => {
  it('says never run, and then the latest result as a link to the security screen', async () => {
    server(() => json({ data: summary() }))
    render(<App />)
    expect(await screen.findByText('未実施')).toBeInTheDocument()
  })

  it('shows the passed count, and failures in red', async () => {
    server(() => json({ data: summary({ self_test: { latest: { id: 'r', status: 'completed', total: 25, passed: 24, failed: 1, finished_at: '2026-11-08T00:00:00Z' } } }) }))
    render(<App />)
    const link = await screen.findByRole('link', { name: '24 / 25 合格（1 件失敗）' })
    expect(link).toHaveAttribute('href', '/security')
    expect(link.parentElement).toHaveClass('text-red-700')
  })

  it('refuses a result of the wrong shape', async () => {
    server(() => json({ data: summary({ self_test: { latest: { id: 'r', status: 'done', total: 1, passed: 1, failed: 0, finished_at: null } } }) }))
    render(<App />)
    expect(await screen.findByRole('alert')).toHaveTextContent('処理に失敗しました')
  })
})
