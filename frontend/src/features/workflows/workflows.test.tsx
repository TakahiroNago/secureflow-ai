import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from '../../App'

const WORKFLOW_ID = '019a0000-0000-7000-8000-00000000000a'
const TASK_ID = '019a0000-0000-7000-8000-00000000000b'
const ANALYSIS_ID = '019a0000-0000-7000-8000-00000000000c'

const user = (role = 'member') => ({
  id: '019a0000-0000-7000-8000-000000000001',
  name: 'Example User',
  email: 'user@example.com',
  role,
  organization: { id: '019a0000-0000-7000-8000-000000000002', name: 'Example Org' },
})

const scan = { status: 'not_scanned', decision: null, limitations_notice: '検出は完全ではありません。' }

const task = (overrides = {}) => ({
  id: TASK_ID,
  position: 1,
  title: '問い合わせの要約',
  description: '問い合わせ内容を要約する。',
  action_type: 'text.summarize',
  steps: ['内容を読む', '要点をまとめる'],
  priority: 'medium',
  target_data: '問い合わせ本文',
  impact_summary: '外部への影響はない。',
  derived_permissions: ['ai.text.read'],
  policy_decision: 'allowed',
  ...overrides,
})

const workflow = (overrides = {}) => ({
  id: WORKFLOW_ID,
  title: '問い合わせの要約',
  status: 'draft',
  created_by: { id: 'u', name: 'Example User' },
  current_revision: { no: 3, plan_hash: 'a'.repeat(64), policy_version: '2026.11.1' },
  scan,
  can_edit: true,
  tasks: [task()],
  ...overrides,
})

const analysis = (overrides = {}) => ({ id: ANALYSIS_ID, status: 'queued', workflow_id: null, error_code: null, scan, ...overrides })

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const problem = (status: number, code: string) =>
  new Response(JSON.stringify({ type: 'x', title: 'x', status, code, detail: 'server text that is not shown' }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  })

type Handler = (init: RequestInit | undefined) => Response

function server(routes: Record<string, Handler>, role = 'member') {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const key = `${init?.method ?? 'GET'} ${String(input as string)}`
    if (key === 'GET /api/health/live') {
      return Promise.resolve(json({ status: 'ok' }))
    }
    if (key === 'GET /api/v1/auth/me') {
      return Promise.resolve(json({ data: user(role) }))
    }
    if (key === 'GET /sanctum/csrf-cookie') {
      document.cookie = 'XSRF-TOKEN=token%3Dvalue; path=/'
      return Promise.resolve(new Response(null, { status: 204 }))
    }
    const handler = routes[key]
    if (!handler) {
      return Promise.reject(new Error(`unexpected request: ${key}`))
    }
    return Promise.resolve(handler(init))
  })
}

const callsTo = (spy: ReturnType<typeof server>, key: string) =>
  spy.mock.calls.filter(([input, init]) => `${init?.method ?? 'GET'} ${String(input as string)}` === key)

function open(path: string) {
  window.history.pushState({}, '', path)
  render(<App />)
}

const headersOf = (call: Parameters<typeof fetch>) => call[1]?.headers as Record<string, string>

afterEach(() => {
  vi.restoreAllMocks()
  window.history.pushState({}, '', '/')
})

describe('new analysis', () => {
  it('always warns that nothing is scanned', async () => {
    server({})
    open('/analyses/new')

    expect(await screen.findByRole('alert')).toHaveTextContent('機密情報や個人情報を入力しないでください')
  })

  it('sends the input, waits, and opens the workflow it created', async () => {
    let polls = 0
    const spy = server({
      'POST /api/v1/analyses': () => json({ data: analysis() }, 202),
      [`GET /api/v1/analyses/${ANALYSIS_ID}`]: () => {
        polls += 1
        return json({ data: polls < 2 ? analysis({ status: 'processing' }) : analysis({ status: 'succeeded', workflow_id: WORKFLOW_ID }) })
      },
      [`GET /api/v1/workflows/${WORKFLOW_ID}`]: () => json({ data: workflow() }),
    })
    open('/analyses/new')

    fireEvent.change(await screen.findByLabelText('依頼内容'), { target: { value: '毎週の報告を作成' } })
    fireEvent.click(screen.getByRole('button', { name: '分析する' }))

    expect(await screen.findByText('作成しています', { exact: false })).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: '問い合わせの要約', level: 2 }, { timeout: 4000 })).toBeInTheDocument()

    const body = callsTo(spy, 'POST /api/v1/analyses')[0]?.[1]?.body
    expect(body).toBe(JSON.stringify({ input: '毎週の報告を作成' }))
  })

  it('says what went wrong with a fixed sentence, not what the server wrote', async () => {
    server({ 'POST /api/v1/analyses': () => problem(429, 'RATE_LIMITED') })
    open('/analyses/new')

    fireEvent.change(await screen.findByLabelText('依頼内容'), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: '分析する' }))

    expect(await screen.findByText('回数の上限に達しました', { exact: false })).toBeInTheDocument()
    expect(screen.queryByText('server text that is not shown')).not.toBeInTheDocument()
  })

  it('stops polling when the analysis has failed', async () => {
    const spy = server({
      [`GET /api/v1/analyses/${ANALYSIS_ID}`]: () => json({ data: analysis({ status: 'failed', error_code: 'AI_INVALID_OUTPUT' }) }),
    })
    open(`/analyses/${ANALYSIS_ID}`)

    expect(await screen.findByText('正しい形式ではなかった', { exact: false })).toBeInTheDocument()

    await new Promise((resolve) => setTimeout(resolve, 1200))
    expect(callsTo(spy, `GET /api/v1/analyses/${ANALYSIS_ID}`)).toHaveLength(1)
  })

  it('does not show the same fixed text for an unknown error code as for a known one, and never the code alone', async () => {
    server({
      [`GET /api/v1/analyses/${ANALYSIS_ID}`]: () => json({ data: analysis({ status: 'failed', error_code: '<img src=x onerror=alert(1)>' }) }),
    })
    open(`/analyses/${ANALYSIS_ID}`)

    expect(await screen.findByText('分析に失敗しました', { exact: false })).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
  })

  it('treats a response of the wrong shape as an error', async () => {
    server({ [`GET /api/v1/analyses/${ANALYSIS_ID}`]: () => json({ data: { id: ANALYSIS_ID, status: 'surprise' } }) })
    open(`/analyses/${ANALYSIS_ID}`)

    expect(await screen.findByText('処理に失敗しました', { exact: false })).toBeInTheDocument()
  })
})

describe('list', () => {
  const summary = { id: WORKFLOW_ID, title: '一覧の項目', status: 'draft', revision_no: 1, created_by: { id: 'u', name: '作成者' }, created_at: null, updated_at: null }

  it('shows the workflows and fetches the next page with its cursor', async () => {
    const spy = server({
      'GET /api/v1/workflows': () => json({ data: [summary], meta: { next_cursor: 'abc=' } }),
      'GET /api/v1/workflows?cursor=abc%3D': () => json({ data: [{ ...summary, id: 'other', title: '次の項目' }], meta: { next_cursor: null } }),
    })
    open('/workflows')

    expect(await screen.findByRole('link', { name: '一覧の項目' })).toHaveAttribute('href', `/workflows/${WORKFLOW_ID}`)
    fireEvent.click(screen.getByRole('button', { name: 'さらに表示' }))
    expect(await screen.findByRole('link', { name: '次の項目' })).toBeInTheDocument()
    expect(callsTo(spy, 'GET /api/v1/workflows?cursor=abc%3D')).toHaveLength(1)
    expect(screen.queryByRole('button', { name: 'さらに表示' })).not.toBeInTheDocument()
  })

  it('does not offer creating to an auditor', async () => {
    server({ 'GET /api/v1/workflows': () => json({ data: [], meta: { next_cursor: null } }) }, 'auditor')
    open('/workflows')

    expect(await screen.findByText('ワークフローはまだありません。')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '新しく作成' })).not.toBeInTheDocument()
  })
})

describe('detail', () => {
  const detailPath = `/workflows/${WORKFLOW_ID}`
  const detailKey = `GET /api/v1/workflows/${WORKFLOW_ID}`
  const putKey = `PUT /api/v1/workflows/${WORKFLOW_ID}/tasks/${TASK_ID}`

  it('shows that it is not scanned, with the notice', async () => {
    server({ [detailKey]: () => json({ data: workflow() }) })
    open(detailPath)

    expect(await screen.findByText('未検査')).toBeInTheDocument()
    expect(screen.getByText('検出は完全ではありません。')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('入力検査は未実装です')
  })

  it('draws what the AI or a user wrote as text, never as markup', async () => {
    const attack = '<img src=x onerror="window.pwned=1"><script>window.pwned=1</script>'
    server({
      [detailKey]: () =>
        json({
          data: workflow({
            title: attack,
            tasks: [task({ title: attack, description: attack, steps: [attack], target_data: attack, impact_summary: attack })],
          }),
        }),
    })
    open(detailPath)

    expect(await screen.findByRole('heading', { name: attack, level: 2 })).toBeInTheDocument()
    expect(screen.getAllByText(attack, { exact: false }).length).toBeGreaterThan(3)
    expect(document.querySelector('img')).toBeNull()
    expect(document.querySelector('script')).toBeNull()
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined()
  })

  it('marks a forbidden action', async () => {
    server({ [detailKey]: () => json({ data: workflow({ tasks: [task({ policy_decision: 'forbidden', action_type: 'shell.exec' })] }) }) })
    open(detailPath)

    expect(await screen.findByText('禁止された操作')).toBeInTheDocument()
  })

  it('offers no editing when the server says so', async () => {
    server({ [detailKey]: () => json({ data: workflow({ can_edit: false }) }) })
    open(detailPath)

    await screen.findByText('未検査')
    expect(screen.queryByRole('button', { name: '編集' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'タスクを追加' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '名前を変更' })).not.toBeInTheDocument()
  })

  it('saves an edit with the revision it was based on, and only the fields a client may set', async () => {
    const spy = server({
      [detailKey]: () => json({ data: workflow() }),
      [putKey]: () => json({ data: workflow({ current_revision: { no: 4, plan_hash: 'b'.repeat(64), policy_version: '2026.11.1' }, tasks: [task({ title: '変更後' })] }) }),
    })
    open(detailPath)

    fireEvent.click(await screen.findByRole('button', { name: '編集' }))
    fireEvent.change(screen.getByLabelText('タイトル'), { target: { value: '変更後' } })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByRole('heading', { name: '1. 変更後' })).toBeInTheDocument()

    const call = callsTo(spy, putKey)[0]
    expect(call).toBeDefined()
    expect(headersOf(call as Parameters<typeof fetch>)['If-Match']).toBe('"3"')

    const sent = JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>
    expect(Object.keys(sent).sort()).toEqual(['action_type', 'description', 'impact_summary', 'priority', 'steps', 'target_data', 'title'])
    expect(sent.steps).toEqual(['内容を読む', '要点をまとめる'])
  })

  it('keeps what was typed and reloads when someone else saved first', async () => {
    const spy = server({ [detailKey]: () => json({ data: workflow() }), [putKey]: () => problem(409, 'REVISION_CONFLICT') })
    open(detailPath)

    fireEvent.click(await screen.findByRole('button', { name: '編集' }))
    fireEvent.change(screen.getByLabelText('タイトル'), { target: { value: '入力した内容' } })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('他の変更が先に保存されました', { exact: false })).toBeInTheDocument()
    expect(screen.getByLabelText('タイトル')).toHaveValue('入力した内容')
    await waitFor(() => {
      expect(callsTo(spy, detailKey).length).toBeGreaterThan(1)
    })
  })

  it('does not let the last task be deleted from the screen, and deletes with If-Match otherwise', async () => {
    const second = task({ id: 'second', position: 2, title: '二番目' })
    const deleteKey = `DELETE /api/v1/workflows/${WORKFLOW_ID}/tasks/${TASK_ID}`
    const spy = server({
      [detailKey]: () => json({ data: workflow({ tasks: [task(), second] }) }),
      [deleteKey]: () => json({ data: workflow({ tasks: [{ ...second, position: 1 }] }) }),
    })
    open(detailPath)

    const buttons = await screen.findAllByRole('button', { name: '削除' })
    fireEvent.click(buttons[0] as HTMLElement)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: '削除' })).toBeDisabled()
    })
    expect(headersOf(callsTo(spy, deleteKey)[0] as Parameters<typeof fetch>)['If-Match']).toBe('"3"')
  })

  it('adds a task and renames the workflow, each with If-Match', async () => {
    const postKey = `POST /api/v1/workflows/${WORKFLOW_ID}/tasks`
    const patchKey = `PATCH /api/v1/workflows/${WORKFLOW_ID}`
    const spy = server({
      [detailKey]: () => json({ data: workflow() }),
      [postKey]: () => json({ data: workflow({ tasks: [task(), task({ id: 'n', position: 2, title: '追加分' })] }) }, 201),
      [patchKey]: () => json({ data: workflow({ title: '新しい名前' }) }),
    })
    open(detailPath)

    fireEvent.click(await screen.findByRole('button', { name: 'タスクを追加' }))
    fireEvent.change(screen.getByLabelText('タイトル'), { target: { value: '追加分' } })
    fireEvent.change(screen.getByLabelText('説明'), { target: { value: '説明' } })
    fireEvent.change(screen.getByLabelText('手順（1行に1つ）'), { target: { value: '一\n\n二' } })
    fireEvent.change(screen.getByLabelText('対象データ'), { target: { value: '対象' } })
    fireEvent.change(screen.getByLabelText('影響'), { target: { value: '影響' } })
    fireEvent.click(screen.getByRole('button', { name: '追加' }))

    expect(await screen.findByRole('heading', { name: '2. 追加分' })).toBeInTheDocument()
    const sent = JSON.parse(String(callsTo(spy, postKey)[0]?.[1]?.body)) as { steps: string[] }
    expect(sent.steps).toEqual(['一', '二'])

    fireEvent.click(screen.getByRole('button', { name: '名前を変更' }))
    fireEvent.change(screen.getByLabelText('ワークフロー名'), { target: { value: '新しい名前' } })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByRole('heading', { name: '新しい名前', level: 2 })).toBeInTheDocument()
    expect(headersOf(callsTo(spy, patchKey)[0] as Parameters<typeof fetch>)['If-Match']).toBe('"3"')
  })

  it('says not found for a workflow the server hides', async () => {
    server({ [detailKey]: () => problem(404, 'NOT_FOUND') })
    open(detailPath)

    expect(await screen.findByText('対象が見つかりません。')).toBeInTheDocument()
  })
})
