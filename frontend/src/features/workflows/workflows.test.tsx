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

const NOTICE = '検出は完全ではありません。'

const notScanned = { status: 'not_scanned', decision: null, block_reason: null, max_severity: null, masking_status: null, findings: [], findings_count: 0, limitations_notice: NOTICE }

const scan = { ...notScanned, status: 'scanned', decision: 'allow', masking_status: 'not_required' }

const finding = (overrides = {}) => ({
  category: 'pii',
  rule_id: 'PII-EMAIL',
  severity: 'medium',
  action: 'mask_continue',
  message: 'メールアドレスを検出しマスキングしました',
  field: null,
  position_start: 3,
  position_end: 19,
  ...overrides,
})

const blockedBody = (overrides = {}) => ({
  ...scan,
  decision: 'block',
  block_reason: 'SECRET_DETECTED',
  max_severity: 'critical',
  findings: [finding({ category: 'secret', rule_id: 'SEC-APIKEY', severity: 'critical', action: 'block', message: 'APIキー形式の文字列を検出しました', position_start: 2, position_end: 8 })],
  findings_count: 1,
  ...overrides,
})

const refused = (body: unknown) =>
  new Response(JSON.stringify({ type: 'x', title: 'x', status: 422, code: 'INPUT_BLOCKED', detail: 'server text that is not shown', scan: body }), {
    status: 422,
    headers: { 'Content-Type': 'application/problem+json' },
  })

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
  max_severity: null,
  can_edit: true,
  can_submit: false,
  can_reopen: false,
  can_view_approval: false,
  approver_available: true,
  decision: null,
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
  it('says before anything is typed that detection is not complete, and does not claim nothing is scanned', async () => {
    server({})
    open('/analyses/new')

    expect(await screen.findByText('検出は完全ではないため', { exact: false })).toBeInTheDocument()
    expect(screen.queryByText('未実装', { exact: false })).not.toBeInTheDocument()
  })

  it('shows what would be kept, and what was found, before sending anything to the AI', async () => {
    const spy = server({
      'POST /api/v1/security/scan-preview': () =>
        json({ data: { ...scan, masking_status: 'masked', masked_input: '担当 [EMAIL_REDACTED] の件', findings: [finding()], findings_count: 1, max_severity: 'medium' } }),
    })
    open('/analyses/new')

    fireEvent.change(await screen.findByLabelText('依頼内容'), { target: { value: '担当 user@example.com の件' } })
    fireEvent.click(screen.getByRole('button', { name: '送信前に確認' }))

    expect(await screen.findByText('担当 [EMAIL_REDACTED] の件')).toBeInTheDocument()
    expect(screen.getByText('マスキング済み')).toBeInTheDocument()
    expect(screen.getByText('重大度：中')).toBeInTheDocument()
    expect(screen.getByText('処理：マスキングして続行')).toBeInTheDocument()
    expect(screen.getByText(NOTICE)).toBeInTheDocument()
    expect(callsTo(spy, 'POST /api/v1/analyses')).toHaveLength(0)
  })

  it('does not call a clean result safe, and always shows the notice', async () => {
    server({ 'POST /api/v1/security/scan-preview': () => json({ data: { ...scan, masked_input: '普通の文' } }) })
    open('/analyses/new')

    fireEvent.change(await screen.findByLabelText('依頼内容'), { target: { value: '普通の文' } })
    fireEvent.click(screen.getByRole('button', { name: '送信前に確認' }))

    expect(await screen.findByText('検出なし')).toBeInTheDocument()
    expect(screen.getByText(NOTICE)).toBeInTheDocument()
    expect(screen.queryByText('安全', { exact: false })).not.toBeInTheDocument()
  })

  it('forgets a preview as soon as the text changes', async () => {
    server({ 'POST /api/v1/security/scan-preview': () => json({ data: { ...scan, masked_input: '前の結果' } }) })
    open('/analyses/new')

    const field = await screen.findByLabelText('依頼内容')
    fireEvent.change(field, { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: '送信前に確認' }))
    expect(await screen.findByText('前の結果')).toBeInTheDocument()

    fireEvent.change(field, { target: { value: 'xy' } })
    await waitFor(() => {
      expect(screen.queryByText('前の結果')).not.toBeInTheDocument()
    })
  })

  it('shows why it stopped, keeps the text, and selects the place, counting characters as the server does', async () => {
    server({ 'POST /api/v1/analyses': () => refused(blockedBody()) })
    open('/analyses/new')

    const field = await screen.findByLabelText<HTMLTextAreaElement>('依頼内容')
    // The first character takes two UTF-16 units.
    fireEvent.change(field, { target: { value: '😀あSECRET後' } })
    fireEvent.click(screen.getByRole('button', { name: '分析する' }))

    expect(await screen.findByText('検査により処理を停止しました', { exact: false })).toBeInTheDocument()
    expect(screen.getByText('APIキー形式の文字列を検出しました')).toBeInTheDocument()
    expect(screen.getByText('重大度：重大')).toBeInTheDocument()
    expect(screen.getByText('処理：停止')).toBeInTheDocument()
    expect(screen.queryByText('server text that is not shown')).not.toBeInTheDocument()
    expect(field).toHaveValue('😀あSECRET後')

    fireEvent.click(screen.getByRole('button', { name: '該当箇所を選択' }))
    expect(field.value.slice(field.selectionStart, field.selectionEnd)).toBe('SECRET')
  })

  it('offers no selection when the scan did not stop: the positions are of the masked text', async () => {
    server({ 'POST /api/v1/security/scan-preview': () => json({ data: { ...scan, masked_input: 'x', findings: [finding()], findings_count: 1 } }) })
    open('/analyses/new')

    fireEvent.change(await screen.findByLabelText('依頼内容'), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: '送信前に確認' }))

    await screen.findByText('メールアドレスを検出しマスキングしました')
    expect(screen.queryByRole('button', { name: '該当箇所を選択' })).not.toBeInTheDocument()
  })

  it('says how many more findings there are than are shown', async () => {
    server({ 'POST /api/v1/security/scan-preview': () => json({ data: { ...scan, masked_input: 'x', findings: [finding()], findings_count: 150 } }) })
    open('/analyses/new')

    fireEvent.change(await screen.findByLabelText('依頼内容'), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: '送信前に確認' }))

    expect(await screen.findByText('ほかに 149 件の検出があります', { exact: false })).toBeInTheDocument()
  })

  it('says when the AI wrote something that stopped the analysis', async () => {
    server({ [`GET /api/v1/analyses/${ANALYSIS_ID}`]: () => json({ data: analysis({ status: 'blocked', error_code: 'AI_OUTPUT_BLOCKED' }) }) })
    open(`/analyses/${ANALYSIS_ID}`)

    expect(await screen.findByText('AI の応答に秘密情報や攻撃と思われる内容', { exact: false })).toBeInTheDocument()
    expect(screen.getByText(NOTICE)).toBeInTheDocument()
  })

  it('draws a masked text and a message as text, never as markup', async () => {
    const attack = '<img src=x onerror="window.pwned=1">'
    server({ 'POST /api/v1/security/scan-preview': () => json({ data: { ...scan, masked_input: attack, findings: [finding({ message: attack, field: attack })], findings_count: 1 } }) })
    open('/analyses/new')

    fireEvent.change(await screen.findByLabelText('依頼内容'), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: '送信前に確認' }))

    expect((await screen.findAllByText(attack)).length).toBeGreaterThan(1)
    expect(document.querySelector('img')).toBeNull()
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

  it('warns only about a revision from before scanning', async () => {
    server({ [detailKey]: () => json({ data: workflow({ scan: notScanned }) }) })
    open(detailPath)

    expect((await screen.findAllByText('未検査')).length).toBeGreaterThan(0)
    expect(screen.getByText(NOTICE)).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('提出、承認、実行はできません')
  })

  it('shows what the scan found, with no warning about scanning, and the notice', async () => {
    server({
      [detailKey]: () =>
        json({ data: workflow({ max_severity: 'high', scan: { ...scan, decision: 'warn', max_severity: 'medium', findings: [finding({ severity: 'medium', action: 'warn', message: '攻撃の可能性', field: 'tasks.2.steps.1' })], findings_count: 1 } }) }),
    })
    open(detailPath)

    expect((await screen.findAllByText('警告あり')).length).toBeGreaterThan(0)
    expect(screen.getByText('タスク 2 の手順 1')).toBeInTheDocument()
    expect(screen.getByText('高')).toBeInTheDocument()
    expect(screen.getByText(NOTICE)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('names what the AI asked for, and the action, in words', async () => {
    server({
      [detailKey]: () =>
        json({
          data: workflow({
            scan: {
              ...scan,
              decision: 'warn',
              findings: [
                finding({ category: 'permission_mismatch', severity: 'medium', action: 'warn', message: '多くの権限', field: 'tasks.1.requested_permissions', position_start: null, position_end: null }),
                finding({ category: 'forbidden_action', severity: 'high', action: 'warn', message: '禁止された操作の提案', field: 'tasks.2.action_type', position_start: null, position_end: null }),
              ],
              findings_count: 2,
            },
          }),
        }),
    })
    open(detailPath)

    expect(await screen.findByText('タスク 1 のAI が申告した権限')).toBeInTheDocument()
    expect(screen.getByText('タスク 2 の操作')).toBeInTheDocument()
  })

  it('keeps what was typed and shows the findings when an edit is refused', async () => {
    server({
      [detailKey]: () => json({ data: workflow() }),
      [putKey]: () => refused(blockedBody({ findings: [finding({ severity: 'critical', action: 'block', message: 'APIキー形式の文字列を検出しました', field: 'tasks.1.description' })] })),
    })
    open(detailPath)

    fireEvent.click(await screen.findByRole('button', { name: '編集' }))
    fireEvent.change(screen.getByLabelText('説明'), { target: { value: '入力した内容' } })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('検査により処理を停止しました', { exact: false })).toBeInTheDocument()
    expect(screen.getByText('APIキー形式の文字列を検出しました')).toBeInTheDocument()
    expect(screen.getByText('タスク 1 の説明')).toBeInTheDocument()
    expect(screen.getByLabelText('説明')).toHaveValue('入力した内容')
  })

  it('says that masking made a text too long, and nothing else from the server', async () => {
    server({
      [detailKey]: () => json({ data: workflow() }),
      [putKey]: () =>
        new Response(JSON.stringify({ type: 'x', title: 'x', status: 422, code: 'VALIDATION_FAILED', errors: { 'tasks.1.title': ['マスキング後の文字数が上限を超えます。短くしてください。'] } }), {
          status: 422,
          headers: { 'Content-Type': 'application/problem+json' },
        }),
    })
    open(detailPath)

    fireEvent.click(await screen.findByRole('button', { name: '編集' }))
    fireEvent.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('マスキング後の文字数が上限を超えます', { exact: false })).toBeInTheDocument()
  })

  it('shows the masked text the server kept after a save, not what was typed', async () => {
    server({
      [detailKey]: () => json({ data: workflow() }),
      [putKey]: () => json({ data: workflow({ tasks: [task({ description: '担当 [EMAIL_REDACTED]' })] }) }),
    })
    open(detailPath)

    fireEvent.click(await screen.findByRole('button', { name: '編集' }))
    fireEvent.change(screen.getByLabelText('説明'), { target: { value: '担当 user@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('担当 [EMAIL_REDACTED]')).toBeInTheDocument()
    expect(screen.queryByText('担当 user@example.com')).not.toBeInTheDocument()
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

    await screen.findAllByText('検出なし')
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

const HASH = 'a'.repeat(64)

const approvalContext = (overrides = {}) => ({
  workflow_id: WORKFLOW_ID,
  title: '問い合わせの要約',
  status: 'pending',
  revision_no: 3,
  plan_hash: HASH,
  policy_version: '2026.11.1',
  tasks: [{ ...task(), ai_feature: 'テキスト要約（模擬実行）' }],
  security: scan,
  requires_risk_acknowledgement: false,
  created_by: { id: 'u', name: '申請者' },
  can_approve: true,
  cannot_approve_reason: null,
  approver_available: true,
  ...overrides,
})

const bodyOf = (call: Parameters<typeof fetch>) => JSON.parse(String(call[1]?.body)) as Record<string, unknown>

describe('submitting and reopening', () => {
  it('submits a draft, and shows the new state', async () => {
    const spy = server({
      [`GET /api/v1/workflows/${WORKFLOW_ID}`]: () => json({ data: workflow({ can_submit: true }) }),
      [`POST /api/v1/workflows/${WORKFLOW_ID}/submit`]: () => json({ data: workflow({ status: 'pending', can_view_approval: true, can_edit: true }) }),
    })
    open(`/workflows/${WORKFLOW_ID}`)

    fireEvent.click(await screen.findByRole('button', { name: '承認を依頼する' }))

    expect(await screen.findByText('承認待ち')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '承認の画面を開く' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '承認を依頼する' })).not.toBeInTheDocument()
    expect(callsTo(spy, `POST /api/v1/workflows/${WORKFLOW_ID}/submit`)).toHaveLength(1)
  })

  it('says when there is nobody to approve it', async () => {
    server({ [`GET /api/v1/workflows/${WORKFLOW_ID}`]: () => json({ data: workflow({ status: 'pending', approver_available: false }) }) })
    open(`/workflows/${WORKFLOW_ID}`)

    expect(await screen.findByText('承認可能な管理者がいないため', { exact: false })).toBeInTheDocument()
  })

  it.each([
    ['FORBIDDEN_ACTION_PRESENT', '禁止された操作を含む'],
    ['SCAN_REQUIRED', '未検査のリビジョンは'],
    ['SCAN_BLOCKED', '検査で停止と判定された'],
  ])('says why a submission was refused: %s', async (code, message) => {
    server({
      [`GET /api/v1/workflows/${WORKFLOW_ID}`]: () => json({ data: workflow({ can_submit: true }) }),
      [`POST /api/v1/workflows/${WORKFLOW_ID}/submit`]: () => problem(409, code),
    })
    open(`/workflows/${WORKFLOW_ID}`)

    fireEvent.click(await screen.findByRole('button', { name: '承認を依頼する' }))

    expect(await screen.findByText(message, { exact: false })).toBeInTheDocument()
    expect(screen.queryByText('server text that is not shown')).not.toBeInTheDocument()
  })

  it('shows why it was rejected, as text, and reopens it', async () => {
    const reason = '<img src=x onerror=alert(1)>手順が足りません'
    const rejected = workflow({ status: 'rejected', can_edit: false, can_reopen: true, decision: { decision: 'rejected', comment: reason, decided_by: { id: 'a', name: '管理者' }, decided_at: '2026-11-07T00:00:00Z' } })
    const spy = server({
      [`GET /api/v1/workflows/${WORKFLOW_ID}`]: () => json({ data: rejected }),
      [`POST /api/v1/workflows/${WORKFLOW_ID}/reopen`]: () => json({ data: workflow({ can_submit: true }) }),
    })
    open(`/workflows/${WORKFLOW_ID}`)

    expect(await screen.findByText(reason)).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '下書きに戻す' }))

    expect(await screen.findByRole('button', { name: '承認を依頼する' })).toBeInTheDocument()
    expect(callsTo(spy, `POST /api/v1/workflows/${WORKFLOW_ID}/reopen`)).toHaveLength(1)
  })
})

describe('the approval screen', () => {
  const contextRoute = `GET /api/v1/workflows/${WORKFLOW_ID}/approval-context`
  const approveRoute = `POST /api/v1/workflows/${WORKFLOW_ID}/approve`
  const rejectRoute = `POST /api/v1/workflows/${WORKFLOW_ID}/reject`
  const afterwards = { [`GET /api/v1/workflows/${WORKFLOW_ID}`]: () => json({ data: workflow({ status: 'approved', can_edit: true }) }) }

  it('shows the six items of the requirements and the notice', async () => {
    server({ [contextRoute]: () => json({ data: approvalContext() }) }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    for (const label of ['実行する処理', '使用する AI 機能', '対象データ', '必要な権限', '実行による影響']) {
      expect(await screen.findByText(label)).toBeInTheDocument()
    }
    expect(screen.getByText('テキスト要約（模擬実行）')).toBeInTheDocument()
    expect(screen.getByText('検査の結果：')).toBeInTheDocument()
    expect(screen.getByText(NOTICE)).toBeInTheDocument()
    expect(screen.getByText(HASH)).toBeInTheDocument()
  })

  it('sends the revision and the hash that were shown', async () => {
    const spy = server({ [contextRoute]: () => json({ data: approvalContext() }), [approveRoute]: () => json({ data: workflow({ status: 'approved' }) }), ...afterwards }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    fireEvent.click(await screen.findByRole('button', { name: '承認する' }))

    await waitFor(() => { expect(callsTo(spy, approveRoute)).toHaveLength(1) })
    expect(bodyOf(callsTo(spy, approveRoute)[0] as Parameters<typeof fetch>)).toEqual({ revision_no: 3, plan_hash: HASH, acknowledged_risks: false, comment: null })
    expect(await screen.findByText('承認済み')).toBeInTheDocument()
  })

  it('asks for the confirmation only when the server does', async () => {
    server({ [contextRoute]: () => json({ data: approvalContext({ requires_risk_acknowledgement: true }) }) }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    expect(await screen.findByRole('checkbox')).toBeRequired()
  })

  it('sends the confirmation that was given', async () => {
    const spy = server({ [contextRoute]: () => json({ data: approvalContext({ requires_risk_acknowledgement: true }) }), [approveRoute]: () => json({ data: workflow({ status: 'approved' }) }), ...afterwards }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    fireEvent.click(await screen.findByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: '承認する' }))

    await waitFor(() => { expect(callsTo(spy, approveRoute)).toHaveLength(1) })
    expect(bodyOf(callsTo(spy, approveRoute)[0] as Parameters<typeof fetch>)['acknowledged_risks']).toBe(true)
  })

  it('reads the plan again when it changed, takes back the confirmation and keeps the comment', async () => {
    let contexts = 0
    const spy = server({
      [contextRoute]: () => {
        contexts += 1
        return json({ data: approvalContext(contexts === 1 ? { requires_risk_acknowledgement: true } : { requires_risk_acknowledgement: true, revision_no: 4, plan_hash: 'b'.repeat(64) }) })
      },
      [approveRoute]: () => problem(409, 'PLAN_HASH_MISMATCH'),
    }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    fireEvent.click(await screen.findByRole('checkbox'))
    fireEvent.change(screen.getByLabelText('コメント（任意）'), { target: { value: '確認済み' } })
    fireEvent.click(screen.getByRole('button', { name: '承認する' }))

    expect(await screen.findByText('内容が変更されています。', { exact: false })).toBeInTheDocument()
    expect(await screen.findByText('b'.repeat(64))).toBeInTheDocument()
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    expect(screen.getByLabelText('コメント（任意）')).toHaveValue('確認済み')
    expect(callsTo(spy, contextRoute).length).toBeGreaterThan(1)
  })

  it('shows what stopped a comment', async () => {
    server({ [contextRoute]: () => json({ data: approvalContext() }), [approveRoute]: () => refused(blockedBody()) }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    fireEvent.change(await screen.findByLabelText('コメント（任意）'), { target: { value: 'text' } })
    fireEvent.click(screen.getByRole('button', { name: '承認する' }))

    expect(await screen.findByText('APIキー形式の文字列を検出しました')).toBeInTheDocument()
    expect(screen.getByLabelText('コメント（任意）')).toHaveValue('text')
  })

  it('needs a reason to reject, and sends it', async () => {
    const spy = server({ [contextRoute]: () => json({ data: approvalContext() }), [rejectRoute]: () => json({ data: workflow({ status: 'rejected' }) }), ...afterwards }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    const reason = await screen.findByLabelText('却下の理由')
    expect(reason).toBeRequired()
    fireEvent.change(reason, { target: { value: '手順が足りません' } })
    fireEvent.click(screen.getByRole('button', { name: '却下する' }))

    await waitFor(() => { expect(callsTo(spy, rejectRoute)).toHaveLength(1) })
    expect(bodyOf(callsTo(spy, rejectRoute)[0] as Parameters<typeof fetch>)).toEqual({ revision_no: 3, plan_hash: HASH, reason: '手順が足りません' })
  })

  it.each([
    ['SELF_CREATED', '自分が作成した'],
    ['ROLE_NOT_ADMIN', '参照のみ'],
  ])('offers no decision to someone who cannot make one: %s', async (reason, message) => {
    server({ [contextRoute]: () => json({ data: approvalContext({ can_approve: false, cannot_approve_reason: reason }) }) })
    open(`/workflows/${WORKFLOW_ID}/approval`)

    expect(await screen.findByText(message, { exact: false })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '承認する' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '却下する' })).not.toBeInTheDocument()
  })

  it.each([
    ['FORBIDDEN_ACTION_PRESENT', '禁止された操作が含まれている'],
    ['SCAN_REQUIRED', '未検査のリビジョン'],
    ['SCAN_BLOCKED', '検査で停止'],
    ['PLAN_HASH_MISMATCH', '一致しない'],
  ])('can only be turned down when it cannot be approved: %s', async (reason, message) => {
    server({ [contextRoute]: () => json({ data: approvalContext({ can_approve: false, cannot_approve_reason: reason }) }) }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    expect(await screen.findByText(message, { exact: false })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '承認する' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '却下する' })).toBeInTheDocument()
  })

  it('draws the plan as text', async () => {
    const markup = '<img src=x onerror=alert(1)>'
    server({ [contextRoute]: () => json({ data: approvalContext({ title: markup, tasks: [{ ...task({ description: markup, target_data: markup, impact_summary: markup, steps: [markup] }), ai_feature: 'x' }] }) }) }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    expect((await screen.findAllByText(markup)).length).toBeGreaterThan(2)
    expect(document.querySelector('img')).toBeNull()
  })

  it('refuses a response of the wrong shape', async () => {
    server({ [contextRoute]: () => json({ data: { ...approvalContext(), can_approve: 'yes' } }) }, 'admin')
    open(`/workflows/${WORKFLOW_ID}/approval`)

    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '承認する' })).not.toBeInTheDocument()
  })
})

describe('the approvals list', () => {
  const row = (overrides = {}) => ({ workflow_id: WORKFLOW_ID, title: '問い合わせの要約', revision_no: 3, max_severity: 'medium', created_by: { id: 'u', name: '申請者' }, submitted_at: '2026-11-07T00:00:00Z', can_approve: true, cannot_approve_reason: null, ...overrides })

  it('is in the menu for an admin only', async () => {
    server({ 'GET /api/v1/workflows': () => json({ data: [], meta: { next_cursor: null } }) })
    open('/workflows')

    await screen.findByRole('heading', { name: 'ワークフロー' })
    expect(screen.queryByRole('link', { name: '承認待ち' })).not.toBeInTheDocument()
  })

  it('lists what waits, and says which ones are the admin\'s own', async () => {
    server({ 'GET /api/v1/approvals?status=pending': () => json({ data: [row(), row({ workflow_id: 'other', title: '自分の', can_approve: false, cannot_approve_reason: 'SELF_CREATED' })], meta: { next_cursor: null } }) }, 'admin')
    open('/approvals')

    const link = await screen.findByRole('link', { name: '問い合わせの要約' })
    expect(link).toHaveAttribute('href', `/workflows/${WORKFLOW_ID}/approval`)
    expect(screen.getByRole('link', { name: '承認待ち' })).toBeInTheDocument()
    expect(screen.getByText('自分が作成した', { exact: false })).toBeInTheDocument()
  })

  it('says when nothing waits', async () => {
    server({ 'GET /api/v1/approvals?status=pending': () => json({ data: [], meta: { next_cursor: null } }) }, 'admin')
    open('/approvals')

    expect(await screen.findByText('承認待ちのワークフローはありません。')).toBeInTheDocument()
  })
})
