import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { ApiError } from '../../api/client'
import { changePassword } from '../auth/authApi'
import { useCurrentUser } from '../auth/useAuth'
import { apiErrorMessage, SEVERITY_LABELS } from '../workflows/labels'
import { fetchAiSettings, fetchLimits, fetchSecuritySettings, LIMIT_FIELDS, updateLimits, type LimitField, type Limits } from './settingsApi'

const cardClass = 'space-y-3 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200'

const inputClass = 'mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm'

const LIMIT_LABELS: Record<LimitField, string> = {
  monthly_token_limit: '組織の月間トークン上限',
  user_daily_request_limit: '利用者ごとの 1 日の分析回数上限',
  max_input_chars: '入力の最大文字数',
}

const LIMIT_RANGES: Record<LimitField, [number, number]> = {
  monthly_token_limit: [1, 1_000_000_000],
  user_daily_request_limit: [1, 100_000],
  max_input_chars: [1, 20_000],
}

const ACTION_LABELS: Record<string, string> = { record: '記録のみ', mask_continue: 'マスキングして続行', warn: '警告して続行', block: '停止' }

function AiSection() {
  const ai = useQuery({ queryKey: ['settings', 'ai'], queryFn: fetchAiSettings, retry: false })

  return (
    <section className={cardClass}>
      <h3 className="text-sm font-medium text-slate-700">AI プロバイダ</h3>
      <p className="text-xs text-slate-500">環境変数でのみ設定します。この画面からは変更できず、API キーの値は表示されません。</p>
      {ai.isPending && <p className="text-sm text-slate-500">読み込み中…</p>}
      {ai.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(ai.error)}
        </p>
      )}
      {ai.data && (
        <dl className="grid grid-cols-2 gap-2 text-sm">
          <dt className="text-slate-500">プロバイダ</dt>
          <dd>{ai.data.provider}</dd>
          <dt className="text-slate-500">モデル</dt>
          <dd>{ai.data.model ?? '-'}</dd>
          <dt className="text-slate-500">API キー</dt>
          <dd>{ai.data.api_key_configured ? '設定済み' : '未設定'}</dd>
          <dt className="text-slate-500">タイムアウト</dt>
          <dd>{ai.data.timeout_seconds} 秒</dd>
          <dt className="text-slate-500">出力トークンの上限</dt>
          <dd>{ai.data.max_output_tokens}</dd>
        </dl>
      )}
    </section>
  )
}

function LimitsForm({ limits }: { limits: Limits }) {
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState<Record<LimitField, string>>({
    monthly_token_limit: String(limits.monthly_token_limit),
    user_daily_request_limit: String(limits.user_daily_request_limit),
    max_input_chars: String(limits.max_input_chars),
  })
  const [problem, setProblem] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: updateLimits,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['settings', 'limits'] })
    },
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const changes: Partial<Record<LimitField, number>> = {}

    for (const field of LIMIT_FIELDS) {
      const value = Number(draft[field])
      const [min, max] = LIMIT_RANGES[field]
      if (!Number.isInteger(value) || value < min || value > max) {
        setProblem(`${LIMIT_LABELS[field]}は ${String(min)} から ${String(max)} までの整数で指定してください。`)
        return
      }
      if (value !== limits[field]) {
        changes[field] = value
      }
    }

    setProblem(null)
    if (Object.keys(changes).length === 0) {
      return
    }
    save.mutate(changes)
  }

  return (
    <form className="space-y-3" aria-label="API 利用制限" noValidate onSubmit={submit}>
      {LIMIT_FIELDS.map((field) => (
        <label key={field} className="block text-sm font-medium text-slate-700">
          {LIMIT_LABELS[field]}
          <input
            className={inputClass}
            type="number"
            inputMode="numeric"
            min={LIMIT_RANGES[field][0]}
            max={LIMIT_RANGES[field][1]}
            step={1}
            value={draft[field]}
            onChange={(event) => {
              setDraft({ ...draft, [field]: event.target.value })
            }}
          />
        </label>
      ))}
      {problem !== null && (
        <p role="alert" className="text-sm text-red-700">
          {problem}
        </p>
      )}
      {save.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(save.error)}
        </p>
      )}
      {save.isSuccess && <p className="text-sm text-emerald-800">保存しました。</p>}
      <button type="submit" className="rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50" disabled={save.isPending}>
        保存
      </button>
    </form>
  )
}

function LimitsSection() {
  const limits = useQuery({ queryKey: ['settings', 'limits'], queryFn: fetchLimits, retry: false })

  return (
    <section className={cardClass}>
      <h3 className="text-sm font-medium text-slate-700">API 利用制限</h3>
      <p className="text-xs text-slate-500">上限に達した分析は受け付けず、AI を呼び出しません。変更は監査ログに記録されます。</p>
      {limits.isPending && <p className="text-sm text-slate-500">読み込み中…</p>}
      {limits.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(limits.error)}
        </p>
      )}
      {limits.data && (
        <>
          <LimitsForm key={limits.data.updated_at ?? 'defaults'} limits={limits.data} />
          <p className="text-xs text-slate-500">
            {limits.data.updated_at === null ? '既定値を使用しています。' : `最終更新：${limits.data.updated_at}（${limits.data.updated_by?.name ?? '-'}）`}
          </p>
        </>
      )}
    </section>
  )
}

function SecuritySection() {
  const security = useQuery({ queryKey: ['settings', 'security'], queryFn: fetchSecuritySettings, retry: false })

  return (
    <section className={cardClass}>
      <h3 className="text-sm font-medium text-slate-700">セキュリティ設定</h3>
      <p className="text-xs text-slate-500">判定の方針はコードで固定されており、変更できません（参照のみ）。</p>
      {security.isPending && <p className="text-sm text-slate-500">読み込み中…</p>}
      {security.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(security.error)}
        </p>
      )}
      {security.data && (
        <dl className="grid grid-cols-2 gap-2 text-sm">
          <dt className="text-slate-500">操作カタログの版</dt>
          <dd>{security.data.policy_version}</dd>
          <dt className="text-slate-500">検出ルールの版</dt>
          <dd>{security.data.ruleset_version}</dd>
          <dt className="text-slate-500">プロンプトの版</dt>
          <dd>{security.data.prompt_version}</dd>
          <dt className="text-slate-500">個人情報</dt>
          <dd>{ACTION_LABELS[security.data.input_actions.pii] ?? security.data.input_actions.pii}</dd>
          <dt className="text-slate-500">認証・秘密情報</dt>
          <dd>{ACTION_LABELS[security.data.input_actions.secret] ?? security.data.input_actions.secret}</dd>
          <dt className="text-slate-500">マスキングの失敗</dt>
          <dd>{ACTION_LABELS[security.data.input_actions.masking_failure] ?? security.data.input_actions.masking_failure}</dd>
          {Object.entries(security.data.input_actions.injection).map(([severity, action]) => (
            <div key={severity} className="contents">
              <dt className="text-slate-500">インジェクション（{SEVERITY_LABELS[severity] ?? severity}）</dt>
              <dd>{ACTION_LABELS[action] ?? action}</dd>
            </div>
          ))}
          <dt className="text-slate-500">承認</dt>
          <dd>
            {security.data.approval.approver_role === 'admin' ? '管理者のみ' : security.data.approval.approver_role}・
            {security.data.approval.self_approval === 'forbidden' ? '自己承認は禁止' : security.data.approval.self_approval}・ 重大度
            {SEVERITY_LABELS[security.data.approval.risk_acknowledgement_from] ?? security.data.approval.risk_acknowledgement_from}
            以上はリスクの確認が必須
          </dd>
        </dl>
      )}
    </section>
  )
}

function passwordErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return 'サーバーに接続できませんでした。'
  }

  switch (error.code) {
    case 'CURRENT_PASSWORD_INVALID':
      return '現在のパスワードが正しくありません。'
    case 'VALIDATION_FAILED': {
      const problems = error.fieldErrors.new_password ?? []
      return problems.length > 0 ? problems.join(' ') : '入力内容を確認してください。'
    }
    case 'IDEMPOTENCY_KEY_CONFLICT':
      return '内容が変更されています。もう一度送信してください。'
    case 'SERVICE_UNAVAILABLE':
      // The server's fixed sentence for this endpoint says what to do (docs/api-design.md §3.1.2).
      return error.detail ?? '現在サービスを利用できません。同じ内容で再度お試しください。'
    case 'RATE_LIMITED':
      return error.retryAfterSeconds
        ? `試行回数が多すぎます。${String(error.retryAfterSeconds)}秒後に同じ内容で再度お試しください。`
        : '試行回数が多すぎます。しばらく待ってから同じ内容で再度お試しください。'
    case 'UNAUTHENTICATED':
      return 'ログインし直してください。'
    default:
      return apiErrorMessage(error)
  }
}

/**
 * docs/api-design.md §3.1.2. One idempotency key per content: it is kept while the content stays the same, so a retry
 * after a 503 or a 429 is the same request, and a new content is a new key. The passwords live only in this form.
 */
function PasswordSection() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [key, setKey] = useState(() => crypto.randomUUID())
  const [mismatch, setMismatch] = useState(false)
  const change = useMutation({
    mutationFn: () => changePassword(current, next, key),
    onSuccess: () => {
      setCurrent('')
      setNext('')
      setConfirm('')
      setKey(crypto.randomUUID())
    },
    onError: (error) => {
      if (error instanceof ApiError && !['SERVICE_UNAVAILABLE', 'RATE_LIMITED', 'CSRF_TOKEN_MISMATCH'].includes(error.code)) {
        setKey(crypto.randomUUID())
      }
    },
  })

  const edit = (setter: (value: string) => void) => (value: string) => {
    setter(value)
    setMismatch(false)
    setKey(crypto.randomUUID())
  }

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (next !== confirm) {
      setMismatch(true)
      return
    }
    change.mutate()
  }

  return (
    <section className={cardClass}>
      <h3 className="text-sm font-medium text-slate-700">アカウント設定</h3>
      <form className="space-y-3" aria-label="パスワードの変更" onSubmit={submit}>
        <label className="block text-sm font-medium text-slate-700" htmlFor="current-password">
          現在のパスワード
          <input id="current-password" className={inputClass} type="password" autoComplete="current-password" required value={current} onChange={(event) => { edit(setCurrent)(event.target.value) }} />
        </label>
        <label className="block text-sm font-medium text-slate-700" htmlFor="new-password">
          新しいパスワード（12 文字以上。広く使われているパスワードは使えません）
          <input id="new-password" className={inputClass} type="password" autoComplete="new-password" required minLength={12} value={next} onChange={(event) => { edit(setNext)(event.target.value) }} />
        </label>
        <label className="block text-sm font-medium text-slate-700" htmlFor="confirm-password">
          新しいパスワード（確認）
          <input id="confirm-password" className={inputClass} type="password" autoComplete="new-password" required value={confirm} onChange={(event) => { edit(setConfirm)(event.target.value) }} />
        </label>
        {mismatch && (
          <p role="alert" className="text-sm text-red-700">
            新しいパスワードが確認と一致しません。
          </p>
        )}
        {change.isError && (
          <p role="alert" className="text-sm text-red-700">
            {passwordErrorMessage(change.error)}
          </p>
        )}
        {change.isSuccess && <p className="text-sm text-emerald-800">パスワードを変更しました。他の端末のセッションは終了しました。</p>}
        <button type="submit" className="rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50" disabled={change.isPending}>
          パスワードを変更
        </button>
      </form>
    </section>
  )
}

export function SettingsPage() {
  const { data: user } = useCurrentUser()

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">設定</h2>
      {/* Shown to an admin only; the server refuses everyone else regardless. */}
      {user?.role === 'admin' && (
        <>
          <AiSection />
          <LimitsSection />
          <SecuritySection />
        </>
      )}
      <PasswordSection />
    </div>
  )
}
