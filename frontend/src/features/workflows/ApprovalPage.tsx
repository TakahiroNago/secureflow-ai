import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { ApiError } from '../../api/client'
import { approveWorkflow, blockedScan, fetchApprovalContext, rejectWorkflow } from './workflowApi'
import { apiErrorMessage, CANNOT_APPROVE_LABELS, NO_APPROVER_MESSAGE, PRIORITY_LABELS, SEVERITY_LABELS } from './labels'
import { ScanPanel } from './ScanPanel'

/**
 * What is about to be decided (docs/requirements.md §4.5). The decision names the revision and hash shown here, so a
 * plan that changed after this was drawn is refused rather than approved unseen. Everything is drawn as text.
 */
export function ApprovalPage() {
  const { id = '' } = useParams()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const key = ['approval-context', id]
  const [acknowledged, setAcknowledged] = useState(false)
  const [comment, setComment] = useState('')
  const [reason, setReason] = useState('')

  const context = useQuery({ queryKey: key, queryFn: () => fetchApprovalContext(id), retry: false })

  const decide = useMutation({
    mutationFn: (run: () => Promise<unknown>) => run(),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['approvals'] })
      queryClient.removeQueries({ queryKey: ['workflows', id] })
      await navigate(`/workflows/${encodeURIComponent(id)}`)
    },
    onError: (error) => {
      // The plan changed or someone decided first: show what is there now, and keep what was typed.
      if (error instanceof ApiError && (error.code === 'PLAN_HASH_MISMATCH' || error.code === 'ALREADY_DECIDED' || error.code === 'WORKFLOW_INVALID_STATE')) {
        setAcknowledged(false)
        void queryClient.invalidateQueries({ queryKey: key })
      }
    },
  })

  if (context.isPending) {
    return <p className="text-sm text-slate-500">読み込み中…</p>
  }

  if (context.isError) {
    return (
      <section className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(context.error)}
        </p>
        <Link className="mt-3 inline-block text-sm underline" to="/workflows">
          一覧へ戻る
        </Link>
      </section>
    )
  }

  const current = context.data
  const blocked = blockedScan(decide.error)
  const needsAcknowledgement = current.requires_risk_acknowledgement
  const identity = current.revision_no !== null && current.plan_hash !== null ? { revision_no: current.revision_no, plan_hash: current.plan_hash } : null

  return (
    <section className="space-y-4 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <Link className="text-sm underline" to={`/workflows/${encodeURIComponent(id)}`}>
        ワークフローへ戻る
      </Link>

      <h2 className="text-lg font-semibold">承認：{current.title}</h2>

      <dl className="grid grid-cols-2 gap-1 text-sm">
        <dt className="text-slate-500">申請者</dt>
        <dd>{current.created_by.name}</dd>
        <dt className="text-slate-500">リビジョン</dt>
        <dd>{current.revision_no ?? '-'}</dd>
        <dt className="text-slate-500">ポリシーのバージョン</dt>
        <dd>{current.policy_version ?? '-'}</dd>
        <dt className="text-slate-500">承認ハッシュ</dt>
        <dd className="break-all font-mono text-xs">{current.plan_hash ?? '-'}</dd>
        <dt className="text-slate-500">これまでの最大の重大度</dt>
        <dd>{current.security.max_severity === null ? 'なし' : SEVERITY_LABELS[current.security.max_severity]}</dd>
      </dl>

      {!current.approver_available && (
        <p role="alert" className="rounded-md bg-amber-50 p-3 text-sm text-amber-900 ring-1 ring-amber-200">
          {NO_APPROVER_MESSAGE}
        </p>
      )}

      <ScanPanel scan={current.security} />

      <ol className="space-y-3">
        {current.tasks.map((task) => (
          <li key={task.position} className="rounded-md p-3 ring-1 ring-slate-200">
            <div className="flex items-center justify-between">
              <h3 className="font-medium">
                {task.position}. {task.title}
              </h3>
              {task.policy_decision === 'forbidden' && <span className="rounded bg-red-100 px-2 py-0.5 text-xs text-red-800">禁止された操作</span>}
            </div>
            <p className="mt-1 whitespace-pre-wrap text-sm">{task.description}</p>
            <dl className="mt-2 grid grid-cols-2 gap-1 text-xs">
              <dt className="text-slate-500">実行する処理</dt>
              <dd>{task.action_type}</dd>
              <dt className="text-slate-500">使用する AI 機能</dt>
              <dd>{task.ai_feature}</dd>
              <dt className="text-slate-500">対象データ</dt>
              <dd>{task.target_data}</dd>
              <dt className="text-slate-500">必要な権限</dt>
              <dd>{task.derived_permissions.join('、')}</dd>
              <dt className="text-slate-500">実行による影響</dt>
              <dd>{task.impact_summary}</dd>
              <dt className="text-slate-500">優先度</dt>
              <dd>{PRIORITY_LABELS[task.priority]}</dd>
            </dl>
            <ul className="mt-2 list-disc pl-5 text-sm">
              {task.steps.map((step, index) => (
                <li key={index}>{step}</li>
              ))}
            </ul>
          </li>
        ))}
      </ol>

      {decide.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(decide.error)}
        </p>
      )}
      {blocked !== null && <ScanPanel scan={blocked} />}

      {current.cannot_approve_reason !== null && (
        <p className="rounded-md bg-slate-50 p-3 text-sm text-slate-700">{CANNOT_APPROVE_LABELS[current.cannot_approve_reason] ?? '承認できません。'}</p>
      )}

      {current.can_approve && identity !== null && (
        <form
          className="space-y-3 rounded-md p-3 ring-1 ring-slate-200"
          onSubmit={(event) => {
            event.preventDefault()
            decide.mutate(() => approveWorkflow(id, { ...identity, acknowledged_risks: acknowledged, comment: comment === '' ? null : comment }))
          }}
        >
          {needsAcknowledgement && (
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-1"
                required
                checked={acknowledged}
                onChange={(event) => {
                  setAcknowledged(event.target.checked)
                }}
              />
              <span>検査で中以上のリスクが検出されたことを確認しました。</span>
            </label>
          )}
          <label className="block text-sm font-medium">
            コメント（任意）
            <textarea
              className="mt-1 w-full rounded-md border border-slate-300 p-2 text-sm"
              maxLength={1000}
              value={comment}
              onChange={(event) => {
                setComment(event.target.value)
              }}
            />
          </label>
          <button type="submit" className="rounded-md bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50" disabled={decide.isPending}>
            承認する
          </button>
        </form>
      )}

      {/* A plan that cannot be approved can still be turned down, so only who and when decide this. */}
      {identity !== null && current.status === 'pending' && current.cannot_approve_reason !== 'SELF_CREATED' && current.cannot_approve_reason !== 'ROLE_NOT_ADMIN' && (
        <form
          className="space-y-3 rounded-md p-3 ring-1 ring-slate-200"
          onSubmit={(event) => {
            event.preventDefault()
            decide.mutate(() => rejectWorkflow(id, { ...identity, reason }))
          }}
        >
          <label className="block text-sm font-medium">
            却下の理由
            <textarea
              className="mt-1 w-full rounded-md border border-slate-300 p-2 text-sm"
              required
              maxLength={1000}
              value={reason}
              onChange={(event) => {
                setReason(event.target.value)
              }}
            />
          </label>
          <button type="submit" className="rounded-md border border-red-300 px-3 py-2 text-sm text-red-800 disabled:opacity-50" disabled={decide.isPending}>
            却下する
          </button>
        </form>
      )}
    </section>
  )
}
