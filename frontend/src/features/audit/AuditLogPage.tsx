import { useInfiniteQuery, useMutation } from '@tanstack/react-query'
import { useState } from 'react'
import { apiErrorMessage } from '../workflows/labels'
import { fetchAuditLogs, NO_FILTERS, verifyAuditChain, type AuditEntry, type AuditFilters } from './auditApi'

const EVENT_TYPES = [
  'auth.login',
  'auth.login_failed',
  'auth.logout',
  'auth.locked',
  'auth.password_changed',
  'auth.password_change_failed',
  'security.scan',
  'security.blocked',
  'ai.call',
  'analysis.failed',
  'workflow.created',
  'workflow.updated',
  'workflow.submitted',
  'workflow.reopened',
  'approval.approved',
  'approval.rejected',
  'approval.denied',
  'execution.started',
  'execution.completed',
  'execution.failed',
  'execution.denied',
  'authz.denied',
  'rate_limit.exceeded',
  'finding.status_changed',
  'settings.updated',
]

const RESULT_LABELS: Record<string, string> = { success: '成功', failure: '失敗', denied: '拒否' }

const SEVERITY_LABELS: Record<string, string> = { low: '低', medium: '中', high: '高', critical: '重大' }

const ACTOR_LABELS: Record<string, string> = { system: 'システム', anonymous: '未認証' }

const actorOf = (entry: AuditEntry) => entry.actor.name ?? ACTOR_LABELS[entry.actor.type] ?? entry.actor.id ?? entry.actor.type

/** Values are whatever was recorded: a line of text each, never markup. */
const detailsOf = (entry: AuditEntry) => Object.entries(entry.metadata).map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`)

export function AuditLogPage() {
  const [draft, setDraft] = useState<AuditFilters>(NO_FILTERS)
  const [filters, setFilters] = useState<AuditFilters>(NO_FILTERS)

  const logs = useInfiniteQuery({
    queryKey: ['audit-logs', filters],
    queryFn: ({ pageParam }) => fetchAuditLogs(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.meta.next_cursor,
    retry: false,
  })
  const verify = useMutation({ mutationFn: verifyAuditChain })
  const items = logs.data?.pages.flatMap((page) => page.data) ?? []
  const set = (name: keyof AuditFilters, value: string) => {
    setDraft({ ...draft, [name]: value })
  }

  return (
    <section className="space-y-4 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <h2 className="text-lg font-semibold">監査ログ</h2>

      <div className="space-y-2 rounded-md p-3 text-sm ring-1 ring-slate-200">
        <button type="button" className="rounded-md border border-slate-300 px-3 py-2 disabled:opacity-50" disabled={verify.isPending} onClick={() => { verify.mutate() }}>
          チェーンを検証
        </button>
        {verify.isError && (
          <p role="alert" className="text-red-700">
            {apiErrorMessage(verify.error)}
          </p>
        )}
        {verify.data?.valid === true && <p>矛盾は見つかりませんでした（{verify.data.checked_count} 件を確認）。</p>}
        {verify.data?.valid === false && (
          <p role="alert" className="text-red-700">
            改ざんまたは破損を検出しました。チェーンの {verify.data.first_broken_seq ?? '-'} 番目（理由：{verify.data.reason_code ?? '-'}）。修復はしていません。管理者に連絡してください。
          </p>
        )}
        <p className="text-xs text-slate-500">
          検証で矛盾が見つからないことは、改ざんがないことの保証ではありません。データベースの所有者の権限があれば、チェーン全体を再計算できます。この組織の記録のみを確認します。
        </p>
      </div>

      <form
        className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-3 lg:grid-cols-6"
        onSubmit={(event) => {
          event.preventDefault()
          setFilters(draft)
        }}
      >
        <label className="block">
          種類
          <select className="mt-1 w-full rounded-md border border-slate-300 p-2" value={draft.event_type} onChange={(event) => { set('event_type', event.target.value) }}>
            <option value="">すべて</option>
            {EVENT_TYPES.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          結果
          <select className="mt-1 w-full rounded-md border border-slate-300 p-2" value={draft.result} onChange={(event) => { set('result', event.target.value) }}>
            <option value="">すべて</option>
            {Object.entries(RESULT_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          重大度
          <select className="mt-1 w-full rounded-md border border-slate-300 p-2" value={draft.severity} onChange={(event) => { set('severity', event.target.value) }}>
            <option value="">すべて</option>
            {Object.entries(SEVERITY_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          開始日（UTC）
          <input type="date" className="mt-1 w-full rounded-md border border-slate-300 p-2" value={draft.from} onChange={(event) => { set('from', event.target.value) }} />
        </label>
        <label className="block">
          終了日（UTC）
          <input type="date" className="mt-1 w-full rounded-md border border-slate-300 p-2" value={draft.to} onChange={(event) => { set('to', event.target.value) }} />
        </label>
        <button type="submit" className="self-end rounded-md bg-slate-900 px-3 py-2 text-white">
          絞り込む
        </button>
      </form>

      {logs.isPending && <p className="text-sm text-slate-500">読み込み中…</p>}
      {logs.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(logs.error)}
        </p>
      )}
      {logs.isSuccess && items.length === 0 && <p className="text-sm text-slate-500">該当する記録はありません。</p>}

      {items.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-slate-500">
              <tr>
                <th className="p-1 font-normal">番号</th>
                <th className="p-1 font-normal">日時（UTC）</th>
                <th className="p-1 font-normal">種類</th>
                <th className="p-1 font-normal">結果</th>
                <th className="p-1 font-normal">重大度</th>
                <th className="p-1 font-normal">実行者</th>
                <th className="p-1 font-normal">IP</th>
                <th className="p-1 font-normal">詳細</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {items.map((entry) => (
                <tr key={entry.event_id}>
                  <td className="p-1">{entry.chain_seq}</td>
                  <td className="whitespace-nowrap p-1">{entry.occurred_at}</td>
                  <td className="p-1">{entry.event_type}</td>
                  <td className="p-1">{RESULT_LABELS[entry.result] ?? entry.result}</td>
                  <td className="p-1">{entry.severity === null ? '-' : (SEVERITY_LABELS[entry.severity] ?? entry.severity)}</td>
                  <td className="p-1">{actorOf(entry)}</td>
                  <td className="p-1">{entry.ip_address ?? '-'}</td>
                  <td className="break-all p-1">
                    {detailsOf(entry).map((line) => (
                      <div key={line}>{line}</div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {logs.hasNextPage && (
        <button
          type="button"
          className="rounded-md border border-slate-300 px-3 py-2 text-sm disabled:opacity-50"
          disabled={logs.isFetchingNextPage}
          onClick={() => {
            void logs.fetchNextPage()
          }}
        >
          さらに表示
        </button>
      )}
    </section>
  )
}
