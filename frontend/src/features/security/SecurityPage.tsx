import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useCurrentUser } from '../auth/useAuth'
import { ACTION_LABELS, apiErrorMessage, SEVERITY_LABELS } from '../workflows/labels'
import {
  fetchFindings,
  NEXT_STATUSES,
  NO_FINDING_FILTERS,
  updateFindingStatus,
  type Finding,
  type FindingFilters,
  type FindingStatus,
} from './securityApi'

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: '未対応',
  acknowledged: '確認済み',
  resolved: '対応済み',
  false_positive: '誤検知',
}

const CATEGORY_LABELS: Record<string, string> = {
  pii: '個人情報',
  secret: '秘密情報',
  injection: 'インジェクション',
  schema: '形式',
  forbidden_action: '禁止操作',
  permission_mismatch: '権限の不一致',
  markup: 'マークアップ',
  canary: 'カナリア',
  masking: 'マスキング',
}

const TARGET_LABELS: Record<string, string> = { input: '入力', output: 'AI の出力', revision: '計画' }

/** The same sentence the API returns with every scan (docs/security-design.md §4). A list of findings is never "all of them". */
const LIMITATIONS_NOTICE =
  '検出は完全ではなく、氏名・住所など自動検出できない個人情報や秘密情報が含まれている可能性があります。検出されなかった情報が存在しないことは保証されません。'

const NOTE_LIMIT = 500

/** A status change by an admin. The server scans the note like any other text and decides the transition. */
function StatusForm({ finding, onDone }: { finding: Finding; onDone: () => void }) {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<FindingStatus>(NEXT_STATUSES[finding.status][0] ?? finding.status)
  const [note, setNote] = useState('')
  const change = useMutation({
    mutationFn: () => updateFindingStatus(finding.id, status, note),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['security-findings'] })
      onDone()
    },
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    change.mutate()
  }

  return (
    <form className="mt-2 space-y-2 rounded-md bg-slate-50 p-2" aria-label="対策状況の変更" onSubmit={submit}>
      <label className="block">
        新しい状態
        <select
          className="mt-1 w-full rounded-md border border-slate-300 p-1"
          value={status}
          onChange={(event) => {
            setStatus(event.target.value as FindingStatus)
          }}
        >
          {NEXT_STATUSES[finding.status].map((next) => (
            <option key={next} value={next}>
              {STATUS_LABELS[next]}
            </option>
          ))}
        </select>
      </label>
      <label className="block">
        メモ（任意。個人情報はマスキングされ、秘密情報があれば保存されません）
        <input
          className="mt-1 w-full rounded-md border border-slate-300 p-1"
          maxLength={NOTE_LIMIT}
          value={note}
          onChange={(event) => {
            setNote(event.target.value)
          }}
        />
      </label>
      {change.isError && (
        <p role="alert" className="text-red-700">
          {apiErrorMessage(change.error)}
        </p>
      )}
      <div className="flex gap-2">
        <button type="submit" className="rounded-md bg-slate-900 px-3 py-1 text-white disabled:opacity-50" disabled={change.isPending}>
          更新
        </button>
        <button type="button" className="rounded-md border border-slate-300 px-3 py-1" onClick={onDone}>
          取り消し
        </button>
      </div>
    </form>
  )
}

function FindingRow({ finding, canChange }: { finding: Finding; canChange: boolean }) {
  const [editing, setEditing] = useState(false)

  return (
    <tr>
      <td className="whitespace-nowrap p-1 align-top">{finding.created_at}</td>
      <td className="p-1 align-top">{SEVERITY_LABELS[finding.severity]}</td>
      <td className="p-1 align-top">{ACTION_LABELS[finding.action]}</td>
      <td className="p-1 align-top">{CATEGORY_LABELS[finding.category] ?? finding.category}</td>
      <td className="p-1 align-top">
        {finding.scan === undefined ? '-' : (TARGET_LABELS[finding.scan.target_type] ?? finding.scan.target_type)}
      </td>
      <td className="break-all p-1 align-top">
        <div>{finding.message}</div>
        <div className="text-slate-500">{finding.rule_id}</div>
        {finding.masked_excerpt !== null && <div className="text-slate-500">抜粋：{finding.masked_excerpt}</div>}
      </td>
      <td className="p-1 align-top">
        <div>{STATUS_LABELS[finding.status]}</div>
        {finding.status_changed_by !== null && (
          <div className="text-slate-500">
            {finding.status_changed_by.name}・{finding.status_changed_at ?? '-'}
          </div>
        )}
        {finding.status_note !== null && <div className="break-all text-slate-500">{finding.status_note}</div>}
        {canChange && !editing && (
          <button
            type="button"
            className="mt-1 text-xs underline"
            onClick={() => {
              setEditing(true)
            }}
          >
            対策状況を変更
          </button>
        )}
        {canChange && editing && (
          <StatusForm
            finding={finding}
            onDone={() => {
              setEditing(false)
            }}
          />
        )}
      </td>
    </tr>
  )
}

export function SecurityPage() {
  const { data: user } = useCurrentUser()
  const [draft, setDraft] = useState<FindingFilters>(NO_FINDING_FILTERS)
  const [filters, setFilters] = useState<FindingFilters>(NO_FINDING_FILTERS)

  const findings = useInfiniteQuery({
    queryKey: ['security-findings', filters],
    queryFn: ({ pageParam }) => fetchFindings(filters, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.meta.next_cursor,
    retry: false,
  })
  const items = findings.data?.pages.flatMap((page) => page.data) ?? []
  const canChange = user?.role === 'admin'
  const set = (name: keyof FindingFilters, value: string) => {
    setDraft({ ...draft, [name]: value })
  }

  return (
    <section className="space-y-4">
      <div className="space-y-4 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
        <h2 className="text-lg font-semibold">セキュリティ管理</h2>
        <p className="text-xs text-slate-500">
          {user?.role === 'member' ? '自分の入力と計画に対する検出のみを表示します。' : 'この組織の検出を表示します。'}
          {LIMITATIONS_NOTICE}
        </p>

        <form
          className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4"
          onSubmit={(event) => {
            event.preventDefault()
            setFilters(draft)
          }}
        >
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
            対策状況
            <select className="mt-1 w-full rounded-md border border-slate-300 p-2" value={draft.status} onChange={(event) => { set('status', event.target.value) }}>
              <option value="">すべて</option>
              {Object.entries(STATUS_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            分類
            <select className="mt-1 w-full rounded-md border border-slate-300 p-2" value={draft.category} onChange={(event) => { set('category', event.target.value) }}>
              <option value="">すべて</option>
              {Object.entries(CATEGORY_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="self-end rounded-md bg-slate-900 px-3 py-2 text-white">
            絞り込む
          </button>
        </form>

        {findings.isPending && <p className="text-sm text-slate-500">読み込み中…</p>}
        {findings.isError && (
          <p role="alert" className="text-sm text-red-700">
            {apiErrorMessage(findings.error)}
          </p>
        )}
        {findings.isSuccess && items.length === 0 && <p className="text-sm text-slate-500">該当する検出はありません。検出がないことは、安全であることを意味しません。</p>}

        {items.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-500">
                <tr>
                  <th className="p-1 font-normal">日時（UTC）</th>
                  <th className="p-1 font-normal">重大度</th>
                  <th className="p-1 font-normal">処理</th>
                  <th className="p-1 font-normal">分類</th>
                  <th className="p-1 font-normal">対象</th>
                  <th className="p-1 font-normal">検出内容</th>
                  <th className="p-1 font-normal">対策状況</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {items.map((finding) => (
                  <FindingRow key={finding.id} finding={finding} canChange={canChange} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {findings.hasNextPage && (
          <button
            type="button"
            className="rounded-md border border-slate-300 px-3 py-2 text-sm disabled:opacity-50"
            disabled={findings.isFetchingNextPage}
            onClick={() => {
              void findings.fetchNextPage()
            }}
          >
            さらに表示
          </button>
        )}
      </div>

      <div className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
        <h3 className="text-sm font-medium text-slate-700">セキュリティテスト結果</h3>
        {/* Not a zero and not "all passed": nothing has run yet (docs/development-roadmap.md 3-3). */}
        <p className="mt-2 text-sm text-slate-500">未実装（アプリ内の自己診断は工程3-3 で追加されます）。HTTP レベルのテストは CI で実行しています。</p>
      </div>
    </section>
  )
}
