import { useInfiniteQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { fetchApprovals } from './workflowApi'
import { apiErrorMessage, CANNOT_APPROVE_LABELS, SEVERITY_LABELS } from './labels'

/** What waits for a decision. Who may decide is the server's answer: this only passes it on. */
export function ApprovalsPage() {
  const approvals = useInfiniteQuery({
    queryKey: ['approvals'],
    queryFn: ({ pageParam }) => fetchApprovals(pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.meta.next_cursor,
  })
  const items = approvals.data?.pages.flatMap((page) => page.data) ?? []

  return (
    <section className="space-y-4 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <h2 className="text-lg font-semibold">承認待ち</h2>

      {approvals.isPending && <p className="text-sm text-slate-500">読み込み中…</p>}
      {approvals.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(approvals.error)}
        </p>
      )}
      {approvals.isSuccess && items.length === 0 && <p className="text-sm text-slate-500">承認待ちのワークフローはありません。</p>}

      <ul className="divide-y divide-slate-200">
        {items.map((item) => (
          <li key={item.workflow_id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
            <Link className="underline" to={`/workflows/${encodeURIComponent(item.workflow_id)}/approval`}>
              {item.title}
            </Link>
            <span className="text-slate-600">
              {item.created_by.name}・リビジョン {item.revision_no ?? '-'}
              {item.max_severity !== null && `・重大度 ${SEVERITY_LABELS[item.max_severity] ?? ''}`}
              {item.cannot_approve_reason !== null && `・${CANNOT_APPROVE_LABELS[item.cannot_approve_reason] ?? '承認できません'}`}
            </span>
          </li>
        ))}
      </ul>

      {approvals.hasNextPage && (
        <button
          type="button"
          className="rounded-md border border-slate-300 px-3 py-2 text-sm disabled:opacity-50"
          disabled={approvals.isFetchingNextPage}
          onClick={() => {
            void approvals.fetchNextPage()
          }}
        >
          さらに表示
        </button>
      )}
    </section>
  )
}
