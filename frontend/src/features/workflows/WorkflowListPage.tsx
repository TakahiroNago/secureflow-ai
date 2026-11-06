import { useInfiniteQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { useCurrentUser } from '../auth/useAuth'
import { fetchWorkflows } from './workflowApi'
import { apiErrorMessage, STATUS_LABELS } from './labels'

export function WorkflowListPage() {
  const { data: user } = useCurrentUser()
  const workflows = useInfiniteQuery({
    queryKey: ['workflows'],
    queryFn: ({ pageParam }) => fetchWorkflows(pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.meta.next_cursor,
  })
  const items = workflows.data?.pages.flatMap((page) => page.data) ?? []

  return (
    <section className="space-y-4 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">ワークフロー</h2>
        <div className="flex items-center gap-3 text-sm">
          <Link className="underline" to="/">
            ホーム
          </Link>
          {user?.role !== 'auditor' && (
            <Link className="rounded-md bg-slate-900 px-3 py-2 font-medium text-white" to="/analyses/new">
              新しく作成
            </Link>
          )}
        </div>
      </div>

      {workflows.isPending && <p className="text-sm text-slate-500">読み込み中…</p>}
      {workflows.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(workflows.error)}
        </p>
      )}
      {workflows.isSuccess && items.length === 0 && <p className="text-sm text-slate-500">ワークフローはまだありません。</p>}

      <ul className="divide-y divide-slate-200">
        {items.map((workflow) => (
          <li key={workflow.id} className="flex items-center justify-between py-2 text-sm">
            <Link className="underline" to={`/workflows/${encodeURIComponent(workflow.id)}`}>
              {workflow.title}
            </Link>
            <span className="text-slate-600">
              {STATUS_LABELS[workflow.status]}・{workflow.created_by.name}
            </span>
          </li>
        ))}
      </ul>

      {workflows.hasNextPage && (
        <button
          type="button"
          className="rounded-md border border-slate-300 px-3 py-2 text-sm disabled:opacity-50"
          disabled={workflows.isFetchingNextPage}
          onClick={() => {
            void workflows.fetchNextPage()
          }}
        >
          さらに表示
        </button>
      )}
    </section>
  )
}
