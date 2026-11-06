import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { apiErrorMessage } from '../workflows/labels'
import { fetchDashboard, type DashboardSummary } from './dashboardApi'
import { StatusCounts } from './StatusCounts'

const EVENT_LABELS: Record<string, string> = {
  'auth.login': 'ログイン',
  'auth.logout': 'ログアウト',
  'workflow.created': 'ワークフローを作成',
  'workflow.updated': 'ワークフローを更新',
}

const cardClass = 'rounded-lg bg-white p-4 shadow-sm ring-1 ring-slate-200'

function Tile({ label, value }: { label: string; value: number | null }) {
  return (
    <div className={cardClass}>
      <dt className="text-sm text-slate-500">{label}</dt>
      {value === null ? (
        // Not a zero: nothing has looked yet, and "0 warnings" would read as "safe".
        <dd className="mt-1 text-sm font-medium text-slate-500">未実装</dd>
      ) : (
        <dd className="mt-1 text-2xl font-semibold tabular-nums text-slate-900">{value}</dd>
      )}
    </div>
  )
}

function RecentOperations({ operations }: { operations: DashboardSummary['recent_operations'] }) {
  if (operations.length === 0) {
    return <p className="mt-2 text-sm text-slate-500">まだ操作はありません。</p>
  }

  return (
    <ul className="mt-2 divide-y divide-slate-100 text-sm">
      {operations.map((operation) => (
        <li key={operation.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
          <span>
            {operation.resource_type === 'workflow' && operation.resource_id !== null ? (
              <Link className="underline" to={`/workflows/${encodeURIComponent(operation.resource_id)}`}>
                {EVENT_LABELS[operation.event_type] ?? '操作'}
              </Link>
            ) : (
              (EVENT_LABELS[operation.event_type] ?? '操作')
            )}
            <span className="ml-2 text-slate-500">{operation.actor?.name ?? 'システム'}</span>
          </span>
          <time className="text-xs text-slate-500" dateTime={operation.occurred_at}>
            {new Date(operation.occurred_at).toLocaleString('ja-JP')}
          </time>
        </li>
      ))}
    </ul>
  )
}

export function DashboardPage() {
  // Not kept between visits: a number from a moment ago, shown as if current, is worse than a short wait.
  const summary = useQuery({ queryKey: ['dashboard'], queryFn: fetchDashboard, retry: false, gcTime: 0 })

  return (
    <section className="space-y-4">
      <h2 className="text-lg font-semibold">ダッシュボード</h2>

      {summary.isPending && <p className="text-sm text-slate-500">読み込み中…</p>}
      {summary.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(summary.error)}
        </p>
      )}

      {summary.data && (
        <>
          <dl className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Tile label="ワークフロー数" value={summary.data.workflows.total} />
            <Tile label="実行済みワークフロー" value={summary.data.executed} />
            <Tile label="承認待ちワークフロー" value={summary.data.pending_approval} />
            <Tile label="今月の分析回数" value={summary.data.analyses_this_month} />
            <Tile label="セキュリティ警告" value={summary.data.security.warnings} />
            <Tile label="検出されたリスク" value={summary.data.security.findings} />
            <Tile label="AI トークン" value={summary.data.ai_usage.tokens} />
            <Tile label="AI 推定費用" value={summary.data.ai_usage.estimated_cost} />
          </dl>

          <div className="grid gap-3 md:grid-cols-2">
            <div className={cardClass}>
              <h3 className="text-sm font-medium text-slate-700">状態ごとのワークフロー数</h3>
              {summary.data.workflows.total === 0 ? (
                <p className="mt-2 text-sm text-slate-500">
                  ワークフローはまだありません。
                </p>
              ) : (
                <StatusCounts counts={summary.data.workflows.by_status} />
              )}
            </div>
            <div className={cardClass}>
              <h3 className="text-sm font-medium text-slate-700">最近の操作</h3>
              <RecentOperations operations={summary.data.recent_operations} />
            </div>
          </div>
        </>
      )}
    </section>
  )
}
