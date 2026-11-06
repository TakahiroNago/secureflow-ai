import { lazy, Suspense } from 'react'
import { STATUS_LABELS } from '../workflows/labels'
import type { DashboardSummary } from './dashboardApi'

const StatusChart = lazy(() => import('./StatusChart'))

/** The order of the life of a workflow, not by size: the shape stays the same as the counts change. */
const ORDER = ['draft', 'pending', 'approved', 'running', 'completed', 'rejected', 'failed'] as const

/** The table is always there: the numbers do not depend on the chart loading, or on seeing color. */
export function StatusCounts({ counts }: { counts: DashboardSummary['workflows']['by_status'] }) {
  const rows = ORDER.map((status) => ({ status, label: STATUS_LABELS[status] ?? status, count: counts[status] }))

  return (
    <div>
      <div className="h-64" aria-hidden="true">
        <Suspense fallback={null}>
          <StatusChart rows={rows} />
        </Suspense>
      </div>
      <details className="mt-2 text-sm">
        <summary className="cursor-pointer text-slate-600">表で見る</summary>
        <table className="mt-2 w-full text-left">
          <caption className="sr-only">状態ごとのワークフロー数</caption>
          <thead>
            <tr className="text-slate-500">
              <th scope="col" className="font-medium">
                状態
              </th>
              <th scope="col" className="text-right font-medium">
                件数
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.status} className="border-t border-slate-100">
                <th scope="row" className="font-normal">
                  {row.label}
                </th>
                <td className="text-right tabular-nums">{row.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  )
}
