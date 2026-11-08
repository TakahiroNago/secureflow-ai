import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import { useCurrentUser } from '../auth/useAuth'
import { apiErrorMessage } from '../workflows/labels'
import { fetchTestRun, fetchTestRuns, isActiveRun, startTestRun, type RunStatus, type TestResult, type TestRun } from './selfTestApi'

export const RUN_STATUS_LABELS: Record<RunStatus, string> = { queued: '実行待ち', running: '実行中', completed: '完了', failed: '失敗' }

const CATEGORY_LABELS: Record<string, string> = { input: '入力検査', output: 'AI 出力', authorization: '認可', workflow: 'ワークフロー', audit: '監査ログ' }

/** How often a queued or running run is read again, and for how long at most (2 minutes). */
const POLL_MS = 2000
const POLL_LIMIT = 60

/** A run's one-line summary, as text. */
export function runSummary(run: Pick<TestRun, 'status' | 'total' | 'passed' | 'failed'>): string {
  if (run.status === 'completed') {
    return `${String(run.passed)} / ${String(run.total)} 合格${run.failed > 0 ? `（${String(run.failed)} 件失敗）` : ''}`
  }
  return RUN_STATUS_LABELS[run.status]
}

function ResultRow({ result }: { result: TestResult }) {
  return (
    <tr className={result.passed ? '' : 'bg-red-50'}>
      <td className="whitespace-nowrap p-1 align-top">{result.case_id}</td>
      <td className="p-1 align-top">{CATEGORY_LABELS[result.category] ?? result.category}</td>
      <td className="p-1 align-top">{result.name}</td>
      <td className="p-1 align-top">{result.expected}</td>
      <td className="p-1 align-top">{result.actual}</td>
      <td className="p-1 align-top">{result.passed ? '合格' : <span className="font-medium text-red-700">失敗</span>}</td>
    </tr>
  )
}

/**
 * The in-app self-test (docs/test-strategy.md §6): the latest run, its results, and what only CI checks. An admin can
 * start one. A failed case is drawn in red: it means a security check of this installation did not hold.
 */
export function SelfTestSection() {
  const { data: user } = useCurrentUser()
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<string | null>(null)
  const polls = useRef(0)

  const runs = useQuery({ queryKey: ['security-test-runs'], queryFn: () => fetchTestRuns(null), retry: false })
  const latest = runs.data?.data[0] ?? null
  const runId = selected ?? latest?.id ?? null

  const detail = useQuery({
    queryKey: ['security-test-run', runId],
    queryFn: () => fetchTestRun(runId ?? ''),
    enabled: runId !== null,
    retry: false,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      if (status !== undefined && isActiveRun(status) && polls.current < POLL_LIMIT) {
        polls.current += 1
        return POLL_MS
      }
      return false
    },
  })

  const start = useMutation({
    mutationFn: startTestRun,
    onSuccess: async (run) => {
      polls.current = 0
      setSelected(run.id)
      await queryClient.invalidateQueries({ queryKey: ['security-test-runs'] })
    },
  })

  const run = detail.data ?? latest
  const active = run !== null && run !== undefined && isActiveRun(run.status)
  const results = detail.data?.results ?? []
  const failedFirst = [...results].sort((a, b) => Number(a.passed) - Number(b.passed) || a.case_id.localeCompare(b.case_id))

  return (
    <div className="space-y-3 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <h3 className="text-sm font-medium text-slate-700">セキュリティ自己診断</h3>
      <p className="text-xs text-slate-500">
        この環境の検出エンジン・Policy・承認と実行の規則を、モック AI とサービス層で直接確認します（HTTP を自分に送らず、作ったデータは残しません）。HTTP レベルの検査は CI で行います。
      </p>

      {runs.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(runs.error)}
        </p>
      )}

      {run === null || run === undefined ? (
        runs.isSuccess && <p className="text-sm text-slate-500">まだ実行されていません。</p>
      ) : (
        <dl className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
          <dt className="text-slate-500">最新の結果</dt>
          <dd className={run.status === 'completed' && run.failed === 0 ? 'font-medium text-emerald-800' : run.status === 'failed' || run.failed > 0 ? 'font-medium text-red-700' : ''}>
            {runSummary(run)}
            {run.error_code !== null && <span className="ml-1 text-xs text-slate-500">（{run.error_code}）</span>}
          </dd>
          <dt className="text-slate-500">実行日時（UTC）</dt>
          <dd>{run.finished_at ?? run.started_at ?? run.created_at}</dd>
          <dt className="text-slate-500">実行者</dt>
          <dd>{run.triggered_by?.name ?? '-'}</dd>
          <dt className="text-slate-500">ルール・ポリシーの版</dt>
          <dd>
            {run.ruleset_version ?? '-'} / {run.policy_version ?? '-'}
          </dd>
        </dl>
      )}

      {user?.role === 'admin' && (
        <div className="flex items-center gap-3">
          <button
            type="button"
            className="rounded-md bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
            disabled={start.isPending || active}
            onClick={() => {
              start.mutate()
            }}
          >
            自己診断を実行
          </button>
          {active && <span className="text-xs text-slate-500">実行中です。結果は自動で更新されます。</span>}
          {start.isError && (
            <p role="alert" className="text-sm text-red-700">
              {apiErrorMessage(start.error)}
            </p>
          )}
        </div>
      )}

      {detail.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(detail.error)}
        </p>
      )}

      {failedFirst.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs" aria-label="自己診断の結果">
            <thead className="text-slate-500">
              <tr>
                <th className="p-1 font-normal">ケース</th>
                <th className="p-1 font-normal">分類</th>
                <th className="p-1 font-normal">内容</th>
                <th className="p-1 font-normal">期待</th>
                <th className="p-1 font-normal">結果</th>
                <th className="p-1 font-normal">合否</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {failedFirst.map((result) => (
                <ResultRow key={result.case_id} result={result} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {detail.data?.ci_only_cases !== undefined && detail.data.ci_only_cases.length > 0 && (
        <details className="text-xs text-slate-500">
          <summary>CI でのみ検証するケース（{detail.data.ci_only_cases.length} 件）</summary>
          <ul className="mt-1 list-inside list-disc">
            {detail.data.ci_only_cases.map((item) => (
              <li key={item.case_id}>
                {item.case_id}：{item.name}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}
