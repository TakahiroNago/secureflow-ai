import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, Navigate, useParams } from 'react-router'
import { fetchAnalysis } from './workflowApi'
import { analysisErrorMessage, apiErrorMessage } from './labels'

const POLL_INTERVAL_MS = 1000

/** Longer than the server takes to give up on a running analysis. */
const MAX_POLLS = 200

export function AnalysisPage() {
  const { id = '' } = useParams()
  const [startedAt] = useState(() => Date.now())

  const analysis = useQuery({
    queryKey: ['analyses', id],
    queryFn: () => fetchAnalysis(id),
    retry: false,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      const unfinished = status === 'queued' || status === 'processing'
      return unfinished && query.state.dataUpdateCount < MAX_POLLS ? POLL_INTERVAL_MS : false
    },
  })

  if (analysis.isError) {
    return (
      <section className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(analysis.error)}
        </p>
        <Link className="mt-3 inline-block text-sm underline" to="/workflows">
          一覧へ戻る
        </Link>
      </section>
    )
  }

  if (analysis.data?.status === 'succeeded' && analysis.data.workflow_id !== null) {
    return <Navigate to={`/workflows/${encodeURIComponent(analysis.data.workflow_id)}`} replace />
  }

  if (analysis.data?.status === 'failed' || analysis.data?.status === 'blocked') {
    return (
      <section className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
        <h2 className="text-lg font-semibold">分析できませんでした</h2>
        <p role="alert" className="mt-2 text-sm text-red-700">
          {analysisErrorMessage(analysis.data.error_code)}
        </p>
        <Link className="mt-3 inline-block text-sm underline" to="/analyses/new">
          入力へ戻る
        </Link>
      </section>
    )
  }

  const gaveUp = analysis.dataUpdatedAt - startedAt >= (MAX_POLLS - 1) * POLL_INTERVAL_MS

  return (
    <section className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <h2 className="text-lg font-semibold">分析中</h2>
      <p role="status" className="mt-2 text-sm text-slate-600">
        {gaveUp ? '時間がかかっています。後でワークフローの一覧をご確認ください。' : 'ワークフローを作成しています…'}
      </p>
      <Link className="mt-3 inline-block text-sm underline" to="/workflows">
        一覧へ戻る
      </Link>
    </section>
  )
}
