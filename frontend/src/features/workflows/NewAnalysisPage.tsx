import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { requestAnalysis } from './workflowApi'
import { apiErrorMessage } from './labels'
import { UnscannedNotice } from './UnscannedNotice'

export function NewAnalysisPage() {
  const [input, setInput] = useState('')
  const navigate = useNavigate()
  const analysis = useMutation({
    mutationFn: requestAnalysis,
    onSuccess: (created) => {
      void navigate(`/analyses/${encodeURIComponent(created.id)}`)
    },
  })

  return (
    <section className="space-y-4 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <h2 className="text-lg font-semibold">業務内容の入力</h2>
      <UnscannedNotice />
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault()
          analysis.mutate(input)
        }}
      >
        <label className="block text-sm font-medium" htmlFor="analysis-input">
          依頼内容
        </label>
        <textarea
          id="analysis-input"
          className="w-full rounded-md border border-slate-300 p-2 text-sm"
          rows={6}
          maxLength={20000}
          required
          value={input}
          onChange={(event) => {
            setInput(event.target.value)
          }}
        />
        {analysis.isError && (
          <p role="alert" className="text-sm text-red-700">
            {apiErrorMessage(analysis.error)}
          </p>
        )}
        <div className="flex items-center gap-3">
          <button type="submit" className="rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50" disabled={analysis.isPending}>
            分析する
          </button>
          <Link className="text-sm text-slate-600 underline" to="/workflows">
            一覧へ戻る
          </Link>
        </div>
      </form>
    </section>
  )
}
