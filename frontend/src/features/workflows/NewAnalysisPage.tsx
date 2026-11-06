import { useMutation } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { blockedScan, previewScan, requestAnalysis, type Finding } from './workflowApi'
import { apiErrorMessage } from './labels'
import { ScanPanel } from './ScanPanel'

/** Shown before anything has been scanned. Every answer from the server carries the same notice. */
const NOTICE_BEFORE_SCAN = '入力は検査され、検出できた個人情報はマスキングされます。検出は完全ではないため、機密情報を入力しないでください。'

/** The server counts characters, and a text field counts UTF-16 units. */
const unitsBefore = (text: string, characters: number) => Array.from(text).slice(0, characters).join('').length

export function NewAnalysisPage() {
  const [input, setInput] = useState('')
  const field = useRef<HTMLTextAreaElement>(null)
  const navigate = useNavigate()

  const preview = useMutation({ mutationFn: previewScan })
  const analysis = useMutation({
    mutationFn: requestAnalysis,
    onSuccess: (created) => {
      void navigate(`/analyses/${encodeURIComponent(created.id)}`)
    },
  })

  const blocked = blockedScan(analysis.error)
  const shown = blocked ?? preview.data

  /** After a stop there is no masked text. The positions point into what is still in the field. */
  const locate = (finding: Finding) => {
    const element = field.current
    if (element === null || finding.position_start === null || finding.position_end === null) {
      return
    }
    element.focus()
    element.setSelectionRange(unitsBefore(input, finding.position_start), unitsBefore(input, finding.position_end))
  }

  return (
    <section className="space-y-4 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <h2 className="text-lg font-semibold">業務内容の入力</h2>
      <p className="text-sm text-slate-600">{NOTICE_BEFORE_SCAN}</p>
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault()
          preview.reset()
          analysis.mutate(input)
        }}
      >
        <label className="block text-sm font-medium" htmlFor="analysis-input">
          依頼内容
        </label>
        <textarea
          ref={field}
          id="analysis-input"
          className="w-full rounded-md border border-slate-300 p-2 text-sm"
          rows={6}
          maxLength={20000}
          required
          value={input}
          onChange={(event) => {
            setInput(event.target.value)
            // What was found was found in the text as it was.
            preview.reset()
            analysis.reset()
          }}
        />
        {analysis.isError && (
          <p role="alert" className="text-sm text-red-700">
            {apiErrorMessage(analysis.error)}
          </p>
        )}
        {preview.isError && (
          <p role="alert" className="text-sm text-red-700">
            {apiErrorMessage(preview.error)}
          </p>
        )}
        {shown !== undefined && shown !== null && <ScanPanel scan={shown} {...(shown.decision === 'block' ? { onLocate: locate } : {})} />}
        <div className="flex items-center gap-3">
          <button type="submit" className="rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50" disabled={analysis.isPending}>
            分析する
          </button>
          <button
            type="button"
            className="rounded-md border border-slate-300 px-3 py-2 text-sm disabled:opacity-50"
            disabled={preview.isPending || input.trim() === ''}
            onClick={() => {
              analysis.reset()
              preview.mutate(input)
            }}
          >
            送信前に確認
          </button>
          <Link className="text-sm text-slate-600 underline" to="/workflows">
            一覧へ戻る
          </Link>
        </div>
      </form>
    </section>
  )
}
