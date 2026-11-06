import { useState } from 'react'
import { ACTION_TYPES, PRIORITY_LABELS } from './labels'
import type { TaskFields } from './workflowApi'

const EMPTY: TaskFields = {
  title: '',
  description: '',
  action_type: 'text.analyze',
  steps: [],
  priority: 'medium',
  target_data: '',
  impact_summary: '',
}

interface Props {
  initial?: TaskFields | undefined
  submitLabel: string
  busy: boolean
  onSubmit: (fields: TaskFields) => void
  onCancel: () => void
}

const inputClass = 'mt-1 w-full rounded-md border border-slate-300 p-2 text-sm'

/** Permissions and the policy decision are not here: the server derives them from the action. */
export function TaskForm({ initial = EMPTY, submitLabel, busy, onSubmit, onCancel }: Props) {
  const [fields, setFields] = useState<TaskFields>(initial)
  const [steps, setSteps] = useState(initial.steps.join('\n'))
  const set = (patch: Partial<TaskFields>) => {
    setFields((current) => ({ ...current, ...patch }))
  }

  return (
    <form
      className="space-y-3 rounded-md bg-slate-50 p-3"
      onSubmit={(event) => {
        event.preventDefault()
        onSubmit({ ...fields, steps: steps.split('\n').filter((step) => step.trim() !== '') })
      }}
    >
      <label className="block text-sm font-medium">
        タイトル
        <input className={inputClass} required maxLength={100} value={fields.title} onChange={(event) => { set({ title: event.target.value }) }} />
      </label>
      <label className="block text-sm font-medium">
        説明
        <textarea className={inputClass} required maxLength={1000} value={fields.description} onChange={(event) => { set({ description: event.target.value }) }} />
      </label>
      <label className="block text-sm font-medium">
        操作
        <select className={inputClass} value={fields.action_type} onChange={(event) => { set({ action_type: event.target.value }) }}>
          {ACTION_TYPES.map((action) => (
            <option key={action} value={action}>
              {action}
            </option>
          ))}
        </select>
      </label>
      <label className="block text-sm font-medium">
        手順（1行に1つ）
        <textarea className={inputClass} required value={steps} onChange={(event) => { setSteps(event.target.value) }} />
      </label>
      <label className="block text-sm font-medium">
        優先度
        <select className={inputClass} value={fields.priority} onChange={(event) => { set({ priority: event.target.value as TaskFields['priority'] }) }}>
          {Object.entries(PRIORITY_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <label className="block text-sm font-medium">
        対象データ
        <input className={inputClass} required maxLength={500} value={fields.target_data} onChange={(event) => { set({ target_data: event.target.value }) }} />
      </label>
      <label className="block text-sm font-medium">
        影響
        <textarea className={inputClass} required maxLength={1000} value={fields.impact_summary} onChange={(event) => { set({ impact_summary: event.target.value }) }} />
      </label>
      <div className="flex gap-2">
        <button type="submit" className="rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50" disabled={busy}>
          {submitLabel}
        </button>
        <button type="button" className="rounded-md border border-slate-300 px-3 py-2 text-sm" onClick={onCancel}>
          キャンセル
        </button>
      </div>
    </form>
  )
}
