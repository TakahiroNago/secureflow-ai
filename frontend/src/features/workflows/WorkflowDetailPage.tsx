import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { ApiError } from '../../api/client'
import { addTask, blockedScan, deleteTask, fetchWorkflow, updateTask, updateTitle, type Task, type TaskFields, type Workflow } from './workflowApi'
import { apiErrorMessage, PRIORITY_LABELS, scanLabel, SEVERITY_LABELS, STATUS_LABELS } from './labels'
import { ScanPanel } from './ScanPanel'
import { TaskForm } from './TaskForm'
import { UnscannedNotice } from './UnscannedNotice'

const fieldsOf = (task: Task): TaskFields => ({
  title: task.title,
  description: task.description,
  action_type: task.action_type,
  steps: task.steps,
  priority: task.priority,
  target_data: task.target_data,
  impact_summary: task.impact_summary,
})

export function WorkflowDetailPage() {
  const { id = '' } = useParams()
  const queryClient = useQueryClient()
  const key = ['workflows', id]
  const [editing, setEditing] = useState<string | 'new' | 'title' | null>(null)
  const [title, setTitle] = useState('')

  const workflow = useQuery({ queryKey: key, queryFn: () => fetchWorkflow(id), retry: false })

  const change = useMutation({
    mutationFn: (run: () => Promise<Workflow>) => run(),
    onSuccess: (updated) => {
      queryClient.setQueryData(key, updated)
      setEditing(null)
    },
    onError: (error) => {
      // Someone else saved first: show what is there now, and keep what was typed in the form.
      if (error instanceof ApiError && error.code === 'REVISION_CONFLICT') {
        void queryClient.invalidateQueries({ queryKey: key })
      }
    },
  })

  if (workflow.isPending) {
    return <p className="text-sm text-slate-500">読み込み中…</p>
  }

  if (workflow.isError) {
    return (
      <section className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(workflow.error)}
        </p>
        <Link className="mt-3 inline-block text-sm underline" to="/workflows">
          一覧へ戻る
        </Link>
      </section>
    )
  }

  const current = workflow.data
  const blocked = blockedScan(change.error)
  const revisionNo = current.current_revision?.no ?? 0
  const editable = current.can_edit && current.current_revision !== null

  return (
    <section className="space-y-4 rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <Link className="text-sm underline" to="/workflows">
        一覧へ戻る
      </Link>

      {editing === 'title' ? (
        <form
          className="flex gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            change.mutate(() => updateTitle(id, revisionNo, title))
          }}
        >
          <label className="flex-1 text-sm font-medium">
            ワークフロー名
            <input className="mt-1 w-full rounded-md border border-slate-300 p-2 text-sm" required maxLength={200} value={title} onChange={(event) => { setTitle(event.target.value) }} />
          </label>
          <button type="submit" className="self-end rounded-md bg-slate-900 px-3 py-2 text-sm text-white" disabled={change.isPending}>
            保存
          </button>
        </form>
      ) : (
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{current.title}</h2>
          {editable && (
            <button
              type="button"
              className="text-sm underline"
              onClick={() => {
                setTitle(current.title)
                setEditing('title')
              }}
            >
              名前を変更
            </button>
          )}
        </div>
      )}

      <dl className="grid grid-cols-2 gap-1 text-sm">
        <dt className="text-slate-500">状態</dt>
        <dd>{STATUS_LABELS[current.status]}</dd>
        <dt className="text-slate-500">作成者</dt>
        <dd>{current.created_by.name}</dd>
        <dt className="text-slate-500">リビジョン</dt>
        <dd>{revisionNo}</dd>
        <dt className="text-slate-500">検査</dt>
        <dd>{scanLabel(current.scan)}</dd>
        <dt className="text-slate-500">これまでの最大の重大度</dt>
        <dd>{current.max_severity === null ? 'なし' : SEVERITY_LABELS[current.max_severity]}</dd>
      </dl>

      {current.scan.status === 'not_scanned' && <UnscannedNotice />}
      <ScanPanel scan={current.scan} />

      {change.isError && (
        <p role="alert" className="text-sm text-red-700">
          {apiErrorMessage(change.error)}
        </p>
      )}
      {blocked !== null && <ScanPanel scan={blocked} />}

      <ol className="space-y-3">
        {current.tasks.map((task) => (
          <li key={task.id} className="rounded-md p-3 ring-1 ring-slate-200">
            {editing === task.id ? (
              <TaskForm
                initial={fieldsOf(task)}
                submitLabel="保存"
                busy={change.isPending}
                onCancel={() => { setEditing(null) }}
                onSubmit={(fields) => { change.mutate(() => updateTask(id, task.id, revisionNo, fields)) }}
              />
            ) : (
              <>
                <div className="flex items-center justify-between">
                  <h3 className="font-medium">
                    {task.position}. {task.title}
                  </h3>
                  {task.policy_decision === 'forbidden' && <span className="rounded bg-red-100 px-2 py-0.5 text-xs text-red-800">禁止された操作</span>}
                </div>
                <p className="mt-1 whitespace-pre-wrap text-sm">{task.description}</p>
                <dl className="mt-2 grid grid-cols-2 gap-1 text-xs">
                  <dt className="text-slate-500">操作</dt>
                  <dd>{task.action_type}</dd>
                  <dt className="text-slate-500">権限</dt>
                  <dd>{task.derived_permissions.join('、')}</dd>
                  <dt className="text-slate-500">優先度</dt>
                  <dd>{PRIORITY_LABELS[task.priority]}</dd>
                  <dt className="text-slate-500">対象データ</dt>
                  <dd>{task.target_data}</dd>
                  <dt className="text-slate-500">影響</dt>
                  <dd>{task.impact_summary}</dd>
                </dl>
                <ul className="mt-2 list-disc pl-5 text-sm">
                  {task.steps.map((step, index) => (
                    <li key={index}>{step}</li>
                  ))}
                </ul>
                {editable && (
                  <div className="mt-2 flex gap-3 text-sm">
                    <button type="button" className="underline" onClick={() => { setEditing(task.id) }}>
                      編集
                    </button>
                    <button
                      type="button"
                      className="underline disabled:opacity-50"
                      disabled={change.isPending || current.tasks.length <= 1}
                      onClick={() => { change.mutate(() => deleteTask(id, task.id, revisionNo)) }}
                    >
                      削除
                    </button>
                  </div>
                )}
              </>
            )}
          </li>
        ))}
      </ol>

      {editable &&
        current.tasks.length < 10 &&
        (editing === 'new' ? (
          <TaskForm
            submitLabel="追加"
            busy={change.isPending}
            onCancel={() => { setEditing(null) }}
            onSubmit={(fields) => { change.mutate(() => addTask(id, revisionNo, fields)) }}
          />
        ) : (
          <button type="button" className="rounded-md border border-slate-300 px-3 py-2 text-sm" onClick={() => { setEditing('new') }}>
            タスクを追加
          </button>
        ))}
    </section>
  )
}
