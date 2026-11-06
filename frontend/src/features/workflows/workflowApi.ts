import { z } from 'zod'
import { apiRequest } from '../../api/client'

/* docs/api-design.md §3.3, §3.4. Everything here is untrusted until it has been parsed, and text is only ever drawn as text. */

const scanSchema = z.object({
  status: z.enum(['not_scanned', 'scanned']),
  decision: z.string().nullable(),
  limitations_notice: z.string(),
})

const analysisSchema = z.object({
  id: z.string(),
  status: z.enum(['queued', 'processing', 'succeeded', 'blocked', 'failed']),
  workflow_id: z.string().nullable(),
  error_code: z.string().nullable(),
  scan: scanSchema,
})

export const workflowStatusSchema = z.enum(['draft', 'pending', 'approved', 'running', 'completed', 'rejected', 'failed'])

const personSchema = z.object({ id: z.string(), name: z.string() })

const summarySchema = z.object({
  id: z.string(),
  title: z.string(),
  status: workflowStatusSchema,
  revision_no: z.number().nullable(),
  created_by: personSchema,
  created_at: z.string().nullable(),
  updated_at: z.string().nullable(),
})

const taskSchema = z.object({
  id: z.string(),
  position: z.number(),
  title: z.string(),
  description: z.string(),
  action_type: z.string(),
  steps: z.array(z.string()),
  priority: z.enum(['low', 'medium', 'high']),
  target_data: z.string(),
  impact_summary: z.string(),
  derived_permissions: z.array(z.string()),
  policy_decision: z.enum(['allowed', 'forbidden']),
})

const workflowSchema = z.object({
  id: z.string(),
  title: z.string(),
  status: workflowStatusSchema,
  created_by: personSchema,
  current_revision: z.object({ no: z.number(), plan_hash: z.string(), policy_version: z.string() }).nullable(),
  scan: scanSchema,
  can_edit: z.boolean(),
  tasks: z.array(taskSchema),
})

const listSchema = z.object({
  data: z.array(summarySchema),
  meta: z.object({ next_cursor: z.string().nullable() }),
})

const analysisResponse = z.object({ data: analysisSchema }).transform((response) => response.data)
const workflowResponse = z.object({ data: workflowSchema }).transform((response) => response.data)

export type Analysis = z.infer<typeof analysisSchema>
export type WorkflowSummary = z.infer<typeof summarySchema>
export type Workflow = z.infer<typeof workflowSchema>
export type Task = z.infer<typeof taskSchema>
export type TaskFields = Pick<Task, 'title' | 'description' | 'action_type' | 'steps' | 'priority' | 'target_data' | 'impact_summary'>

const revision = (no: number) => ({ 'If-Match': `"${String(no)}"` })

export function requestAnalysis(input: string): Promise<Analysis> {
  return apiRequest('POST', '/api/v1/analyses', analysisResponse, { input })
}

export function fetchAnalysis(id: string): Promise<Analysis> {
  return apiRequest('GET', `/api/v1/analyses/${encodeURIComponent(id)}`, analysisResponse)
}

export function fetchWorkflows(cursor: string | null): Promise<z.infer<typeof listSchema>> {
  const query = cursor === null ? '' : `?cursor=${encodeURIComponent(cursor)}`
  return apiRequest('GET', `/api/v1/workflows${query}`, listSchema)
}

export function fetchWorkflow(id: string): Promise<Workflow> {
  return apiRequest('GET', `/api/v1/workflows/${encodeURIComponent(id)}`, workflowResponse)
}

export function updateTitle(id: string, revisionNo: number, title: string): Promise<Workflow> {
  return apiRequest('PATCH', `/api/v1/workflows/${encodeURIComponent(id)}`, workflowResponse, { title }, revision(revisionNo))
}

export function addTask(id: string, revisionNo: number, fields: TaskFields): Promise<Workflow> {
  return apiRequest('POST', `/api/v1/workflows/${encodeURIComponent(id)}/tasks`, workflowResponse, fields, revision(revisionNo))
}

export function updateTask(id: string, taskId: string, revisionNo: number, fields: TaskFields): Promise<Workflow> {
  return apiRequest('PUT', `/api/v1/workflows/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskId)}`, workflowResponse, fields, revision(revisionNo))
}

export function deleteTask(id: string, taskId: string, revisionNo: number): Promise<Workflow> {
  return apiRequest('DELETE', `/api/v1/workflows/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskId)}`, workflowResponse, undefined, revision(revisionNo))
}
