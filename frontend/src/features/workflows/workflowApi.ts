import { z } from 'zod'
import { ApiError, apiRequest } from '../../api/client'

/* docs/api-design.md §3.3, §3.4. Everything here is untrusted until it has been parsed, and text is only ever drawn as text. */

const severitySchema = z.enum(['low', 'medium', 'high', 'critical'])

const findingSchema = z.object({
  category: z.string(),
  rule_id: z.string(),
  severity: severitySchema,
  action: z.enum(['record', 'mask_continue', 'warn', 'block']),
  message: z.string(),
  field: z.string().nullable(),
  position_start: z.number().nullable(),
  position_end: z.number().nullable(),
})

const scanSchema = z.object({
  status: z.enum(['not_scanned', 'scanned']),
  decision: z.enum(['allow', 'warn', 'block']).nullable(),
  block_reason: z.string().nullable(),
  max_severity: severitySchema.nullable(),
  masking_status: z.string().nullable(),
  masked_input: z.string().optional(),
  findings: z.array(findingSchema),
  findings_count: z.number(),
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
  max_severity: severitySchema.nullable(),
  can_edit: z.boolean(),
  tasks: z.array(taskSchema),
})

const listSchema = z.object({
  data: z.array(summarySchema),
  meta: z.object({ next_cursor: z.string().nullable() }),
})

const analysisResponse = z.object({ data: analysisSchema }).transform((response) => response.data)
const workflowResponse = z.object({ data: workflowSchema }).transform((response) => response.data)
const scanResponse = z.object({ data: scanSchema }).transform((response) => response.data)

export type Scan = z.infer<typeof scanSchema>
export type Finding = z.infer<typeof findingSchema>
export type Analysis = z.infer<typeof analysisSchema>
export type WorkflowSummary = z.infer<typeof summarySchema>
export type Workflow = z.infer<typeof workflowSchema>
export type Task = z.infer<typeof taskSchema>
export type TaskFields = Pick<Task, 'title' | 'description' | 'action_type' | 'steps' | 'priority' | 'target_data' | 'impact_summary'>

const revision = (no: number) => ({ 'If-Match': `"${String(no)}"` })

export function previewScan(input: string): Promise<Scan> {
  return apiRequest('POST', '/api/v1/security/scan-preview', scanResponse, { input })
}

/** The scan in a refusal, or null for any other error. */
export function blockedScan(error: unknown): Scan | null {
  if (!(error instanceof ApiError) || error.code !== 'INPUT_BLOCKED') {
    return null
  }

  const parsed = scanSchema.safeParse(error.scan)

  return parsed.success ? parsed.data : null
}

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
