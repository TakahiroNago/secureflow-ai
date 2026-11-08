import { z } from 'zod'
import { apiRequest } from '../../api/client'

/* docs/api-design.md §3.7, step 3-3. Everything here is untrusted until it has been parsed, and is only ever drawn as text. */

export const RUN_STATUSES = ['queued', 'running', 'completed', 'failed'] as const

const runStatusSchema = z.enum(RUN_STATUSES)

const resultSchema = z.object({
  case_id: z.string(),
  category: z.string(),
  name: z.string(),
  expected: z.string(),
  actual: z.string(),
  passed: z.boolean(),
  duration_ms: z.number(),
  details: z.record(z.string(), z.unknown()),
})

const runSchema = z.object({
  id: z.string(),
  status: runStatusSchema,
  total: z.number(),
  passed: z.number(),
  failed: z.number(),
  ruleset_version: z.string().nullable(),
  policy_version: z.string().nullable(),
  error_code: z.string().nullable(),
  triggered_by: z.object({ id: z.string(), name: z.string() }).nullable(),
  created_at: z.string(),
  started_at: z.string().nullable(),
  finished_at: z.string().nullable(),
  results: z.array(resultSchema).optional(),
  ci_only_cases: z.array(z.object({ case_id: z.string(), name: z.string() })).optional(),
})

const listSchema = z.object({
  data: z.array(runSchema),
  meta: z.object({ next_cursor: z.string().nullable() }),
})

const runResponse = z.object({ data: runSchema }).transform((response) => response.data)

export type TestRun = z.infer<typeof runSchema>
export type TestResult = z.infer<typeof resultSchema>
export type RunStatus = z.infer<typeof runStatusSchema>

export function fetchTestRuns(cursor: string | null): Promise<z.infer<typeof listSchema>> {
  return apiRequest('GET', `/api/v1/security/test-runs${cursor === null ? '' : `?cursor=${encodeURIComponent(cursor)}`}`, listSchema)
}

export function fetchTestRun(id: string): Promise<TestRun> {
  return apiRequest('GET', `/api/v1/security/test-runs/${encodeURIComponent(id)}`, runResponse)
}

export function startTestRun(): Promise<TestRun> {
  return apiRequest('POST', '/api/v1/security/test-runs', runResponse)
}

export const isActiveRun = (status: RunStatus): boolean => status === 'queued' || status === 'running'
