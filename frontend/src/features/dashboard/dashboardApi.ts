import { z } from 'zod'
import { apiRequest } from '../../api/client'

/* docs/api-design.md §3.2. null means "does not exist yet", which is not the same as 0. */

const summarySchema = z.object({
  workflows: z.object({
    total: z.number(),
    by_status: z.object({
      draft: z.number(),
      pending: z.number(),
      approved: z.number(),
      running: z.number(),
      completed: z.number(),
      rejected: z.number(),
      failed: z.number(),
    }),
  }),
  executed: z.number(),
  pending_approval: z.number(),
  analyses_this_month: z.number(),
  security: z.object({ warnings: z.number().nullable(), findings: z.number().nullable() }),
  ai_usage: z.object({ tokens: z.number().nullable(), estimated_cost: z.number().nullable() }),
  self_test: z.object({
    latest: z
      .object({
        id: z.string(),
        status: z.enum(['queued', 'running', 'completed', 'failed']),
        total: z.number(),
        passed: z.number(),
        failed: z.number(),
        finished_at: z.string().nullable(),
      })
      .nullable(),
  }),
  recent_operations: z.array(
    z.object({
      id: z.string(),
      event_type: z.string(),
      actor: z.object({ id: z.string(), name: z.string().nullable() }).nullable(),
      resource_type: z.string().nullable(),
      resource_id: z.string().nullable(),
      result: z.string(),
      occurred_at: z.string(),
    }),
  ),
})

const responseSchema = z.object({ data: summarySchema }).transform((response) => response.data)

export type DashboardSummary = z.infer<typeof summarySchema>

export function fetchDashboard(): Promise<DashboardSummary> {
  return apiRequest('GET', '/api/v1/dashboard/summary', responseSchema)
}
