import { z } from 'zod'
import { apiRequest } from '../../api/client'

/* docs/api-design.md §3.7. Everything here is untrusted until it has been parsed, and is only ever drawn as text. */

export const FINDING_STATUSES = ['open', 'acknowledged', 'resolved', 'false_positive'] as const

const findingStatusSchema = z.enum(FINDING_STATUSES)

const findingSchema = z.object({
  id: z.string(),
  category: z.string(),
  rule_id: z.string(),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  action: z.enum(['record', 'mask_continue', 'warn', 'block']),
  message: z.string(),
  masked_excerpt: z.string().nullable(),
  field: z.string().nullable(),
  status: findingStatusSchema,
  status_note: z.string().nullable(),
  status_changed_by: z.object({ id: z.string(), name: z.string() }).nullable(),
  status_changed_at: z.string().nullable(),
  created_at: z.string(),
  scan: z
    .object({
      id: z.string(),
      target_type: z.string(),
      target_id: z.string().nullable(),
      decision: z.string(),
      block_reason: z.string().nullable(),
      max_severity: z.string().nullable(),
      created_at: z.string(),
    })
    .optional(),
})

const listSchema = z.object({
  data: z.array(findingSchema),
  meta: z.object({ next_cursor: z.string().nullable() }),
})

const findingResponse = z.object({ data: findingSchema }).transform((response) => response.data)

export type Finding = z.infer<typeof findingSchema>
export type FindingStatus = z.infer<typeof findingStatusSchema>

export type FindingFilters = { severity: string; status: string; category: string }

export const NO_FINDING_FILTERS: FindingFilters = { severity: '', status: '', category: '' }

/** The same transitions as the server (docs/security-design.md §20). For choosing only: the server decides. */
export const NEXT_STATUSES: Record<FindingStatus, FindingStatus[]> = {
  open: ['acknowledged', 'resolved', 'false_positive'],
  acknowledged: ['resolved', 'false_positive', 'open'],
  resolved: ['open'],
  false_positive: ['open'],
}

function query(filters: FindingFilters, cursor: string | null): string {
  const params = new URLSearchParams()

  for (const name of ['severity', 'status', 'category'] as const) {
    if (filters[name] !== '') {
      params.set(name, filters[name])
    }
  }
  if (cursor !== null) {
    params.set('cursor', cursor)
  }

  const text = params.toString()

  return text === '' ? '' : `?${text}`
}

export function fetchFindings(filters: FindingFilters, cursor: string | null): Promise<z.infer<typeof listSchema>> {
  return apiRequest('GET', `/api/v1/security/findings${query(filters, cursor)}`, listSchema)
}

/** An empty note is not sent: the server treats it as no note anyway, and the previous note is replaced. */
export function updateFindingStatus(id: string, status: FindingStatus, note: string): Promise<Finding> {
  return apiRequest('PATCH', `/api/v1/security/findings/${encodeURIComponent(id)}`, findingResponse, {
    status,
    ...(note === '' ? {} : { status_note: note }),
  })
}
