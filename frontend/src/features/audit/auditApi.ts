import { z } from 'zod'
import { apiRequest } from '../../api/client'

/* docs/api-design.md §3.8. Everything here is untrusted until it has been parsed, and is only ever drawn as text. */

const entrySchema = z.object({
  event_id: z.string(),
  chain_seq: z.number(),
  event_type: z.string(),
  result: z.string(),
  severity: z.string().nullable(),
  actor: z.object({ type: z.string(), id: z.string().nullable(), name: z.string().nullable() }),
  resource: z.object({ type: z.string().nullable(), id: z.string().nullable() }),
  ip_address: z.string().nullable(),
  request_id: z.string().nullable(),
  metadata: z.record(z.string(), z.unknown()),
  occurred_at: z.string(),
})

const listSchema = z.object({
  data: z.array(entrySchema),
  meta: z.object({ next_cursor: z.string().nullable() }),
})

const verificationResponse = z
  .object({
    data: z.object({
      valid: z.boolean(),
      checked_count: z.number(),
      first_broken_seq: z.number().nullable(),
      reason_code: z.string().nullable(),
    }),
  })
  .transform((response) => response.data)

export type AuditEntry = z.infer<typeof entrySchema>
export type Verification = z.output<typeof verificationResponse>

export type AuditFilters = { event_type: string; result: string; severity: string; from: string; to: string }

export const NO_FILTERS: AuditFilters = { event_type: '', result: '', severity: '', from: '', to: '' }

/** Empty means not filtered. The days are whole days in UTC, as the times on this screen are. */
function query(filters: AuditFilters, cursor: string | null): string {
  const params = new URLSearchParams()

  for (const name of ['event_type', 'result', 'severity'] as const) {
    if (filters[name] !== '') {
      params.set(name, filters[name])
    }
  }
  if (filters.from !== '') {
    params.set('from', `${filters.from}T00:00:00Z`)
  }
  if (filters.to !== '') {
    params.set('to', `${filters.to}T23:59:59Z`)
  }
  if (cursor !== null) {
    params.set('cursor', cursor)
  }

  const text = params.toString()

  return text === '' ? '' : `?${text}`
}

export function fetchAuditLogs(filters: AuditFilters, cursor: string | null): Promise<z.infer<typeof listSchema>> {
  return apiRequest('GET', `/api/v1/audit-logs${query(filters, cursor)}`, listSchema)
}

export function verifyAuditChain(): Promise<Verification> {
  return apiRequest('POST', '/api/v1/audit-logs/verify', verificationResponse)
}
