import { z } from 'zod'
import { apiRequest } from '../../api/client'

/* docs/api-design.md §3.9. The key never comes this way: the server says only whether one is configured. */

const aiSettingsSchema = z.object({
  provider: z.string(),
  model: z.string().nullable(),
  api_key_configured: z.boolean(),
  timeout_seconds: z.number(),
  max_output_tokens: z.number(),
})

export const LIMIT_FIELDS = ['monthly_token_limit', 'user_daily_request_limit', 'max_input_chars'] as const

export type LimitField = (typeof LIMIT_FIELDS)[number]

const limitsSchema = z.object({
  monthly_token_limit: z.number(),
  user_daily_request_limit: z.number(),
  max_input_chars: z.number(),
  updated_at: z.string().nullable(),
  updated_by: z.object({ id: z.string(), name: z.string() }).nullable(),
})

const securitySettingsSchema = z.object({
  policy_version: z.string(),
  ruleset_version: z.string(),
  prompt_version: z.string(),
  input_actions: z.object({
    pii: z.string(),
    secret: z.string(),
    masking_failure: z.string(),
    injection: z.record(z.string(), z.string()),
  }),
  approval: z.object({
    approver_role: z.string(),
    self_approval: z.string(),
    risk_acknowledgement_from: z.string(),
    decisions_per_revision: z.number(),
  }),
})

const aiResponse = z.object({ data: aiSettingsSchema }).transform((response) => response.data)
const limitsResponse = z.object({ data: limitsSchema }).transform((response) => response.data)
const securityResponse = z.object({ data: securitySettingsSchema }).transform((response) => response.data)

export type AiSettings = z.infer<typeof aiSettingsSchema>
export type Limits = z.infer<typeof limitsSchema>
export type SecuritySettings = z.infer<typeof securitySettingsSchema>

export function fetchAiSettings(): Promise<AiSettings> {
  return apiRequest('GET', '/api/v1/settings/ai', aiResponse)
}

export function fetchLimits(): Promise<Limits> {
  return apiRequest('GET', '/api/v1/settings/limits', limitsResponse)
}

/** Only the fields that changed are sent, so the record of the change says only what changed. */
export function updateLimits(changes: Partial<Record<LimitField, number>>): Promise<Limits> {
  return apiRequest('PATCH', '/api/v1/settings/limits', limitsResponse, changes)
}

export function fetchSecuritySettings(): Promise<SecuritySettings> {
  return apiRequest('GET', '/api/v1/settings/security', securityResponse)
}
