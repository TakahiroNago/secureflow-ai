import { z } from 'zod'

/*
 * API client: same-origin cookie session with a CSRF token (docs/api-design.md §1).
 * No credential or token is ever stored by this code: the session cookie is HttpOnly and the
 * CSRF token is read from its cookie for each request.
 */

const problemSchema = z.object({
  code: z.string(),
  detail: z.string().optional(),
  errors: z.record(z.string(), z.array(z.string())).optional(),
})

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly detail: string | undefined
  readonly fieldErrors: Record<string, string[]>
  readonly retryAfterSeconds: number | undefined

  constructor(
    status: number,
    code: string,
    options: { detail?: string | undefined; fieldErrors?: Record<string, string[]> | undefined; retryAfterSeconds?: number | undefined } = {},
  ) {
    super(code)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.detail = options.detail
    this.fieldErrors = options.fieldErrors ?? {}
    this.retryAfterSeconds = options.retryAfterSeconds
  }
}

const COOKIE_PREFIX = 'XSRF-TOKEN='

function readCsrfToken(): string | null {
  const entry = document.cookie.split('; ').find((cookie) => cookie.startsWith(COOKIE_PREFIX))
  return entry ? decodeURIComponent(entry.slice(COOKIE_PREFIX.length)) : null
}

async function refreshCsrfCookie(): Promise<void> {
  await fetch('/sanctum/csrf-cookie', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
}

async function toApiError(response: Response): Promise<ApiError> {
  const body: unknown = await response.json().catch(() => null)
  const problem = problemSchema.safeParse(body)
  const retryAfter = Number(response.headers.get('Retry-After'))

  return new ApiError(response.status, problem.success ? problem.data.code : 'UNKNOWN_ERROR', {
    detail: problem.success ? problem.data.detail : undefined,
    fieldErrors: problem.success ? problem.data.errors : undefined,
    retryAfterSeconds: Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
  })
}

async function send(method: string, path: string, body: unknown): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  const token = readCsrfToken()

  if (token !== null) {
    headers['X-XSRF-TOKEN'] = token
  }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }

  return fetch(path, {
    method,
    credentials: 'same-origin',
    headers,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  })
}

/**
 * Sends a request and validates the response. A response of the wrong shape is an error,
 * because responses are untrusted input until they have been checked.
 */
export async function apiRequest<Schema extends z.ZodType>(
  method: 'GET' | 'POST' | 'PATCH',
  path: string,
  schema: Schema,
  body?: unknown,
): Promise<z.output<Schema>> {
  if (method !== 'GET' && readCsrfToken() === null) {
    await refreshCsrfCookie()
  }

  let response = await send(method, path, body)

  // The token expires with the session. Get a new one and try once more.
  if (response.status === 419) {
    await refreshCsrfCookie()
    response = await send(method, path, body)
  }

  if (!response.ok) {
    throw await toApiError(response)
  }

  const payload: unknown = response.status === 204 ? undefined : await response.json().catch(() => null)
  const parsed = schema.safeParse(payload)

  if (!parsed.success) {
    throw new ApiError(response.status, 'INVALID_RESPONSE')
  }

  return parsed.data
}
