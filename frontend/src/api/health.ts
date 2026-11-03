export type HealthStatus = 'ok' | 'unavailable' | 'unknown'

/**
 * Fetches the API liveness status.
 * The response is untrusted input: anything other than the documented shape is "unknown".
 */
export async function fetchLiveness(signal?: AbortSignal): Promise<HealthStatus> {
  try {
    const res = await fetch('/api/health/live', {
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
      ...(signal ? { signal } : {}),
    })
    if (!res.ok) {
      return 'unavailable'
    }
    const body: unknown = await res.json()
    return parseHealthStatus(body)
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw e
    }
    return 'unavailable'
  }
}

export function parseHealthStatus(body: unknown): HealthStatus {
  if (typeof body === 'object' && body !== null && 'status' in body) {
    const status = (body as { status: unknown }).status
    if (status === 'ok' || status === 'unavailable') {
      return status
    }
  }
  return 'unknown'
}
