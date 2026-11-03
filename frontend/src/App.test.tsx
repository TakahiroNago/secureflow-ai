import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import App from './App'
import { parseHealthStatus } from './api/health'
import { StatusBadge } from './components/StatusBadge'

// P0-FE-01 (docs/test-strategy.md §12)

function mockFetch(response: Response | Error) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
    response instanceof Error ? Promise.reject(response) : Promise.resolve(response),
  )
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

describe('App', () => {
  it('shows the API as running when liveness returns ok', async () => {
    const fetchSpy = mockFetch(json({ status: 'ok' }))

    render(<App />)

    expect(screen.getByRole('heading', { name: 'SecureFlow AI' })).toBeInTheDocument()
    expect(await screen.findByText('稼働中')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledWith('/api/health/live', expect.objectContaining({ credentials: 'same-origin' }))
  })

  it('shows unavailable when the API cannot be reached', async () => {
    mockFetch(new TypeError('network error'))

    render(<App />)

    expect(await screen.findByText('利用不可')).toBeInTheDocument()
  })

  it('shows unavailable on a non-2xx response', async () => {
    mockFetch(json({ status: 'unavailable' }, 503))

    render(<App />)

    expect(await screen.findByText('利用不可')).toBeInTheDocument()
  })
})

describe('parseHealthStatus (untrusted response)', () => {
  it.each([
    [{ status: 'ok' }, 'ok'],
    [{ status: 'unavailable' }, 'unavailable'],
    [{ status: '<img src=x onerror=alert(1)>' }, 'unknown'],
    [{}, 'unknown'],
    [null, 'unknown'],
    ['ok', 'unknown'],
  ])('%j -> %s', (body, expected) => {
    expect(parseHealthStatus(body)).toBe(expected)
  })
})

describe('text-only rendering', () => {
  it('renders HTML-like strings as text, never as elements', () => {
    const payload = '<img src=x onerror="alert(1)"><script>alert(2)</script>'

    const { container } = render(<StatusBadge label={payload} tone="neutral" />)

    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('script')).toBeNull()
    expect(screen.getByText(payload)).toBeInTheDocument()
  })
})
