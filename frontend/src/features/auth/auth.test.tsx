import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '../../App'

const user = {
  id: '019a0000-0000-7000-8000-000000000001',
  name: 'Example User',
  email: 'user@example.com',
  role: 'member',
  organization: { id: '019a0000-0000-7000-8000-000000000002', name: 'Example Org' },
}

const problem = (status: number, code: string, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ type: 'https://secureflow.local/problems/x', title: 'x', status, code, detail: 'detail', trace_id: 't' }), {
    status,
    headers: { 'Content-Type': 'application/problem+json', ...headers },
  })

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

type Handler = (init: RequestInit | undefined) => Response

/** Routes each fetch by "METHOD path". Anything unexpected fails loudly. */
function server(routes: Record<string, Handler>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const key = `${init?.method ?? 'GET'} ${String(input as string)}`
    if (key === 'GET /api/health/live') {
      return Promise.resolve(json({ status: 'ok' }))
    }
    if (key === 'GET /sanctum/csrf-cookie') {
      document.cookie = 'XSRF-TOKEN=token%3Dvalue; path=/'
      return Promise.resolve(new Response(null, { status: 204 }))
    }
    const handler = routes[key]
    if (!handler) {
      return Promise.reject(new Error(`unexpected request: ${key}`))
    }
    return Promise.resolve(handler(init))
  })
}

const callsTo = (spy: ReturnType<typeof server>, key: string) =>
  spy.mock.calls.filter(([input, init]) => `${init?.method ?? 'GET'} ${String(input as string)}` === key)

function fillAndSubmit(email = 'user@example.com', password = 'a long enough password') {
  fireEvent.change(screen.getByLabelText('メールアドレス'), { target: { value: email } })
  fireEvent.change(screen.getByLabelText('パスワード'), { target: { value: password } })
  fireEvent.click(screen.getByRole('button', { name: 'ログイン' }))
}

beforeEach(() => {
  window.history.pushState({}, '', '/')
  document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('requests', () => {
  it('sends a Referer to its own origin, or the server would not use the session for a GET', async () => {
    const spy = server({ 'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED') })

    render(<App />)
    await waitFor(() => {
      expect(callsTo(spy, 'GET /api/v1/auth/me').length).toBeGreaterThan(0)
    })

    expect(callsTo(spy, 'GET /api/v1/auth/me')[0]?.[1]?.referrerPolicy).toBe('same-origin')
  })
})

describe('route guard', () => {
  it('sends an unauthenticated visitor to the login page and shows nothing protected', async () => {
    server({ 'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED') })

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'ログイン' })).toBeInTheDocument()
    expect(window.location.pathname).toBe('/login')
    expect(screen.queryByText('ようこそ')).not.toBeInTheDocument()
  })

  it('shows nothing protected while the session is being checked', () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise(() => undefined))

    render(<App />)

    expect(screen.queryByText('ようこそ')).not.toBeInTheDocument()
    expect(screen.getAllByText('確認中').length).toBeGreaterThan(0)
  })

  it('fails closed when the response has the wrong shape', async () => {
    server({ 'GET /api/v1/auth/me': () => json({ data: { id: 'x', role: 'superadmin' } }) })

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'ログイン' })).toBeInTheDocument()
    expect(screen.queryByText('ようこそ')).not.toBeInTheDocument()
  })

  it('fails closed when the server cannot be reached', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) =>
      String(input as string) === '/api/health/live' ? Promise.resolve(json({ status: 'ok' })) : Promise.reject(new TypeError('network error')),
    )

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'ログイン' })).toBeInTheDocument()
  })

  it('shows the home page to a logged-in user, and sends them away from the login page', async () => {
    server({ 'GET /api/v1/auth/me': () => json({ data: user }) })
    window.history.pushState({}, '', '/login')

    render(<App />)

    expect(await screen.findByText('ようこそ')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/')
    expect(screen.getByText('Example Org')).toBeInTheDocument()
  })

  it('returns to the login page when the session has expired', async () => {
    let expired = false
    server({ 'GET /api/v1/auth/me': () => (expired ? problem(401, 'UNAUTHENTICATED') : json({ data: user })) })

    render(<App />)
    await screen.findByText('ようこそ')

    expired = true
    window.dispatchEvent(new Event('visibilitychange'))
    window.dispatchEvent(new Event('focus'))

    await waitFor(() => {
      expect(window.location.pathname).toBe('/login')
    })
  })
})

describe('login', () => {
  it('gets a CSRF cookie first, sends the decoded token, and shows the home page', async () => {
    const spy = server({
      'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED'),
      'POST /api/v1/auth/login': () => json({ data: user }),
    })

    render(<App />)
    await screen.findByRole('heading', { name: 'ログイン' })
    fillAndSubmit()

    expect(await screen.findByText('ようこそ')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/')

    const [call] = callsTo(spy, 'POST /api/v1/auth/login')
    const headers = call?.[1]?.headers as Record<string, string>
    expect(headers['X-XSRF-TOKEN']).toBe('token=value')
    expect(headers['Content-Type']).toBe('application/json')
    expect(call?.[1]?.credentials).toBe('same-origin')
    expect(callsTo(spy, 'GET /sanctum/csrf-cookie')).toHaveLength(1)
  })

  it('shows one message for a failed login and clears the password', async () => {
    server({
      'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED'),
      'POST /api/v1/auth/login': () => problem(401, 'AUTH_FAILED'),
    })

    render(<App />)
    await screen.findByRole('heading', { name: 'ログイン' })
    fillAndSubmit()

    expect(await screen.findByRole('alert')).toHaveTextContent('メールアドレスまたはパスワードが正しくありません。')
    expect(screen.getByLabelText('パスワード')).toHaveValue('')
    expect(screen.getByLabelText('メールアドレス')).toHaveValue('user@example.com')
    expect(window.location.pathname).toBe('/login')
  })

  it('shows how long to wait when rate limited', async () => {
    server({
      'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED'),
      'POST /api/v1/auth/login': () => problem(429, 'RATE_LIMITED', { 'Retry-After': '42' }),
    })

    render(<App />)
    await screen.findByRole('heading', { name: 'ログイン' })
    fillAndSubmit()

    expect(await screen.findByRole('alert')).toHaveTextContent('42秒後')
  })

  it('shows a validation message', async () => {
    server({
      'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED'),
      'POST /api/v1/auth/login': () => problem(422, 'VALIDATION_FAILED'),
    })

    render(<App />)
    await screen.findByRole('heading', { name: 'ログイン' })
    fillAndSubmit()

    expect(await screen.findByRole('alert')).toHaveTextContent('入力内容を確認してください。')
  })

  it('does not show server text for an unknown error', async () => {
    server({
      'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED'),
      'POST /api/v1/auth/login': () => new Response('<h1>internal details</h1>', { status: 500 }),
    })

    render(<App />)
    await screen.findByRole('heading', { name: 'ログイン' })
    fillAndSubmit()

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('ログインできませんでした')
    expect(screen.queryByText(/internal details/)).not.toBeInTheDocument()
  })

  it('refreshes an expired CSRF token and retries once', async () => {
    document.cookie = 'XSRF-TOKEN=stale; path=/'
    let attempts = 0
    const spy = server({
      'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED'),
      'POST /api/v1/auth/login': () => {
        attempts += 1
        return attempts === 1 ? problem(419, 'CSRF_TOKEN_MISMATCH') : json({ data: user })
      },
    })

    render(<App />)
    await screen.findByRole('heading', { name: 'ログイン' })
    fillAndSubmit()

    expect(await screen.findByText('ようこそ')).toBeInTheDocument()
    expect(attempts).toBe(2)
    expect(callsTo(spy, 'GET /sanctum/csrf-cookie')).toHaveLength(1)
  })

  it('stops after one CSRF retry', async () => {
    document.cookie = 'XSRF-TOKEN=stale; path=/'
    const spy = server({
      'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED'),
      'POST /api/v1/auth/login': () => problem(419, 'CSRF_TOKEN_MISMATCH'),
    })

    render(<App />)
    await screen.findByRole('heading', { name: 'ログイン' })
    fillAndSubmit()

    await screen.findByRole('alert')
    expect(callsTo(spy, 'POST /api/v1/auth/login')).toHaveLength(2)
  })

  it('never writes anything to browser storage', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    server({
      'GET /api/v1/auth/me': () => problem(401, 'UNAUTHENTICATED'),
      'POST /api/v1/auth/login': () => json({ data: user }),
      'POST /api/v1/auth/logout': () => new Response(null, { status: 204 }),
    })

    render(<App />)
    await screen.findByRole('heading', { name: 'ログイン' })
    fillAndSubmit()
    fireEvent.click(await screen.findByRole('button', { name: 'ログアウト' }))
    await screen.findByRole('heading', { name: 'ログイン' })

    expect(setItem).not.toHaveBeenCalled()
  })
})

describe('home page', () => {
  it('logs out and returns to the login page', async () => {
    const spy = server({
      'GET /api/v1/auth/me': () => json({ data: user }),
      'POST /api/v1/auth/logout': () => new Response(null, { status: 204 }),
    })

    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: 'ログアウト' }))

    expect(await screen.findByRole('heading', { name: 'ログイン' })).toBeInTheDocument()
    expect(window.location.pathname).toBe('/login')
    expect(callsTo(spy, 'POST /api/v1/auth/logout')).toHaveLength(1)
  })

  it('renders user data as text, never as HTML', async () => {
    const payload = '<img src=x onerror="alert(1)">'
    server({ 'GET /api/v1/auth/me': () => json({ data: { ...user, name: payload } }) })

    const { container } = render(<App />)

    expect(await screen.findByText(payload)).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
  })
})
