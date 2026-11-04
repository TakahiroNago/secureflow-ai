import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate } from 'react-router'
import { ApiError } from '../../api/client'
import { useCurrentUser, useLogin } from './useAuth'

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'AUTH_FAILED':
        return 'メールアドレスまたはパスワードが正しくありません。'
      case 'RATE_LIMITED':
        return error.retryAfterSeconds
          ? `試行回数が多すぎます。${String(error.retryAfterSeconds)}秒後に再度お試しください。`
          : '試行回数が多すぎます。しばらく待ってから再度お試しください。'
      case 'VALIDATION_FAILED':
        return '入力内容を確認してください。'
    }
  }
  return 'ログインできませんでした。時間をおいて再度お試しください。'
}

export function LoginPage() {
  const currentUser = useCurrentUser()
  const login = useLogin()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  if (currentUser.data) {
    return <Navigate to="/" replace />
  }

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    login.mutate(
      { email, password },
      {
        // The password is kept only in this form, and only until it has been submitted.
        onSettled: () => {
          setPassword('')
        },
        onSuccess: () => {
          void navigate('/', { replace: true })
        },
      },
    )
  }

  return (
    <section className="mx-auto max-w-sm rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <h2 className="text-lg font-semibold">ログイン</h2>
      <form className="mt-4 space-y-4" onSubmit={submit}>
        <div>
          <label className="block text-sm font-medium text-slate-700" htmlFor="email">
            メールアドレス
          </label>
          <input
            id="email"
            className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(event) => {
              setEmail(event.target.value)
            }}
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700" htmlFor="password">
            パスワード
          </label>
          <input
            id="password"
            className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => {
              setPassword(event.target.value)
            }}
          />
        </div>
        {login.isError && (
          <p role="alert" className="text-sm text-red-700">
            {errorMessage(login.error)}
          </p>
        )}
        <button
          type="submit"
          className="w-full rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
          disabled={login.isPending}
        >
          ログイン
        </button>
      </form>
    </section>
  )
}
