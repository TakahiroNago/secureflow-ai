import { useNavigate } from 'react-router'
import { useCurrentUser, useLogout } from '../auth/useAuth'

/** A placeholder after login. The dashboard comes in step 1-7. */
export function HomePage() {
  const { data: user } = useCurrentUser()
  const logout = useLogout()
  const navigate = useNavigate()

  if (!user) {
    return null
  }

  return (
    <section className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <h2 className="text-lg font-semibold">ようこそ</h2>
      <dl className="mt-4 space-y-1 text-sm">
        <div>
          <dt className="inline text-slate-500">氏名：</dt>
          <dd className="inline">{user.name}</dd>
        </div>
        <div>
          <dt className="inline text-slate-500">メールアドレス：</dt>
          <dd className="inline">{user.email}</dd>
        </div>
        <div>
          <dt className="inline text-slate-500">ロール：</dt>
          <dd className="inline">{user.role}</dd>
        </div>
        <div>
          <dt className="inline text-slate-500">組織：</dt>
          <dd className="inline">{user.organization.name}</dd>
        </div>
      </dl>
      <button
        type="button"
        className="mt-4 rounded-md border border-slate-300 px-3 py-2 text-sm font-medium disabled:opacity-50"
        disabled={logout.isPending}
        onClick={() => {
          logout.mutate(undefined, {
            onSettled: () => {
              void navigate('/login', { replace: true })
            },
          })
        }}
      >
        ログアウト
      </button>
    </section>
  )
}
