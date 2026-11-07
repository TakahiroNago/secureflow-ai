import { NavLink, Outlet, useNavigate } from 'react-router'
import { useCurrentUser, useLogout } from '../auth/useAuth'

const ROLE_LABELS: Record<string, string> = { admin: '管理者', member: 'メンバー', auditor: '監査者' }

const linkClass = ({ isActive }: { isActive: boolean }) => (isActive ? 'font-semibold text-slate-900' : 'text-slate-600 underline')

/** Around every screen after login. What it shows and hides is for usability: the server decides. */
export function AppShell() {
  const { data: user } = useCurrentUser()
  const logout = useLogout()
  const navigate = useNavigate()

  if (!user) {
    return null
  }

  return (
    <div className="space-y-4">
      <nav aria-label="メイン" className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-white px-4 py-3 text-sm shadow-sm ring-1 ring-slate-200">
        <div className="flex gap-4">
          <NavLink className={linkClass} to="/" end>
            ダッシュボード
          </NavLink>
          <NavLink className={linkClass} to="/workflows">
            ワークフロー
          </NavLink>
          {user.role === 'admin' && (
            <NavLink className={linkClass} to="/approvals">
              承認待ち
            </NavLink>
          )}
          {(user.role === 'admin' || user.role === 'auditor') && (
            <NavLink className={linkClass} to="/audit-logs">
              監査ログ
            </NavLink>
          )}
          <NavLink className={linkClass} to="/security">
            セキュリティ
          </NavLink>
          <NavLink className={linkClass} to="/settings">
            設定
          </NavLink>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-slate-600">
            {user.name}（{ROLE_LABELS[user.role] ?? user.role}）・{user.organization.name}
          </span>
          <button
            type="button"
            className="rounded-md border border-slate-300 px-3 py-1.5 font-medium disabled:opacity-50"
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
        </div>
      </nav>
      <Outlet />
    </div>
  )
}
