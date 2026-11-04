import { Navigate, Outlet } from 'react-router'
import { useCurrentUser } from './useAuth'

/**
 * Hides protected screens until the server confirms the session. This is for usability only:
 * authorization always happens on the server (docs/architecture.md §6).
 */
export function RequireAuth() {
  const currentUser = useCurrentUser()

  if (currentUser.isPending) {
    return <p className="text-sm text-slate-500">確認中…</p>
  }

  if (!currentUser.data) {
    return <Navigate to="/login" replace />
  }

  return <Outlet />
}
