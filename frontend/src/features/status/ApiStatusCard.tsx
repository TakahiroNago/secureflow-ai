import { useEffect, useState } from 'react'
import { fetchLiveness, type HealthStatus } from '../../api/health'
import { StatusBadge } from '../../components/StatusBadge'

const statusLabel: Record<HealthStatus | 'checking', string> = {
  checking: '確認中',
  ok: '稼働中',
  unavailable: '利用不可',
  unknown: '不明',
}

export function ApiStatusCard() {
  const [status, setStatus] = useState<HealthStatus | 'checking'>('checking')

  useEffect(() => {
    const controller = new AbortController()
    fetchLiveness(controller.signal)
      .then(setStatus)
      .catch(() => {
        /* aborted on unmount */
      })
    return () => {
      controller.abort()
    }
  }, [])

  return (
    <section className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <h2 className="text-sm font-medium text-slate-500">APIステータス</h2>
      <div className="mt-2" data-testid="api-status">
        <StatusBadge
          label={statusLabel[status]}
          tone={status === 'ok' ? 'ok' : status === 'checking' ? 'neutral' : 'warn'}
        />
      </div>
    </section>
  )
}
