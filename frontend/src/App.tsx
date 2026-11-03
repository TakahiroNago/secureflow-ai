import { useEffect, useState } from 'react'
import { fetchLiveness, type HealthStatus } from './api/health'
import { StatusBadge } from './components/StatusBadge'

const statusLabel: Record<HealthStatus | 'checking', string> = {
  checking: '確認中',
  ok: '稼働中',
  unavailable: '利用不可',
  unknown: '不明',
}

export default function App() {
  const [status, setStatus] = useState<HealthStatus | 'checking'>('checking')

  useEffect(() => {
    const controller = new AbortController()
    fetchLiveness(controller.signal)
      .then(setStatus)
      .catch(() => {
        /* aborted on unmount */
      })
    return () => controller.abort()
  }, [])

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="bg-slate-900 text-white">
        <div className="mx-auto max-w-5xl px-6 py-4">
          <h1 className="text-lg font-semibold tracking-tight">SecureFlow AI</h1>
          <p className="text-sm text-slate-300">AI業務自動化・セキュリティ管理プラットフォーム</p>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-6 py-8">
        <section className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
          <h2 className="text-sm font-medium text-slate-500">APIステータス</h2>
          <div className="mt-2" data-testid="api-status">
            <StatusBadge
              label={statusLabel[status]}
              tone={status === 'ok' ? 'ok' : status === 'checking' ? 'neutral' : 'warn'}
            />
          </div>
          <p className="mt-4 text-sm text-slate-500">Phase 0：開発基盤のみ。業務機能は Phase 1 以降で実装します。</p>
        </section>
      </main>
    </div>
  )
}
