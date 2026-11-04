import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useState } from 'react'
import { BrowserRouter } from 'react-router'
import { ApiStatusCard } from './features/status/ApiStatusCard'
import { AppRoutes } from './routes/AppRoutes'

export default function App() {
  const [queryClient] = useState(() => new QueryClient())

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="min-h-screen bg-slate-50 text-slate-900">
          <header className="bg-slate-900 text-white">
            <div className="mx-auto max-w-5xl px-6 py-4">
              <h1 className="text-lg font-semibold tracking-tight">SecureFlow AI</h1>
              <p className="text-sm text-slate-300">AI業務自動化・セキュリティ管理プラットフォーム</p>
            </div>
          </header>
          <main className="mx-auto max-w-5xl space-y-6 px-6 py-8">
            <AppRoutes />
            <ApiStatusCard />
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
