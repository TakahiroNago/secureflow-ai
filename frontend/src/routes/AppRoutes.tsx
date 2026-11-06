import { Navigate, Route, Routes } from 'react-router'
import { LoginPage } from '../features/auth/LoginPage'
import { RequireAuth } from '../features/auth/RequireAuth'
import { HomePage } from '../features/home/HomePage'
import { AnalysisPage } from '../features/workflows/AnalysisPage'
import { NewAnalysisPage } from '../features/workflows/NewAnalysisPage'
import { WorkflowDetailPage } from '../features/workflows/WorkflowDetailPage'
import { WorkflowListPage } from '../features/workflows/WorkflowListPage'

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route path="/" element={<HomePage />} />
        <Route path="/analyses/new" element={<NewAnalysisPage />} />
        <Route path="/analyses/:id" element={<AnalysisPage />} />
        <Route path="/workflows" element={<WorkflowListPage />} />
        <Route path="/workflows/:id" element={<WorkflowDetailPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
