import { Navigate, Route, Routes } from 'react-router'
import { LoginPage } from '../features/auth/LoginPage'
import { RequireAuth } from '../features/auth/RequireAuth'
import { DashboardPage } from '../features/dashboard/DashboardPage'
import { AppShell } from '../features/layout/AppShell'
import { AnalysisPage } from '../features/workflows/AnalysisPage'
import { ApprovalPage } from '../features/workflows/ApprovalPage'
import { ApprovalsPage } from '../features/workflows/ApprovalsPage'
import { NewAnalysisPage } from '../features/workflows/NewAnalysisPage'
import { WorkflowDetailPage } from '../features/workflows/WorkflowDetailPage'
import { WorkflowListPage } from '../features/workflows/WorkflowListPage'

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/analyses/new" element={<NewAnalysisPage />} />
          <Route path="/analyses/:id" element={<AnalysisPage />} />
          <Route path="/workflows" element={<WorkflowListPage />} />
          <Route path="/workflows/:id" element={<WorkflowDetailPage />} />
          <Route path="/workflows/:id/approval" element={<ApprovalPage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
