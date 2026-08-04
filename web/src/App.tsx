import type { ReactNode } from 'react'
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
} from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { AuthProvider, useAuth } from './lib/AuthContext'
import { DEFAULT_INDUSTRY_ID } from './industries/registry'
import AppShell from './components/AppShell'
import LoginPage from './components/LoginPage'

function FullPageSpinner() {
  return (
    <div className="h-full flex items-center justify-center bg-slate-950">
      <Loader2 className="w-6 h-6 animate-spin text-slate-500" />
    </div>
  )
}

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) return <FullPageSpinner />
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />
  return <>{children}</>
}

function LoginRoute() {
  const { user, loading } = useAuth()
  if (loading) return <FullPageSpinner />
  if (user) return <Navigate to={`/${DEFAULT_INDUSTRY_ID}/dashboard`} replace />
  return <LoginPage />
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginRoute />} />
          <Route
            path="/:industryId/chat"
            element={
              <RequireAuth>
                <AppShell view="chat" />
              </RequireAuth>
            }
          />
          <Route
            path="/:industryId/dashboard"
            element={
              <RequireAuth>
                <AppShell view="dashboard" />
              </RequireAuth>
            }
          />
          <Route
            path="*"
            element={<Navigate to={`/${DEFAULT_INDUSTRY_ID}/dashboard`} replace />}
          />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
