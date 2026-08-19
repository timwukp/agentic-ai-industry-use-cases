import type { ReactNode } from 'react'
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
} from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { LocaleProvider } from './i18n/LocaleContext'
import { AuthProvider, useAuth } from './lib/AuthContext'
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
  if (user) return <Navigate to="/" replace />
  return <LoginPage />
}

export default function App() {
  return (
    // LocaleProvider outermost: LoginPage renders before auth and needs t() too.
    <LocaleProvider>
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
            {/* Architecture is industry-agnostic — one canonical URL. */}
            <Route
              path="/architecture"
              element={
                <RequireAuth>
                  <AppShell view="architecture" />
                </RequireAuth>
              }
            />
            <Route
              path="/:industryId/architecture"
              element={<Navigate to="/architecture" replace />}
            />
            {/* The home URL IS the default dashboard — no redirect. */}
            <Route
              path="/"
              element={
                <RequireAuth>
                  <AppShell view="dashboard" />
                </RequireAuth>
              }
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </LocaleProvider>
  )
}
