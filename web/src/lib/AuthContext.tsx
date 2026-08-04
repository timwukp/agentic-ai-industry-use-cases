import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { doSignOut, getAccessToken, loadCurrentUser, type AuthUser } from './auth'

interface AuthContextValue {
  user: AuthUser | null
  /** True while the initial session check is in flight. */
  loading: boolean
  /** Re-reads the Cognito session (call after a successful sign-in). */
  refresh: () => Promise<void>
  signOut: () => Promise<void>
  /** Fresh access token for API / agent calls (Amplify refreshes as needed). */
  getToken: () => Promise<string | null>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    const current = await loadCurrentUser()
    setUser(current)
  }, [])

  useEffect(() => {
    void refresh().finally(() => setLoading(false))
  }, [refresh])

  const signOut = useCallback(async () => {
    await doSignOut()
    setUser(null)
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({ user, loading, refresh, signOut, getToken: getAccessToken }),
    [user, loading, refresh, signOut],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
