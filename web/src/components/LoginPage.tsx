import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { KeyRound, Loader2, Lock, Mail, ShieldCheck } from 'lucide-react'
import { answerChallenge, startSignIn, type SignInChallenge } from '../lib/auth'
import { useAuth } from '../lib/AuthContext'
import { DEFAULT_INDUSTRY_ID } from '../industries/registry'

type Step = 'credentials' | 'totp' | 'newPassword'

export default function LoginPage() {
  const navigate = useNavigate()
  const { refresh } = useAuth()

  const [step, setStep] = useState<Step>('credentials')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const finishSignIn = async () => {
    await refresh()
    navigate(`/${DEFAULT_INDUSTRY_ID}/dashboard`, { replace: true })
  }

  const handleChallenge = async (challenge: SignInChallenge) => {
    switch (challenge) {
      case 'DONE':
        await finishSignIn()
        break
      case 'TOTP':
        setStep('totp')
        break
      case 'NEW_PASSWORD':
        setStep('newPassword')
        break
      default:
        setError('Unsupported sign-in challenge. Contact your administrator.')
    }
  }

  const submit = async (event: FormEvent, action: () => Promise<SignInChallenge>) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await handleChallenge(await action())
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  const inputClass =
    'w-full pl-10 pr-4 py-2.5 bg-slate-800 border border-slate-700 rounded-lg ' +
    'text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 ' +
    'focus:ring-1 focus:ring-blue-500 text-sm'

  const buttonClass =
    'w-full flex items-center justify-center gap-2 py-2.5 bg-blue-600 rounded-lg ' +
    'text-white text-sm font-medium hover:bg-blue-500 disabled:opacity-50 ' +
    'disabled:cursor-not-allowed transition-colors'

  return (
    <div className="min-h-full flex items-center justify-center bg-slate-950 p-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="mx-auto w-12 h-12 rounded-xl bg-blue-600 flex items-center justify-center mb-4">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-xl font-bold text-white">Agentic AI Use Cases</h1>
          <p className="text-sm text-slate-400 mt-1">Sign in with your Cognito account</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
          {step === 'credentials' && (
            <form
              onSubmit={(e) => submit(e, () => startSignIn(email.trim(), password))}
              className="space-y-4"
            >
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="email"
                  autoComplete="username"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Email"
                  className={inputClass}
                />
              </div>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password"
                  className={inputClass}
                />
              </div>
              <button type="submit" disabled={busy || !email || !password} className={buttonClass}>
                {busy && <Loader2 className="w-4 h-4 animate-spin" />}
                Sign in
              </button>
            </form>
          )}

          {step === 'totp' && (
            <form
              onSubmit={(e) => submit(e, () => answerChallenge(totpCode.trim()))}
              className="space-y-4"
            >
              <p className="text-sm text-slate-300">
                Enter the 6-digit code from your authenticator app.
              </p>
              <div className="relative">
                <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="\d{6}"
                  maxLength={6}
                  required
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="MFA code"
                  className={`${inputClass} tracking-[0.3em]`}
                />
              </div>
              <button type="submit" disabled={busy || totpCode.length !== 6} className={buttonClass}>
                {busy && <Loader2 className="w-4 h-4 animate-spin" />}
                Verify
              </button>
            </form>
          )}

          {step === 'newPassword' && (
            <form
              onSubmit={(e) => submit(e, () => answerChallenge(newPassword))}
              className="space-y-4"
            >
              <p className="text-sm text-slate-300">
                Your account requires a new password before continuing.
              </p>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="password"
                  autoComplete="new-password"
                  minLength={8}
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="New password"
                  className={inputClass}
                />
              </div>
              <button type="submit" disabled={busy || newPassword.length < 8} className={buttonClass}>
                {busy && <Loader2 className="w-4 h-4 animate-spin" />}
                Set password &amp; sign in
              </button>
            </form>
          )}

          {error && (
            <div className="px-3 py-2 rounded-lg bg-red-950/50 border border-red-900 text-sm text-red-300">
              {error}
            </div>
          )}
        </div>

        <p className="text-center text-xs text-slate-600 mt-6">
          AWS AgentCore Harness · Cognito authenticated
        </p>
      </div>
    </div>
  )
}
