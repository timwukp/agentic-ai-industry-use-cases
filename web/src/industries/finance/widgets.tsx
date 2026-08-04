import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { AlertTriangle, FlaskConical, Loader2, RotateCw } from 'lucide-react'

export function Card({
  title,
  children,
  className = '',
  action,
}: {
  title?: string
  children: ReactNode
  className?: string
  action?: ReactNode
}) {
  return (
    <div className={`bg-slate-900 rounded-xl border border-slate-800 ${className}`}>
      {title && (
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-medium text-slate-400">{title}</h3>
          {action}
        </div>
      )}
      {children}
    </div>
  )
}

export function StatCard({
  title,
  value,
  icon: Icon,
  sub,
  subClass = 'text-slate-400',
}: {
  title: string
  value: string
  icon: LucideIcon
  sub?: string
  subClass?: string
}) {
  return (
    <div className="bg-slate-900 rounded-xl p-4 @lg:p-5 border border-slate-800">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs @lg:text-sm text-slate-400">{title}</span>
        <Icon className="w-4 h-4 @lg:w-5 @lg:h-5 text-slate-500" />
      </div>
      <div className="text-xl @lg:text-2xl font-bold text-white tabular-nums">{value}</div>
      {sub && <div className={`text-xs @lg:text-sm mt-1 ${subClass}`}>{sub}</div>}
    </div>
  )
}

export function LoadingPane({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-slate-400 text-sm">
      <Loader2 className="w-4 h-4 animate-spin" />
      {label}
    </div>
  )
}

export function ErrorPane({
  message,
  onRetry,
}: {
  message: string
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-10 px-6 text-center">
      <AlertTriangle className="w-6 h-6 text-amber-400" />
      <p className="text-sm text-slate-300 break-all max-w-md">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors"
        >
          <RotateCw className="w-3.5 h-3.5" />
          Retry
        </button>
      )}
    </div>
  )
}

/** Data-provenance disclosure required for simulated backends. */
export function SimulatedBadge() {
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-950/50 border border-amber-800/50 text-[11px] text-amber-300">
      <FlaskConical className="w-3 h-3" />
      source: simulated
    </span>
  )
}

export const fmtUsd = (n: number): string =>
  n.toLocaleString('en-US', {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 2,
    minimumFractionDigits: 2,
  })

export const fmtUsdCompact = (n: number): string =>
  n.toLocaleString('en-US', {
    style: 'currency',
    currency: 'USD',
    notation: 'compact',
    maximumFractionDigits: 1,
  })

export const fmtSigned = (n: number, suffix = ''): string =>
  `${n >= 0 ? '+' : ''}${n.toLocaleString('en-US', { maximumFractionDigits: 2 })}${suffix}`

export const pnlClass = (n: number): string =>
  n >= 0 ? 'text-green-400' : 'text-red-400'
