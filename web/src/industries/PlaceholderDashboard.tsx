import type { LucideIcon } from 'lucide-react'
import { Hammer } from 'lucide-react'

interface Props {
  name: string
  description: string
  icon: LucideIcon
  accentClass: string
}

/** Shared "coming soon" pane for industries whose stack is not deployed yet. */
export default function PlaceholderDashboard({
  name,
  description,
  icon: Icon,
  accentClass,
}: Props) {
  return (
    <div className="h-full flex items-center justify-center p-6">
      <div className="max-w-md w-full text-center bg-slate-900 border border-slate-800 rounded-2xl p-10">
        <div
          className={`mx-auto w-16 h-16 rounded-2xl flex items-center justify-center bg-slate-800 ${accentClass}`}
        >
          <Icon className="w-8 h-8" />
        </div>
        <h2 className="mt-5 text-xl font-semibold text-white">{name}</h2>
        <p className="mt-2 text-sm text-slate-400">{description}</p>
        <div className="mt-6 inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800 border border-slate-700 text-xs text-slate-300">
          <Hammer className="w-3.5 h-3.5" />
          Coming soon — template ready, not deployed
        </div>
      </div>
    </div>
  )
}
