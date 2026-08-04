import type { LucideIcon } from 'lucide-react'
import { Hammer, MessageSquare } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'

interface Props {
  name: string
  description: string
  icon: LucideIcon
  accentClass: string
  /** When true the agent is deployed and chat works — only widgets are pending. */
  chatLive?: boolean
}

/** Shared pane for industries without dashboard widgets yet. */
export default function PlaceholderDashboard({
  name,
  description,
  icon: Icon,
  accentClass,
  chatLive = false,
}: Props) {
  const { industryId } = useParams()
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
        {chatLive ? (
          <div className="mt-6 flex flex-col items-center gap-3">
            <Link
              to={`/${industryId}/chat`}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-sm font-medium text-white transition-colors"
            >
              <MessageSquare className="w-4 h-4" />
              Agent is live — open Chat
            </Link>
            <span className="text-xs text-slate-500">
              Dashboard widgets coming soon
            </span>
          </div>
        ) : (
          <div className="mt-6 inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800 border border-slate-700 text-xs text-slate-300">
            <Hammer className="w-3.5 h-3.5" />
            Coming soon — template ready, not deployed
          </div>
        )}
      </div>
    </div>
  )
}
