import { useEffect, useState } from 'react'
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom'
import {
  Bot,
  LayoutDashboard,
  LogOut,
  MessageSquare,
  PanelLeftClose,
  PanelLeftOpen,
  PanelRightClose,
  PanelRightOpen,
  X,
} from 'lucide-react'
import { getIndustry, industries, DEFAULT_INDUSTRY_ID } from '../industries/registry'
import { useAuth } from '../lib/AuthContext'
import ChatPanel from './ChatPanel'

export type ShellView = 'dashboard' | 'chat'

export default function AppShell({ view }: { view: ShellView }) {
  const { industryId } = useParams()
  const navigate = useNavigate()
  const { user, signOut } = useAuth()

  const industry = getIndustry(industryId)

  // Desktop-only chat collapse; md rail expansion; mobile industries sheet.
  const [chatCollapsed, setChatCollapsed] = useState(false)
  const [railExpanded, setRailExpanded] = useState(false)
  const [industriesOpen, setIndustriesOpen] = useState(false)

  // Navigating to the chat tab always reveals the chat pane on desktop too.
  useEffect(() => {
    if (view === 'chat') setChatCollapsed(false)
  }, [view])

  useEffect(() => {
    setIndustriesOpen(false)
  }, [industryId])

  if (!industry) {
    return <Navigate to={`/${DEFAULT_INDUSTRY_ID}/dashboard`} replace />
  }

  const Dashboard = industry.Dashboard
  const IndustryIcon = industry.icon

  const handleSignOut = async () => {
    await signOut()
    navigate('/login', { replace: true })
  }

  const navLink = (target: ShellView, label: string, Icon: typeof LayoutDashboard) => (
    <Link
      to={`/${industry.id}/${target}`}
      className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${
        view === target
          ? 'bg-slate-800 text-white'
          : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
      }`}
    >
      <Icon className="w-4 h-4 shrink-0" />
      <span className={`${railExpanded ? 'inline' : 'hidden'} lg:inline truncate`}>
        {label}
      </span>
    </Link>
  )

  const industryList = (onSelect?: () => void) => (
    <nav className="space-y-1">
      {industries.map((item) => {
        const Icon = item.icon
        const active = item.id === industry.id
        return (
          <Link
            key={item.id}
            to={`/${item.id}/${view}`}
            onClick={onSelect}
            title={item.name}
            className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${
              active
                ? 'bg-slate-800 text-white'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Icon className={`w-4 h-4 shrink-0 ${active ? item.themeColor : ''}`} />
            <span
              className={`${railExpanded ? 'inline' : 'hidden'} lg:inline truncate flex-1`}
            >
              {item.name}
            </span>
            {!item.enabled && (
              <span
                className={`${railExpanded ? 'inline' : 'hidden'} lg:inline text-[10px] px-1.5 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-500`}
              >
                soon
              </span>
            )}
          </Link>
        )
      })}
    </nav>
  )

  return (
    <div className="h-full flex flex-col bg-slate-950">
      {/* Top bar */}
      <header className="h-14 shrink-0 border-b border-slate-800 bg-slate-900/60 flex items-center gap-3 px-4">
        <div className="hidden md:flex lg:hidden">
          <button
            onClick={() => setRailExpanded((v) => !v)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title={railExpanded ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {railExpanded ? (
              <PanelLeftClose className="w-5 h-5" />
            ) : (
              <PanelLeftOpen className="w-5 h-5" />
            )}
          </button>
        </div>
        <div className="flex items-center gap-2.5 min-w-0">
          <IndustryIcon className={`w-5 h-5 shrink-0 ${industry.themeColor}`} />
          <h1 className="text-sm font-semibold text-white truncate">{industry.name}</h1>
        </div>
        <div className="flex-1" />
        {/* Desktop chat collapse toggle */}
        <button
          onClick={() => setChatCollapsed((v) => !v)}
          className="hidden lg:inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 transition-colors"
          title={chatCollapsed ? 'Show chat' : 'Hide chat'}
        >
          {chatCollapsed ? (
            <PanelRightOpen className="w-4 h-4" />
          ) : (
            <PanelRightClose className="w-4 h-4" />
          )}
          Chat
        </button>
        <div className="hidden sm:block text-xs text-slate-500 truncate max-w-[180px]">
          {user?.email ?? user?.username}
        </div>
        <button
          onClick={() => void handleSignOut()}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          title="Sign out"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </header>

      <div className="flex-1 flex min-h-0">
        {/* Sidebar: full at lg+, collapsible icon rail at md, hidden below md */}
        <aside
          className={`hidden md:flex flex-col border-r border-slate-800 bg-slate-900/40 p-3 gap-4 transition-all ${
            railExpanded ? 'md:w-60' : 'md:w-[60px]'
          } lg:w-60`}
        >
          <div>
            <div
              className={`px-3 pb-2 text-[11px] font-medium uppercase tracking-wider text-slate-600 ${
                railExpanded ? 'block' : 'hidden'
              } lg:block`}
            >
              View
            </div>
            <nav className="space-y-1">
              {navLink('dashboard', 'Dashboard', LayoutDashboard)}
              {navLink('chat', 'Chat', MessageSquare)}
            </nav>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto">
            <div
              className={`px-3 pb-2 text-[11px] font-medium uppercase tracking-wider text-slate-600 ${
                railExpanded ? 'block' : 'hidden'
              } lg:block`}
            >
              Industries
            </div>
            {industryList()}
          </div>
        </aside>

        {/* Main area */}
        <main className="flex-1 flex min-w-0 pb-14 md:pb-0">
          {/* Dashboard pane: active view below lg; always present at lg+ */}
          <div
            className={`flex-1 min-w-0 @container ${
              view === 'dashboard' ? 'block' : 'hidden'
            } lg:block`}
          >
            <Dashboard />
          </div>

          {/* Chat pane: active view below lg; right split (collapsible) at lg+ */}
          <div
            className={`flex-1 min-w-0 lg:flex-none lg:w-[360px] xl:w-[420px] lg:border-l lg:border-slate-800 ${
              view === 'chat' ? 'block' : 'hidden'
            } ${chatCollapsed ? 'lg:hidden' : 'lg:block'}`}
          >
            <ChatPanel industryId={industry.id} />
          </div>
        </main>
      </div>

      {/* Mobile bottom tab bar */}
      <nav className="md:hidden fixed bottom-0 inset-x-0 h-14 bg-slate-900 border-t border-slate-800 flex items-stretch z-40 pb-[env(safe-area-inset-bottom)]">
        <MobileTab
          label="Dashboard"
          icon={LayoutDashboard}
          active={view === 'dashboard' && !industriesOpen}
          onClick={() => {
            setIndustriesOpen(false)
            navigate(`/${industry.id}/dashboard`)
          }}
        />
        <MobileTab
          label="Chat"
          icon={MessageSquare}
          active={view === 'chat' && !industriesOpen}
          onClick={() => {
            setIndustriesOpen(false)
            navigate(`/${industry.id}/chat`)
          }}
        />
        <MobileTab
          label="Industries"
          icon={Bot}
          active={industriesOpen}
          onClick={() => setIndustriesOpen((v) => !v)}
        />
      </nav>

      {/* Mobile industries sheet */}
      {industriesOpen && (
        <div className="md:hidden fixed inset-0 z-50 flex flex-col justify-end">
          <button
            aria-label="Close"
            className="absolute inset-0 bg-slate-950/70"
            onClick={() => setIndustriesOpen(false)}
          />
          <div className="relative bg-slate-900 border-t border-slate-800 rounded-t-2xl p-4 pb-[calc(1rem+env(safe-area-inset-bottom))] max-h-[70vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">Industries</h2>
              <button
                onClick={() => setIndustriesOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <nav className="space-y-1">
              {industries.map((item) => {
                const Icon = item.icon
                const active = item.id === industry.id
                return (
                  <Link
                    key={item.id}
                    to={`/${item.id}/${view}`}
                    onClick={() => setIndustriesOpen(false)}
                    className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm ${
                      active
                        ? 'bg-slate-800 text-white'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                    }`}
                  >
                    <Icon className={`w-5 h-5 shrink-0 ${item.themeColor}`} />
                    <span className="flex-1">
                      <span className="block">{item.name}</span>
                      <span className="block text-xs text-slate-500 line-clamp-1">
                        {item.description}
                      </span>
                    </span>
                    {!item.enabled && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-500">
                        soon
                      </span>
                    )}
                  </Link>
                )
              })}
            </nav>
          </div>
        </div>
      )}
    </div>
  )
}

function MobileTab({
  label,
  icon: Icon,
  active,
  onClick,
}: {
  label: string
  icon: typeof LayoutDashboard
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 flex flex-col items-center justify-center gap-0.5 text-[11px] transition-colors ${
        active ? 'text-blue-400' : 'text-slate-500 hover:text-slate-300'
      }`}
    >
      <Icon className="w-5 h-5" />
      {label}
    </button>
  )
}
