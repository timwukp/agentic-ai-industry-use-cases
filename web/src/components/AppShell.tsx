import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom'
import {
  Bot,
  LayoutDashboard,
  Network,
  LogOut,
  Maximize2,
  MessageSquare,
  Minimize2,
  PanelLeftClose,
  PanelLeftOpen,
  PanelRightClose,
  PanelRightOpen,
  X,
} from 'lucide-react'
import { getIndustry, industries, DEFAULT_INDUSTRY_ID } from '../industries/registry'
import { useLocale } from '../i18n/LocaleContext'
import { AGENT_PROMPT_EVENT, ANSWER_CHARTS_EVENT } from '../lib/promptBus'
import { useAuth } from '../lib/AuthContext'
import AnswerChartPanel from './AnswerChartPanel'
import type { ChartSpec } from '../lib/chartSpec'
import ArchitecturePage from './ArchitecturePage'
import ChatPanel from './ChatPanel'
import LocalePicker from './LocalePicker'

export type ShellView = 'dashboard' | 'chat' | 'architecture'

/** Desktop chat pane display mode. 'normal' honors the resizable width;
 *  'max' fills the main area (dashboard hidden); 'min' collapses to a thin
 *  rail with just a restore button — distinct from hidden, which removes it
 *  entirely and is toggled from the header. */
type ChatMode = 'normal' | 'max' | 'min'

const CHAT_WIDTH_KEY = 'chat-panel-width'
const CHAT_MIN_W = 280
const CHAT_MAX_W = 720
const CHAT_DEFAULT_W = 400

function initialChatWidth(): number {
  const stored = Number(localStorage.getItem(CHAT_WIDTH_KEY))
  if (Number.isFinite(stored) && stored >= CHAT_MIN_W && stored <= CHAT_MAX_W) {
    return stored
  }
  return CHAT_DEFAULT_W
}

export default function AppShell({ view }: { view: ShellView }) {
  const { industryId } = useParams()
  const navigate = useNavigate()
  const { user, signOut } = useAuth()
  const { t } = useLocale()

  const industry = getIndustry(industryId)

  // Desktop-only chat collapse; md rail expansion; mobile industries sheet.
  const [chatCollapsed, setChatCollapsed] = useState(false)
  const [railExpanded, setRailExpanded] = useState(false)
  const [industriesOpen, setIndustriesOpen] = useState(false)
  // Resizable chat pane (desktop): width persists across sessions; mode
  // handles maximize/minimize without losing the user's chosen width.
  const [chatWidth, setChatWidth] = useState(initialChatWidth)
  const [chatMode, setChatMode] = useState<ChatMode>('normal')
  const dragging = useRef(false)

  const beginDrag = useCallback(
    (event: React.PointerEvent) => {
      event.preventDefault()
      dragging.current = true
      const startX = event.clientX
      const startW = chatWidth
      const onMove = (e: PointerEvent) => {
        if (!dragging.current) return
        // handle sits left of the chat pane: dragging left widens the chat
        const next = Math.min(
          CHAT_MAX_W,
          Math.max(CHAT_MIN_W, startW + (startX - e.clientX)),
        )
        setChatWidth(next)
      }
      const onUp = () => {
        dragging.current = false
        setChatWidth((w) => {
          localStorage.setItem(CHAT_WIDTH_KEY, String(w))
          return w
        })
        window.removeEventListener('pointermove', onMove)
        window.removeEventListener('pointerup', onUp)
      }
      window.addEventListener('pointermove', onMove)
      window.addEventListener('pointerup', onUp)
    },
    [chatWidth],
  )

  // Keyboard resize on the separator (a11y): arrows nudge 24px.
  const onHandleKeyDown = useCallback((event: React.KeyboardEvent) => {
    const delta =
      event.key === 'ArrowLeft' ? 24 : event.key === 'ArrowRight' ? -24 : 0
    if (!delta) return
    event.preventDefault()
    setChatWidth((w) => {
      const next = Math.min(CHAT_MAX_W, Math.max(CHAT_MIN_W, w + delta))
      localStorage.setItem(CHAT_WIDTH_KEY, String(next))
      return next
    })
  }, [])
  // Charts extracted from the current answer, published by ChatPanel. Held here
  // rather than in the dashboard because the dashboard is per-industry and would
  // lose them on any remount; the panel belongs to the conversation, not the view.
  const [answerCharts, setAnswerCharts] = useState<ChartSpec[]>([])

  // Navigating to the chat tab always reveals the chat pane on desktop too.
  useEffect(() => {
    if (view === 'chat') setChatCollapsed(false)
  }, [view])

  useEffect(() => {
    setIndustriesOpen(false)
  }, [industryId])

  // Prompt bus: an "Ask agent" click reveals the chat pane — un-collapse on
  // desktop, and below lg (where dashboard/chat are separate views) switch to
  // the chat view so the prefilled input is visible.
  useEffect(() => {
    const onPrompt = () => {
      setChatCollapsed(false)
      const belowLg = !window.matchMedia('(min-width: 1024px)').matches
      if (belowLg && view !== 'chat' && industry) {
        navigate(`/${industry.id}/chat`)
      }
    }
    window.addEventListener(AGENT_PROMPT_EVENT, onPrompt)
    return () => window.removeEventListener(AGENT_PROMPT_EVENT, onPrompt)
  }, [view, industry, navigate])

  // Answer charts: the reverse channel. An empty array is the dismiss signal, so
  // clearing goes through the same listener rather than a second event.
  useEffect(() => {
    const onCharts = (event: Event) => {
      const detail = (event as CustomEvent<unknown>).detail
      setAnswerCharts(Array.isArray(detail) ? (detail as ChartSpec[]) : [])
    }
    window.addEventListener(ANSWER_CHARTS_EVENT, onCharts)
    return () => window.removeEventListener(ANSWER_CHARTS_EVENT, onCharts)
  }, [])

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
            title={t(`industries.${item.id}.name`)}
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
              {t(`industries.${item.id}.name`)}
            </span>
            {!item.enabled && (
              <span
                className={`${railExpanded ? 'inline' : 'hidden'} lg:inline text-[10px] px-1.5 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-500`}
              >
                {t('chrome.soon')}
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
            title={railExpanded ? t('chrome.collapseSidebar') : t('chrome.expandSidebar')}
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
          <h1 className="text-sm font-semibold text-white truncate">
            {t(`industries.${industry.id}.name`)}
          </h1>
        </div>
        <div className="flex-1" />
        {/* Desktop chat collapse toggle */}
        <button
          onClick={() => setChatCollapsed((v) => !v)}
          className="hidden lg:inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 transition-colors"
          title={chatCollapsed ? t('chrome.showChat') : t('chrome.hideChat')}
        >
          {chatCollapsed ? (
            <PanelRightOpen className="w-4 h-4" />
          ) : (
            <PanelRightClose className="w-4 h-4" />
          )}
          {t('chrome.chat')}
        </button>
        <LocalePicker />
        <div className="hidden sm:block text-xs text-slate-500 truncate max-w-[180px]">
          {user?.email ?? user?.username}
        </div>
        <button
          onClick={() => void handleSignOut()}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          title={t('chrome.signOut')}
          aria-label={t('chrome.signOut')}
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
              {t('chrome.view')}
            </div>
            <nav className="space-y-1">
              {/* Dashboard/Chat switch panes only below lg (at lg+ both panes
                  are side by side), so the links only exist where they act. */}
              <div className="lg:hidden space-y-1">
                {navLink('dashboard', t('chrome.dashboard'), LayoutDashboard)}
                {navLink('chat', t('chrome.chat'), MessageSquare)}
              </div>
              {navLink('architecture', t('chrome.architecture'), Network)}
            </nav>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto">
            <div
              className={`px-3 pb-2 text-[11px] font-medium uppercase tracking-wider text-slate-600 ${
                railExpanded ? 'block' : 'hidden'
              } lg:block`}
            >
              {t('chrome.industries')}
            </div>
            {industryList()}
          </div>
        </aside>

        {/* Main area */}
        <main className="flex-1 flex min-w-0 pb-14 md:pb-0">
          {/* Dashboard pane: active view below lg; always present at lg+
              unless the chat is maximized. A column so the answer-chart
              overlay can take the space it needs at the top while the
              dashboard keeps its own scroller below. */}
          <div
            className={`flex-1 min-w-0 flex flex-col @container ${
              view === 'dashboard' ? 'flex' : 'hidden'
            } ${
              view === 'architecture' || (chatMode === 'max' && !chatCollapsed)
                ? 'lg:hidden'
                : 'lg:flex'
            }`}
          >
            {/* lg+ only: below lg the same charts render inline under the message
                (see ChatPanel), because there the dashboard is a different view.

                The cap is 55%, not 45%: the tallest recognized chart is the
                11-row sector ranking at ~330px (see chartHeight), and at 45% of a
                720px window it was clipped mid-bar. overflow-y-auto is the
                backstop for a shorter window, not the normal case — a chart the
                user must scroll to finish reading is only marginally better than
                the table it replaced. */}
            <div className="hidden lg:block shrink-0 max-h-[55%] overflow-y-auto">
              <AnswerChartPanel
                specs={answerCharts}
                onDismiss={() => setAnswerCharts([])}
              />
            </div>
            <div className="flex-1 min-h-0">
              <Dashboard />
            </div>
          </div>

          {/* Architecture pane: stateless, so mounted only when active
              (dashboard/chat stay mounted and hide via CSS to keep state). */}
          {view === 'architecture' && (
            <div className="flex-1 min-w-0 min-h-0">
              <ArchitecturePage />
            </div>
          )}

          {/* Resize handle: desktop only, hidden when chat is collapsed,
              minimized, or maximized (no boundary to drag in those states). */}
          {view !== 'architecture' && !chatCollapsed && chatMode === 'normal' && (
            <div
              role="separator"
              aria-orientation="vertical"
              aria-label={t('chrome.resizeChat')}
              tabIndex={0}
              onPointerDown={beginDrag}
              onKeyDown={onHandleKeyDown}
              className="hidden lg:flex w-1.5 shrink-0 cursor-col-resize items-center justify-center bg-slate-800/40 hover:bg-blue-500/60 focus:bg-blue-500/60 focus:outline-none transition-colors"
              data-testid="chat-resize-handle"
            >
              <div className="h-8 w-0.5 rounded bg-slate-600" />
            </div>
          )}

          {/* Chat pane: active view below lg; right split at lg+ with
              normal (resizable) / max / min modes. */}
          {view !== 'architecture' && chatMode === 'min' && !chatCollapsed ? (
            <div className="hidden lg:flex w-11 shrink-0 border-l border-slate-800 bg-slate-900/60 flex-col items-center pt-3 gap-2">
              <button
                onClick={() => setChatMode('normal')}
                className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                title={t('chrome.restoreChat')}
                aria-label={t('chrome.restoreChat')}
                data-testid="chat-restore"
              >
                <MessageSquare className="w-5 h-5" />
              </button>
            </div>
          ) : (
            <div
              className={`min-w-0 lg:border-l lg:border-slate-800 ${
                view === 'chat' ? 'flex-1 block' : 'hidden'
              } ${chatCollapsed || view === 'architecture' ? 'lg:hidden' : 'lg:block'} ${
                chatMode === 'max' ? 'lg:flex-1' : 'lg:flex-none'
              }`}
              style={
                chatMode === 'normal'
                  ? ({ ['--chat-w' as string]: `${chatWidth}px` } as React.CSSProperties)
                  : undefined
              }
              data-chat-mode={chatMode}
            >
              <div
                className={`h-full flex flex-col ${
                  chatMode === 'normal' ? 'lg:w-[var(--chat-w)]' : ''
                }`}
              >
                {/* Chat window controls: max/min (desktop only) */}
                <div className="hidden lg:flex items-center justify-end gap-1 px-2 pt-2">
                  <button
                    onClick={() => setChatMode(chatMode === 'max' ? 'normal' : 'max')}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800 transition-colors"
                    title={
                      chatMode === 'max'
                        ? t('chrome.restoreChat')
                        : t('chrome.maximizeChat')
                    }
                    aria-label={
                      chatMode === 'max'
                        ? t('chrome.restoreChat')
                        : t('chrome.maximizeChat')
                    }
                    data-testid="chat-maximize"
                  >
                    <Maximize2 className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setChatMode('min')}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800 transition-colors"
                    title={t('chrome.minimizeChat')}
                    aria-label={t('chrome.minimizeChat')}
                    data-testid="chat-minimize"
                  >
                    <Minimize2 className="w-3.5 h-3.5" />
                  </button>
                </div>
                <div className="flex-1 min-h-0">
                  <ChatPanel industryId={industry.id} />
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Mobile bottom tab bar */}
      <nav className="md:hidden fixed bottom-0 inset-x-0 h-14 bg-slate-900 border-t border-slate-800 flex items-stretch z-40 pb-[env(safe-area-inset-bottom)]">
        <MobileTab
          label={t('chrome.dashboard')}
          icon={LayoutDashboard}
          active={view === 'dashboard' && !industriesOpen}
          onClick={() => {
            setIndustriesOpen(false)
            navigate(`/${industry.id}/dashboard`)
          }}
        />
        <MobileTab
          label={t('chrome.chat')}
          icon={MessageSquare}
          active={view === 'chat' && !industriesOpen}
          onClick={() => {
            setIndustriesOpen(false)
            navigate(`/${industry.id}/chat`)
          }}
        />
        <MobileTab
          label={t('chrome.architecture')}
          icon={Network}
          active={view === 'architecture' && !industriesOpen}
          onClick={() => {
            setIndustriesOpen(false)
            navigate(`/${industry.id}/architecture`)
          }}
        />
        <MobileTab
          label={t('chrome.industries')}
          icon={Bot}
          active={industriesOpen}
          onClick={() => setIndustriesOpen((v) => !v)}
        />
      </nav>

      {/* Mobile industries sheet */}
      {industriesOpen && (
        <div className="md:hidden fixed inset-0 z-50 flex flex-col justify-end">
          <button
            aria-label={t('chrome.close')}
            className="absolute inset-0 bg-slate-950/70"
            onClick={() => setIndustriesOpen(false)}
          />
          <div className="relative bg-slate-900 border-t border-slate-800 rounded-t-2xl p-4 pb-[calc(1rem+env(safe-area-inset-bottom))] max-h-[70vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">{t('chrome.industries')}</h2>
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
                      <span className="block">{t(`industries.${item.id}.name`)}</span>
                      <span className="block text-xs text-slate-500 line-clamp-1">
                        {t(`industries.${item.id}.description`)}
                      </span>
                    </span>
                    {!item.enabled && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-500">
                        {t('chrome.soon')}
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
      <span className="truncate max-w-full px-0.5">{label}</span>
    </button>
  )
}
