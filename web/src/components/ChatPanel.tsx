import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { Bot, Loader2, RefreshCw, Send, User } from 'lucide-react'
import { invokeAgent, newSessionId } from '../lib/agentClient'
import Markdown from './Markdown'
import { ChartCard } from './AnswerChartPanel'
import { chartFor, type ChartSpec } from '../lib/chartSpec'
import { AGENT_PROMPT_EVENT, publishAnswerCharts } from '../lib/promptBus'
import { industries } from '../industries/registry'
import { starterPrompts, type StarterPrompt } from '../industries/starterPrompts'
import { useAuth } from '../lib/AuthContext'

interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  streaming?: boolean
  /** Charts built from the tool payloads behind this answer. */
  charts?: ChartSpec[]
}

function sessionKey(industryId: string): string {
  return `agent-session:${industryId}`
}

function getOrCreateSession(industryId: string): string {
  const key = sessionKey(industryId)
  const existing = sessionStorage.getItem(key)
  if (existing) return existing
  const id = newSessionId()
  sessionStorage.setItem(key, id)
  return id
}

export default function ChatPanel({ industryId }: { industryId: string }) {
  const { user, getToken } = useAuth()
  const [sessionId, setSessionId] = useState(() => getOrCreateSession(industryId))
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const endRef = useRef<HTMLDivElement>(null)
  const abortRef = useRef<AbortController | null>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  // Prompt bus: dashboard "Ask agent" buttons prefill the input (never auto-send).
  useEffect(() => {
    const onPrompt = (event: Event) => {
      const detail = (event as CustomEvent<string>).detail
      if (typeof detail !== 'string') return
      setInput(detail)
      inputRef.current?.focus()
    }
    window.addEventListener(AGENT_PROMPT_EVENT, onPrompt)
    return () => window.removeEventListener(AGENT_PROMPT_EVENT, onPrompt)
  }, [])

  // Industry switch → pick up (or mint) that industry's session, clear the pane.
  useEffect(() => {
    setSessionId(getOrCreateSession(industryId))
    setMessages([])
    setError(null)
    abortRef.current?.abort()
    setStreaming(false)
    // Finance charts must not linger over the healthcare dashboard.
    publishAnswerCharts([])
  }, [industryId])

  // Unmounting takes the overlay with it: below lg the chat pane unmounts when
  // the user navigates to the dashboard view, and a panel left behind would
  // outlive the conversation that produced it.
  useEffect(() => () => publishAnswerCharts([]), [])

  // Follow the conversation, but only once there is one. On an empty pane this
  // fired on mount and scrolled the starter list to the bottom of its scroller,
  // pushing the first two questions above the visible top (measured: the pane
  // began at y=24 inside a viewport starting at y=117).
  useEffect(() => {
    if (messages.length === 0) return
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  useEffect(() => () => abortRef.current?.abort(), [])

  const newSession = useCallback(() => {
    abortRef.current?.abort()
    const id = newSessionId()
    sessionStorage.setItem(sessionKey(industryId), id)
    setSessionId(id)
    setMessages([])
    setError(null)
    setStreaming(false)
    publishAnswerCharts([])
  }, [industryId])

  const send = useCallback(
    async (prompt: string) => {
      if (!prompt.trim() || streaming) return
      setError(null)

      const userMsg: ChatMessage = {
        id: crypto.randomUUID(),
        role: 'user',
        content: prompt.trim(),
      }
      const assistantId = crypto.randomUUID()
      setMessages((prev) => [
        ...prev,
        userMsg,
        { id: assistantId, role: 'assistant', content: '', streaming: true },
      ])
      setStreaming(true)
      // The previous answer's charts describe the previous question. Leaving them
      // up while a new answer streams is the one way this panel could actively
      // mislead, so they go before the new request starts.
      publishAnswerCharts([])

      const controller = new AbortController()
      abortRef.current = controller

      try {
        const token = await getToken()
        if (!token) throw new Error('Session expired — please sign in again.')

        // Charts for THIS answer only. Accumulated locally rather than in state
        // so a second tool arriving does not re-render the whole message list
        // mid-stream; the finished set is committed to the message below.
        const specs: ChartSpec[] = []

        let received = false
        for await (const chunk of invokeAgent(prompt.trim(), sessionId, token, {
          actorId: user?.sub,
          harnessArn: industries.find((i) => i.id === industryId)?.harnessArn,
          signal: controller.signal,
          onToolCall: (call) => {
            const spec = chartFor(call.tool, call.payload)
            // Most tools have nothing worth plotting; chartFor returns null and
            // no panel appears. Duplicate titles are dropped so an agent that
            // retries a call does not paginate the same chart twice.
            if (!spec || specs.some((s) => s.title === spec.title)) return
            specs.push(spec)
            // Published as it arrives so the panel opens while prose streams.
            publishAnswerCharts([...specs])
            setMessages((prev) =>
              prev.map((m) =>
                m.id === assistantId ? { ...m, charts: [...specs] } : m,
              ),
            )
          },
        })) {
          received = true
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantId ? { ...m, content: m.content + chunk } : m,
            ),
          )
        }
        if (!received) {
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantId
                ? { ...m, content: '(no response from agent)' }
                : m,
            ),
          )
        }
      } catch (err: unknown) {
        if (!controller.signal.aborted) {
          setError(err instanceof Error ? err.message : String(err))
          // Drop the empty assistant bubble on failure.
          setMessages((prev) =>
            prev.filter((m) => !(m.id === assistantId && m.content === '')),
          )
        }
      } finally {
        setMessages((prev) =>
          prev.map((m) => (m.id === assistantId ? { ...m, streaming: false } : m)),
        )
        setStreaming(false)
      }
    },
    [streaming, sessionId, user?.sub, getToken],
  )

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    const prompt = input
    setInput('')
    void send(prompt)
  }

  return (
    <div className="flex flex-col h-full bg-slate-950">
      {/* Header */}
      <div className="px-4 py-3 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between gap-2">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-white truncate">AI Assistant</h2>
          <p className="text-[11px] text-slate-500 truncate">
            AgentCore Harness · session {sessionId.slice(0, 8)}…
          </p>
        </div>
        <button
          onClick={newSession}
          title="Start a new session"
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 transition-colors shrink-0"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          New session
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 && (
          <StarterPane
            description={industries.find((i) => i.id === industryId)?.description}
            prompts={starterPrompts(industryId)}
            disabled={streaming}
            onPick={(prompt) => void send(prompt)}
          />
        )}
        {messages.map((msg) => (
          <MessageBubble key={msg.id} message={msg} />
        ))}
        <div ref={endRef} />
      </div>

      {/* Error */}
      {error && (
        <div className="mx-4 mb-2 px-3 py-2 rounded-lg bg-red-950/50 border border-red-900 text-xs text-red-300 break-all">
          {error}
        </div>
      )}

      {/* Input */}
      <form onSubmit={handleSubmit} className="p-3 border-t border-slate-800 bg-slate-900/60">
        <div className="flex items-end gap-2">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                if (input.trim() && !streaming) handleSubmit(e)
              }
            }}
            rows={2}
            placeholder="Ask the agent…"
            disabled={streaming}
            className="flex-1 resize-none px-3 py-2.5 bg-slate-800 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={!input.trim() || streaming}
            className="p-2.5 bg-blue-600 rounded-xl text-white hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            title="Send"
          >
            {streaming ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              <Send className="w-5 h-5" />
            )}
          </button>
        </div>
      </form>
    </div>
  )
}

/** Empty-pane starter questions.
 *
 * A click sends straight away rather than prefilling: this pane only ever shows
 * on an empty conversation, so there is no in-progress thought to interrupt and
 * one click is the whole point. (The dashboard "Ask agent" buttons do prefill —
 * those fire mid-conversation, where silently sending would hijack the turn.)
 *
 * Laid out as a scrollable column, not a vertically-centred block: five starters
 * plus the description overflow a short mobile pane, and centring clipped the
 * last one with no way to reach it.
 *
 * The header is deliberately small. Measured on a 390x664 viewport the pane is
 * 404px tall; a centred 32px robot plus a 3-line centred description took 172px
 * of it (43%), leaving one and a half cards above the fold — the starters are the
 * point of this pane, so the branding gives way to them. Icon and text now sit on
 * one row, and the description is clamped to two lines.
 */
function StarterPane({
  description,
  prompts,
  disabled,
  onPick,
}: {
  description?: string
  prompts: StarterPrompt[]
  disabled: boolean
  onPick: (prompt: string) => void
}) {
  return (
    <div
      data-testid="starter-pane"
      className="flex flex-col items-center gap-3 pt-1 pb-2"
    >
      <div className="w-full max-w-[340px] flex items-start gap-2.5">
        <Bot className="w-5 h-5 text-slate-500 shrink-0 mt-0.5" />
        <p className="text-xs leading-snug text-slate-500 line-clamp-2">
          {description ?? 'Ask the agent anything about this industry.'}
        </p>
      </div>

      {prompts.length > 0 && (
        <div className="w-full max-w-[340px] flex flex-col gap-2">
          <p className="text-[11px] uppercase tracking-wide text-slate-600 font-medium">
            Try asking
          </p>
          {prompts.map((starter) => (
            <button
              key={starter.label}
              type="button"
              disabled={disabled}
              onClick={() => onPick(starter.prompt)}
              data-testid="starter-prompt"
              title={starter.prompt}
              className="group w-full text-left px-3 py-2.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-600 hover:bg-slate-800/70 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <span className="block text-xs font-medium text-slate-200">
                {starter.label}
              </span>
              <span className="block mt-0.5 text-[11px] leading-snug text-slate-500 group-hover:text-slate-400">
                {starter.prompt}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function MessageBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === 'user'
  return (
    <div data-role={message.role}
         className={`flex gap-2.5 ${isUser ? 'justify-end' : 'justify-start'}`}>
      {!isUser && (
        <div className="w-7 h-7 bg-blue-600 rounded-lg flex items-center justify-center shrink-0 mt-0.5">
          <Bot className="w-4 h-4 text-white" />
        </div>
      )}
      {/* Assistant bubbles run wider than user bubbles: they carry tables, and at
          80% of a 620px pane a five-column table is already scrolling. min-w-0 is
          required for the table's overflow-x-auto to work at all — without it the
          flex item sizes to its content and the table pushes the bubble past the
          pane instead of scrolling inside it. */}
      <div
        className={`px-3.5 py-2.5 rounded-2xl text-sm leading-relaxed ${
          isUser
            ? 'max-w-[80%] bg-blue-600 text-white rounded-br-md'
            : 'max-w-[92%] min-w-0 bg-slate-800 text-slate-200 rounded-bl-md border border-slate-700'
        }`}
      >
        {isUser ? (
          <div className="whitespace-pre-wrap break-words">{message.content}</div>
        ) : (
          <>
            {/* Parsing is skipped while streaming: half-arrived Markdown reparses
                on every chunk and a table renders as a flickering pile of pipes
                until its separator row lands. Plain text until the stream ends,
                then one clean parse. */}
            {message.streaming ? (
              <div className="whitespace-pre-wrap break-words">{message.content}</div>
            ) : (
              <Markdown>{message.content}</Markdown>
            )}
            {message.streaming && (
              <span className="inline-block w-1.5 h-4 ml-0.5 align-text-bottom bg-slate-400 animate-pulse rounded-sm" />
            )}
            {/* Inline charts, below lg only. At lg+ the same specs are drawn in
                the overlay above the dashboard, so rendering both would show the
                chart twice side by side. Below lg the dashboard is a separate
                view the user is not currently looking at, so the chart has to
                live with the message that produced it. */}
            {message.charts && message.charts.length > 0 && (
              <div
                data-testid="inline-answer-charts"
                className="lg:hidden mt-3 -mx-1 space-y-4 border-t border-slate-700 pt-3"
              >
                {message.charts.map((spec) => (
                  <ChartCard key={spec.title} spec={spec} />
                ))}
              </div>
            )}
          </>
        )}
      </div>
      {isUser && (
        <div className="w-7 h-7 bg-slate-700 rounded-lg flex items-center justify-center shrink-0 mt-0.5">
          <User className="w-4 h-4 text-slate-300" />
        </div>
      )}
    </div>
  )
}
