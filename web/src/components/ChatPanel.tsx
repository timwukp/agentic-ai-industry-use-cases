import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { Bot, Loader2, RefreshCw, Send, User } from 'lucide-react'
import { invokeAgent, newSessionId } from '../lib/agentClient'
import { AGENT_PROMPT_EVENT } from '../lib/promptBus'
import { industries } from '../industries/registry'
import { useAuth } from '../lib/AuthContext'

interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  streaming?: boolean
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
  }, [industryId])

  useEffect(() => {
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

      const controller = new AbortController()
      abortRef.current = controller

      try {
        const token = await getToken()
        if (!token) throw new Error('Session expired — please sign in again.')

        let received = false
        for await (const chunk of invokeAgent(prompt.trim(), sessionId, token, {
          actorId: user?.sub,
          harnessArn: industries.find((i) => i.id === industryId)?.harnessArn,
          signal: controller.signal,
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
          <div className="h-full flex flex-col items-center justify-center text-center gap-3 text-slate-500">
            <Bot className="w-8 h-8" />
            <p className="text-sm max-w-[240px]">
              {industries.find((i) => i.id === industryId)?.description ??
                'Ask the agent anything about this industry.'}
            </p>
          </div>
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
      <div
        className={`max-w-[80%] px-3.5 py-2.5 rounded-2xl text-sm leading-relaxed ${
          isUser
            ? 'bg-blue-600 text-white rounded-br-md'
            : 'bg-slate-800 text-slate-200 rounded-bl-md border border-slate-700'
        }`}
      >
        <div className="whitespace-pre-wrap break-words">
          {message.content}
          {message.streaming && (
            <span className="inline-block w-1.5 h-4 ml-0.5 align-text-bottom bg-slate-400 animate-pulse rounded-sm" />
          )}
        </div>
      </div>
      {isUser && (
        <div className="w-7 h-7 bg-slate-700 rounded-lg flex items-center justify-center shrink-0 mt-0.5">
          <User className="w-4 h-4 text-slate-300" />
        </div>
      )}
    </div>
  )
}
