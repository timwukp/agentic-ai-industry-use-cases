import { useEffect, useMemo, useState } from 'react'
import { History, Loader2, MessageSquare, Search, X } from 'lucide-react'
import { apiGet } from '../lib/api'
import { useLocale } from '../i18n/LocaleContext'

export interface SessionIndexEntry {
  sessionId: string
  industryId: string
  title: string
  summary?: string | null
  startedAt: string
  updatedAt: string
  messageCount: number
}

export interface SavedTranscript {
  sessionId: string
  industryId: string
  messages: Array<{ role: 'user' | 'assistant'; content: string }>
  summary?: string | null
}

/** Slide-over listing the caller's saved sessions with client-side search
 *  over title + summary + industry. Selecting one loads the transcript and
 *  hands it to the chat window. Search is client-side: the index is one
 *  small JSON per user (≤500 entries), so a round-trip per keystroke would
 *  buy nothing. */
export default function ChatHistoryDrawer({
  open,
  onClose,
  onLoad,
}: {
  open: boolean
  onClose: () => void
  onLoad: (transcript: SavedTranscript) => void
}) {
  const { t } = useLocale()
  const [entries, setEntries] = useState<SessionIndexEntry[] | null>(null)
  const [query, setQuery] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loadingId, setLoadingId] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setError(null)
    setEntries(null)
    apiGet<{ sessions: SessionIndexEntry[] }>('/api/chat/sessions')
      .then((r) => setEntries(r.sessions))
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e)),
      )
  }, [open])

  const filtered = useMemo(() => {
    if (!entries) return []
    const q = query.trim().toLowerCase()
    if (!q) return entries
    return entries.filter((s) =>
      [s.title, s.summary ?? '', s.industryId, s.sessionId]
        .join(' ')
        .toLowerCase()
        .includes(q),
    )
  }, [entries, query])

  const pick = async (entry: SessionIndexEntry) => {
    setLoadingId(entry.sessionId)
    setError(null)
    try {
      const transcript = await apiGet<SavedTranscript>(
        `/api/chat/session?id=${encodeURIComponent(entry.sessionId)}`,
      )
      onLoad(transcript)
      onClose()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoadingId(null)
    }
  }

  if (!open) return null

  return (
    <div className="absolute inset-0 z-30 flex" data-testid="history-drawer">
      <button
        aria-label={t('chrome.close')}
        className="absolute inset-0 bg-slate-950/70"
        onClick={onClose}
      />
      <div className="relative ml-auto h-full w-full max-w-sm bg-slate-900 border-l border-slate-700 flex flex-col">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2">
          <History className="w-4 h-4 text-slate-400" />
          <h3 className="text-sm font-semibold text-white flex-1">
            {t('chat.historyTitle')}
          </h3>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
            aria-label={t('chrome.close')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-3 border-b border-slate-800">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('chat.historySearch')}
              data-testid="history-search"
              className="w-full pl-8 pr-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
          {entries === null && !error && (
            <div className="flex items-center justify-center gap-2 py-10 text-slate-500 text-xs">
              <Loader2 className="w-4 h-4 animate-spin" />
              {t('widgets.loading')}
            </div>
          )}
          {error && (
            <div className="mx-2 my-3 px-3 py-2 rounded-lg bg-red-950/50 border border-red-900 text-xs text-red-300 break-all">
              {error}
            </div>
          )}
          {entries !== null && filtered.length === 0 && !error && (
            <p className="text-center text-xs text-slate-500 py-10">
              {query ? t('chat.historyNoMatch') : t('chat.historyEmpty')}
            </p>
          )}
          {filtered.map((s) => (
            <button
              key={s.sessionId}
              onClick={() => void pick(s)}
              disabled={loadingId !== null}
              data-testid="history-entry"
              className="w-full text-left px-3 py-2.5 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-slate-600 hover:bg-slate-800/60 disabled:opacity-50 transition-colors"
            >
              <div className="flex items-center gap-2">
                <MessageSquare className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                <span className="text-xs font-medium text-slate-200 truncate flex-1">
                  {s.summary || s.title}
                </span>
                {loadingId === s.sessionId && (
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-400" />
                )}
              </div>
              <div className="mt-1 flex items-center gap-2 text-[10px] text-slate-500">
                <span className="px-1.5 py-0.5 rounded bg-slate-800">{s.industryId}</span>
                <span>{new Date(s.updatedAt).toLocaleString()}</span>
                <span>
                  {s.messageCount} {t('chat.historyMessages')}
                </span>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
