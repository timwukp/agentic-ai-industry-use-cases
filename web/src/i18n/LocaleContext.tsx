/** UI locale provider — the AuthContext pattern applied to language.
 *
 * The provider owns the current locale and message dictionary; `useLocale()`
 * hands components `t()`. It is also the single writer of the module-level
 * cell in i18n/index.ts, which is how pure non-React modules (the language
 * directive in agentClient, the number formatters) see the same locale
 * without prop-drilling.
 *
 * Switching keeps the PREVIOUS dictionary on screen until the new chunk
 * resolves — a beat of the old language is invisible; a beat of raw
 * `chrome.dashboard` keys is not.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import {
  STORAGE_KEY,
  _setCurrent,
  en,
  initialLocale,
  interpolate,
  loadMessages,
  type Locale,
  type Messages,
} from './index'

interface LocaleContextValue {
  locale: Locale
  messages: Messages
  setLocale: (locale: Locale) => void
  /** t('chat.tryAsking') or t('charts.sessions', {n: 30}) */
  t: (key: string, params?: Record<string, string | number>) => string
}

const LocaleContext = createContext<LocaleContextValue | null>(null)

/** Dot-path lookup with the English dictionary as the safety net. The type
 *  system makes a missing key a compile error in the locale files, so the
 *  fallback exists for the one hole types cannot cover: a key typo at a
 *  CALL SITE, where returning the English text (or, failing that, the key
 *  itself) is the legible failure. */
function lookup(dict: Messages, key: string): string | undefined {
  let node: unknown = dict
  for (const part of key.split('.')) {
    if (!node || typeof node !== 'object') return undefined
    node = (node as Record<string, unknown>)[part]
  }
  return typeof node === 'string' ? node : undefined
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(initialLocale)
  const [messages, setMessages] = useState<Messages>(en)
  // Guards a slow chunk resolving after the user has already switched again.
  const requestRef = useRef(0)

  useEffect(() => {
    const request = ++requestRef.current
    let cancelled = false
    loadMessages(locale)
      .then((dict) => {
        if (cancelled || request !== requestRef.current) return
        _setCurrent(locale, dict)
        setMessages(dict)
        document.documentElement.lang = locale
        document.title = dict.chrome.appTitle
      })
      .catch(() => {
        // A failed chunk fetch (offline, first visit) leaves the previous
        // language in place — degraded, not broken.
      })
    return () => {
      cancelled = true
    }
  }, [locale])

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next)
    try {
      localStorage.setItem(STORAGE_KEY, next)
    } catch {
      // Private-mode quota: the choice just won't survive a reload.
    }
  }, [])

  const t = useCallback(
    (key: string, params?: Record<string, string | number>) => {
      const text = lookup(messages, key) ?? lookup(en, key) ?? key
      return interpolate(text, params)
    },
    [messages],
  )

  return (
    <LocaleContext.Provider value={{ locale, messages, setLocale, t }}>
      {children}
    </LocaleContext.Provider>
  )
}

export function useLocale(): LocaleContextValue {
  const ctx = useContext(LocaleContext)
  if (!ctx) throw new Error('useLocale must be used within LocaleProvider')
  return ctx
}
