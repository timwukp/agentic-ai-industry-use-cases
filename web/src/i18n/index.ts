/** Locale registry, message loading, and the module-level locale cell.
 *
 * Hand-rolled rather than a library: ~500 strings, one provider, one t()
 * function. TS modules per locale mean a missing translation key is a compile
 * error (`satisfies Messages`), which no JSON-catalog library provides.
 *
 * English is imported statically — the fallback dictionary must never await a
 * network. The other 15 locales are dynamic imports, so each becomes its own
 * chunk, fetched the first time it is chosen and precached by the service
 * worker thereafter.
 */
import { en, type Messages } from './messages/en.ts'

export const LOCALES = [
  'en',
  'zh-TW',
  'zh-CN',
  'ja',
  'ko',
  'fr',
  'es',
  'it',
  'pt',
  'de',
  'id',
  'ms',
  'th',
  'vi',
  'fil',
  'hi',
] as const

export type Locale = (typeof LOCALES)[number]

/** Each language names itself — an endonym needs no translation. */
export const LOCALE_NAMES: Record<Locale, string> = {
  en: 'English',
  'zh-TW': '繁體中文',
  'zh-CN': '简体中文',
  ja: '日本語',
  ko: '한국어',
  fr: 'Français',
  es: 'Español',
  it: 'Italiano',
  pt: 'Português',
  de: 'Deutsch',
  id: 'Bahasa Indonesia',
  ms: 'Bahasa Melayu',
  th: 'ไทย',
  vi: 'Tiếng Việt',
  fil: 'Filipino',
  hi: 'हिन्दी',
}

const loaders: Record<Locale, () => Promise<Messages>> = {
  en: () => Promise.resolve(en),
  'zh-TW': () => import('./messages/zh-TW').then((m) => m.zhTW),
  'zh-CN': () => import('./messages/zh-CN').then((m) => m.zhCN),
  ja: () => import('./messages/ja').then((m) => m.ja),
  ko: () => import('./messages/ko').then((m) => m.ko),
  fr: () => import('./messages/fr').then((m) => m.fr),
  es: () => import('./messages/es').then((m) => m.es),
  it: () => import('./messages/it').then((m) => m.it),
  pt: () => import('./messages/pt').then((m) => m.pt),
  de: () => import('./messages/de').then((m) => m.de),
  id: () => import('./messages/id').then((m) => m.id),
  ms: () => import('./messages/ms').then((m) => m.ms),
  th: () => import('./messages/th').then((m) => m.th),
  vi: () => import('./messages/vi').then((m) => m.vi),
  fil: () => import('./messages/fil').then((m) => m.fil),
  hi: () => import('./messages/hi').then((m) => m.hi),
}

export function loadMessages(locale: Locale): Promise<Messages> {
  return loaders[locale]()
}

export const STORAGE_KEY = 'ui-locale'

/** The persisted choice, else English.
 *
 * Deliberately NOT navigator.language: E2E runs and screenshot verification
 * need a deterministic English default on a fresh profile, and an explicit
 * picker choice is a stronger signal than a browser setting anyway.
 */
export function initialLocale(): Locale {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored && (LOCALES as readonly string[]).includes(stored)) {
      return stored as Locale
    }
  } catch {
    // Storage unavailable (private mode with quota 0) — English it is.
  }
  return 'en'
}

/** Replaces {name} tokens. Unknown tokens stay verbatim — a visible,
 *  greppable failure beats a silently dropped value. */
export function interpolate(
  template: string,
  params?: Record<string, string | number>,
): string {
  if (!params) return template
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in params ? String(params[name]) : whole,
  )
}

/* ------------------------- module-level locale cell ------------------------
 *
 * Pure modules (agentClient's language directive, the number formatters in the
 * dashboard widgets) need the current locale but must not depend on React.
 * This cell is written ONLY by LocaleProvider; everything else reads.
 * Components re-render on locale change via context, so render-time reads of
 * this cell are always fresh.
 */
let currentLocale: Locale = initialLocale()
let currentMessages: Messages = en

export function getCurrentLocale(): Locale {
  return currentLocale
}

export function getMessages(): Messages {
  return currentMessages
}

/** Provider-only. Exported with an underscore to say so. */
export function _setCurrent(locale: Locale, messages: Messages): void {
  currentLocale = locale
  currentMessages = messages
}

export { en }
export type { Messages }
