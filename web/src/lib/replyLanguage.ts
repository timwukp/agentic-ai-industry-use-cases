/** Which language the agent should answer in, decided from the prompt and the
 * UI locale together.
 *
 * The system prompt already says "reply in the user's language", but that alone
 * proved insufficient: a stored memory record written in Chinese was injected on
 * every turn and the model read it as a language signal, so English starter
 * questions came back in Chinese. Sending the language explicitly makes the
 * current message the authority instead of whatever the retrieved context is
 * written in.
 *
 * With sixteen UI languages there are now two signals, ranked:
 *
 *   1. What the user TYPED, when its script is decisive. Someone writing Korean
 *      wants Korean back whatever their picker says — the message is the
 *      fresher signal. Script probes exist only for scripts that identify a
 *      language in this app's set: kana → ja, Hangul → ko, Thai → th,
 *      Devanagari → hi, Han → Chinese (variant from the picker, the one place
 *      script cannot decide). Latin is NOT probed further: telling French from
 *      English from Vietnamese-without-diacritics is language detection, and a
 *      wrong explicit instruction is worse than none.
 *   2. The UI locale the user chose. It decides all Latin prose (including the
 *      English starter prompts — UI in Thai means the canned English question
 *      should get a Thai answer) and the unclear cases (bare ids like
 *      "PT-1002"), except when the locale is the untouched English default,
 *      where '' preserves "let the model decide".
 */
import type { Locale } from '../i18n/index.ts'

/** Han ideographs (no kana) — Chinese, or the Han part of Japanese. */
const HAN = /[㐀-䶿一-鿿豈-﫿]/u
/** Hiragana/Katakana — decisively Japanese. */
const KANA = /[぀-ゟ゠-ヿ]/u
/** Hangul syllables and jamo — decisively Korean. */
const HANGUL = /[가-힯ᄀ-ᇿㄱ-ㆎ]/u
/** Thai block. */
const THAI = /[฀-๿]/u
/** Devanagari — Hindi (this app has no other Devanagari language). */
const DEVANAGARI = /[ऀ-ॿ]/u
/** Latin letters, to measure how much of the message is not CJK. */
const LATIN = /[A-Za-z]/u
/** Lowercase specifically, as evidence the Latin text is prose and not an id. */
const LATIN_LOWER = /[a-z]/u

export type ReplyLanguage = 'zh' | 'ja' | 'ko' | 'th' | 'hi' | 'en' | 'latin'

/** How the model is told to answer, per locale. English phrasing throughout —
 *  instructions in English are the most reliably followed. */
const DIRECTIVES: Record<Locale, string> = {
  en: '(Reply in English.)',
  'zh-TW': '(Reply in Traditional Chinese.)',
  'zh-CN': '(Reply in Simplified Chinese.)',
  ja: '(Reply in Japanese.)',
  ko: '(Reply in Korean.)',
  fr: '(Reply in French.)',
  es: '(Reply in Spanish.)',
  it: '(Reply in Italian.)',
  pt: '(Reply in Portuguese.)',
  de: '(Reply in German.)',
  id: '(Reply in Indonesian.)',
  ms: '(Reply in Malay.)',
  th: '(Reply in Thai.)',
  vi: '(Reply in Vietnamese.)',
  fil: '(Reply in Filipino.)',
  hi: '(Reply in Hindi.)',
}

function count(text: string, probe: RegExp): number {
  return (text.match(new RegExp(probe, 'gu')) ?? []).length
}

/**
 * The language the TYPED text asserts, or 'latin' for decisive Latin prose
 * (which script alone cannot pin to a language), or undefined when the prompt
 * carries no language at all (empty, ids, or a genuine mix).
 *
 * Mixed input is the real trap: technical Chinese is full of English terms
 * ("幫我看 NVDA 的 VaR"), so any-Latin-wins would answer that in English. The
 * test is therefore which script carries the message, with a margin — a handful
 * of Latin identifiers inside a Chinese sentence stays Chinese, and a lone CJK
 * character inside an English sentence stays English.
 */
export function replyLanguage(prompt: string): ReplyLanguage | undefined {
  const text = prompt.trim()
  if (!text) return undefined

  // Any kana at all makes Han text Japanese, not Chinese — Japanese sentences
  // are typically majority kanji by weight, so a count comparison against the
  // Han probe would misread them.
  if (KANA.test(text)) return 'ja'
  if (HANGUL.test(text)) return 'ko'
  if (THAI.test(text)) return 'th'
  if (DEVANAGARI.test(text)) return 'hi'

  const han = count(text, HAN)
  const latin = count(text, LATIN)
  if (han === 0 && latin === 0) return undefined // digits, punctuation only

  // An all-caps, no-CJK message is an identifier, not English: "PT-1002",
  // "NVDA", "SKU-1001". Users paste these as bare follow-ups, and mid-Chinese
  // conversation an explicit directive there would flip the reply language on
  // a message that carries no language at all. Ids and prose are
  // distinguishable because prose has lowercase.
  if (han === 0 && !LATIN_LOWER.test(text)) return undefined

  // A CJK character carries far more of a sentence than a Latin letter does, so
  // comparing raw counts would under-weight Chinese. Roughly: one ideograph is
  // worth about an English word.
  const AVG_LATIN_CHARS_PER_WORD = 4
  const hanWeight = han
  const latinWeight = latin / AVG_LATIN_CHARS_PER_WORD

  if (hanWeight === 0) return 'latin'
  if (latinWeight === 0) return 'zh'
  if (hanWeight >= latinWeight * 1.5) return 'zh'
  if (latinWeight >= hanWeight * 1.5) return 'latin'
  return undefined // genuinely mixed — let the model decide
}

/** The instruction appended to a prompt, or '' when nothing is clear enough to
 *  assert. `uiLocale` is the picker choice — see the ranking at the top. */
export function languageDirective(prompt: string, uiLocale: Locale = 'en'): string {
  const detected = replyLanguage(prompt)

  // Rank 1: a decisive non-Latin script in the typed text wins outright.
  if (detected === 'ja' || detected === 'ko' || detected === 'th' || detected === 'hi') {
    return `\n\n${DIRECTIVES[detected]}`
  }
  if (detected === 'zh') {
    // Script cannot tell Traditional from Simplified; the picker can. A picker
    // set to either variant is the user telling us which Chinese they read.
    const variant: Locale =
      uiLocale === 'zh-CN' || uiLocale === 'zh-TW' ? uiLocale : 'zh-TW'
    return `\n\n${DIRECTIVES[variant]}`
  }

  // Rank 2: decisive Latin prose — script can't name the language, the picker
  // does. This is the starter-prompt path: canned English questions answered in
  // the UI language.
  if (detected === 'latin') {
    return `\n\n${DIRECTIVES[uiLocale]}`
  }

  // Undefined: the text asserts nothing. A non-default picker choice is still
  // an explicit preference; the untouched English default keeps the old
  // "say nothing, let the model decide".
  return uiLocale === 'en' ? '' : `\n\n${DIRECTIVES[uiLocale]}`
}
