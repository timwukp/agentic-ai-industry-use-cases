/** Which language the agent should answer in, decided from the prompt itself.
 *
 * The system prompt already says "reply in the user's language", but that alone
 * proved insufficient: a stored memory record written in Chinese was injected on
 * every turn and the model read it as a language signal, so English starter
 * questions came back in Chinese. Sending the language explicitly makes the
 * current message the authority instead of whatever the retrieved context is
 * written in.
 *
 * Deliberately narrow. This is not language detection — it is a CJK-vs-Latin
 * script test, which is all the ambiguity we actually have. Anything unclear
 * returns undefined and the model falls back to its own judgement, because a
 * wrong explicit instruction is worse than none.
 */

/** CJK ideographs plus the Hiragana/Katakana blocks, as a script probe. */
const CJK = /[぀-ヿ㐀-䶿一-鿿豈-﫿]/u
/** Latin letters, to measure how much of the message is not CJK. */
const LATIN = /[A-Za-z]/u
/** Lowercase specifically, as evidence the Latin text is prose and not an id. */
const LATIN_LOWER = /[a-z]/u

export type ReplyLanguage = 'zh' | 'en'

/**
 * The language to answer in, or undefined when the prompt does not clearly
 * indicate one (empty, digits/ids only, or a genuine mix).
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

  const cjk = (text.match(new RegExp(CJK, 'gu')) ?? []).length
  const latin = (text.match(new RegExp(LATIN, 'gu')) ?? []).length
  if (cjk === 0 && latin === 0) return undefined // digits, punctuation only

  // An all-caps, no-CJK message is an identifier, not English: "PT-1002",
  // "NVDA", "SKU-1001". Users paste these as bare follow-ups, and mid-Chinese
  // conversation an 'en' directive there would flip the reply language on a
  // message that carries no language at all. Ids and prose are distinguishable
  // because prose has lowercase.
  if (cjk === 0 && !LATIN_LOWER.test(text)) return undefined

  // A CJK character carries far more of a sentence than a Latin letter does, so
  // comparing raw counts would under-weight Chinese. Roughly: one ideograph is
  // worth about an English word.
  const AVG_LATIN_CHARS_PER_WORD = 4
  const cjkWeight = cjk
  const latinWeight = latin / AVG_LATIN_CHARS_PER_WORD

  if (cjkWeight === 0) return 'en'
  if (latinWeight === 0) return 'zh'
  if (cjkWeight >= latinWeight * 1.5) return 'zh'
  if (latinWeight >= cjkWeight * 1.5) return 'en'
  return undefined // genuinely mixed — let the model decide
}

/** The instruction appended to a prompt, or '' when the language is unclear. */
export function languageDirective(prompt: string): string {
  const language = replyLanguage(prompt)
  if (!language) return ''
  return language === 'zh'
    ? '\n\n(Reply in Traditional Chinese.)'
    : '\n\n(Reply in English.)'
}
