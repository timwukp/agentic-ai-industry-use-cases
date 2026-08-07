/**
 * The front-end half of the reply-language fix, now with sixteen UI locales.
 *
 * Run with the repo's node (>=22.6), which strips types natively — no test
 * runner or transpiler is added to the web app for this:
 *
 *   node --test tests/unit/replyLanguage.test.ts
 *
 * What is actually worth asserting here is the *undefined* cases. Returning a
 * language is cheap to get right; the risk is asserting a wrong one, because the
 * directive overrides the model's own judgement. So the mixed-script and
 * no-script inputs get as much attention as the clear ones.
 *
 * Two signals now feed the directive, and their RANKING is the thing this file
 * pins: the typed text's script when it is decisive, else the UI locale from
 * the picker, else silence (English default only).
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { replyLanguage, languageDirective } from '../../web/src/lib/replyLanguage.ts'

test('English prompts are decisive Latin prose', () => {
  // Script can say "Latin prose", not "English" — French looks the same. The
  // locale decides which language that prose gets answered in (tests below).
  assert.equal(
    replyLanguage(
      'Give me a market overview and tell me which sectors are leading and lagging today.',
    ),
    'latin',
  )
  assert.equal(replyLanguage('What is the VaR on my portfolio?'), 'latin')
  assert.equal(replyLanguage('hi'), 'latin')
})

test('Chinese prompts answer in Chinese', () => {
  assert.equal(replyLanguage('今天大盤怎麼樣？'), 'zh')
  assert.equal(replyLanguage('幫我看一下投資組合的風險'), 'zh')
  assert.equal(replyLanguage('好'), 'zh')
})

test('a Chinese sentence carrying English identifiers stays Chinese', () => {
  // The realistic failure of an any-Latin-wins rule. Technical Chinese is full
  // of tickers and acronyms; if these answered in English the fix would be a
  // regression for the user who reported it.
  assert.equal(replyLanguage('幫我看 NVDA 的 VaR'), 'zh')
  assert.equal(replyLanguage('用 DCF 估一下 AAPL 的內在價值，順便說明假設'), 'zh')
  assert.equal(replyLanguage('PT-1002 的 care gaps 有哪些？'), 'zh')
})

test('an English sentence carrying a stray CJK character stays Latin', () => {
  assert.equal(
    replyLanguage('Explain the 股 market structure for a US equities desk please'),
    'latin',
  )
})

test('non-Latin scripts identify their language outright', () => {
  // Kana beats the Han count: Japanese sentences are often majority kanji, so a
  // weight comparison against the Chinese probe would misread them.
  assert.equal(replyLanguage('今日の市場はどうですか'), 'ja')
  assert.equal(replyLanguage('ポートフォリオを見せて'), 'ja')
  assert.equal(replyLanguage('오늘 시장 어때요?'), 'ko')
  assert.equal(replyLanguage('ตลาดวันนี้เป็นอย่างไรบ้าง'), 'th')
  assert.equal(replyLanguage('आज बाज़ार कैसा है?'), 'hi')
})

test('genuinely mixed input defers to the model', () => {
  // Half and half: neither script clears the 1.5x margin, and guessing here is
  // worse than saying nothing.
  assert.equal(replyLanguage('今天大盤如何 and what about bonds'), undefined)
})

test('scriptless input defers to the model', () => {
  for (const prompt of ['', '   ', '2026-08-04', '?!', '123 456']) {
    assert.equal(replyLanguage(prompt), undefined, `expected undefined for ${JSON.stringify(prompt)}`)
  }
})

test('a bare identifier is not treated as prose', () => {
  // Users paste these as one-word follow-ups. Mid-Chinese conversation, calling
  // "PT-1002" English would flip the reply language on a message that carries no
  // language at all — so an all-caps, no-CJK message defers to the model.
  for (const prompt of ['PT-1002', 'NVDA', 'SKU-1001', 'DR-CHEN', 'AAPL MSFT']) {
    assert.equal(replyLanguage(prompt), undefined, `expected undefined for ${prompt}`)
  }
  // But lowercase prose is prose, however short.
  assert.equal(replyLanguage('why'), 'latin')
  assert.equal(replyLanguage('What about NVDA'), 'latin')
})

test('with the default English UI, behaviour is exactly the old behaviour', () => {
  // Every pre-locale assertion, preserved verbatim: uiLocale='en' must be a
  // pure refactor for the user who never touches the picker.
  assert.equal(languageDirective('What moved today?'), '\n\n(Reply in English.)')
  assert.equal(languageDirective('今天什麼在動？'), '\n\n(Reply in Traditional Chinese.)')
  assert.equal(languageDirective('PT-1002'), '')
  assert.equal(languageDirective('2026-08-04'), '')
  assert.equal(languageDirective(''), '')
})

test('the UI locale decides Latin prose — the starter-prompt path', () => {
  // The canned starter questions are English prose. A user who set the UI to
  // Thai clicked an English button; the answer must still be Thai.
  const starter = 'Which SKUs are out of stock right now?'
  assert.equal(languageDirective(starter, 'th'), '\n\n(Reply in Thai.)')
  assert.equal(languageDirective(starter, 'fr'), '\n\n(Reply in French.)')
  assert.equal(languageDirective(starter, 'zh-CN'), '\n\n(Reply in Simplified Chinese.)')
  assert.equal(languageDirective(starter, 'en'), '\n\n(Reply in English.)')
})

test('a decisive non-Latin script in the typed text beats the picker', () => {
  // Someone writing Korean wants Korean back whatever the UI shows. The typed
  // message is the fresher signal.
  assert.equal(languageDirective('오늘 시장 어때요?', 'fr'), '\n\n(Reply in Korean.)')
  assert.equal(languageDirective('今日の市場はどうですか', 'en'), '\n\n(Reply in Japanese.)')
  assert.equal(languageDirective('ตลาดวันนี้เป็นอย่างไร', 'de'), '\n\n(Reply in Thai.)')
  assert.equal(languageDirective('आज बाज़ार कैसा है?', 'es'), '\n\n(Reply in Hindi.)')
})

test('the picker is the Traditional-vs-Simplified tiebreaker', () => {
  // Han script alone cannot distinguish the variants; the picker is the user
  // saying which Chinese they read. Any non-Chinese picker keeps the zh-TW
  // status quo.
  assert.equal(languageDirective('今天大盤怎麼樣？', 'zh-CN'), '\n\n(Reply in Simplified Chinese.)')
  assert.equal(languageDirective('今天大盤怎麼樣？', 'zh-TW'), '\n\n(Reply in Traditional Chinese.)')
  assert.equal(languageDirective('今天大盤怎麼樣？', 'ja'), '\n\n(Reply in Traditional Chinese.)')
})

test('an explicit picker choice covers the cases the text leaves open', () => {
  // A bare id asserts nothing — but a user who chose Vietnamese has stated a
  // preference, so silence is no longer the honest default. Only the untouched
  // English default keeps "let the model decide".
  assert.equal(languageDirective('PT-1002', 'vi'), '\n\n(Reply in Vietnamese.)')
  assert.equal(languageDirective('', 'hi'), '\n\n(Reply in Hindi.)')
  assert.equal(languageDirective('今天大盤如何 and what about bonds', 'fil'), '\n\n(Reply in Filipino.)')
  assert.equal(languageDirective('PT-1002', 'en'), '')
})

test('the directive never rewrites the prompt it is appended to', () => {
  // agentClient sends `prompt + languageDirective(prompt, locale)` while
  // ChatPanel shows the user's own words. If the directive were ever anything
  // but a suffix, the bubble and the sent text would diverge.
  const prompt = 'Give me a market overview.'
  const sent = prompt + languageDirective(prompt, 'ko')
  assert.ok(sent.startsWith(prompt))
  assert.equal(sent.slice(prompt.length), '\n\n(Reply in Korean.)')
})

test('a long Latin prompt is not flipped to zh by the CJK weighting', () => {
  // The 4-chars-per-word weighting deliberately favours CJK. Guard the boundary:
  // one ideograph must not outvote a full English sentence.
  const english =
    'Please compare the fifty day and two hundred day moving averages for the index 值'
  assert.equal(replyLanguage(english), 'latin')
})
