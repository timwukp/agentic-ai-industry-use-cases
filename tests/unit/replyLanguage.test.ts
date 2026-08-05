/**
 * The front-end half of the reply-language fix.
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
 * Mutation-checked: any-Latin-wins (5 failures), raw counts with no margin (3),
 * dropping the identifier guard (5), always-zh (15), and making the directive a
 * prefix instead of a suffix (3) are all caught. One mutant survives on purpose
 * — deleting the `if (!text)` early return changes nothing, because empty input
 * also has zero characters of both scripts and exits by the next guard. That
 * line is a fast path, not behaviour.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { replyLanguage, languageDirective } from '../../web/src/lib/replyLanguage.ts'

test('English prompts answer in English', () => {
  // The literal starter question that came back in Chinese, which is the bug
  // this module exists to fix.
  assert.equal(
    replyLanguage(
      'Give me a market overview and tell me which sectors are leading and lagging today.',
    ),
    'en',
  )
  assert.equal(replyLanguage('What is the VaR on my portfolio?'), 'en')
  assert.equal(replyLanguage('hi'), 'en')
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

test('an English sentence carrying a stray CJK character stays English', () => {
  assert.equal(
    replyLanguage('Explain the 股 market structure for a US equities desk please'),
    'en',
  )
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

test('a bare identifier is not treated as English', () => {
  // Users paste these as one-word follow-ups. Mid-Chinese conversation, calling
  // "PT-1002" English would flip the reply language on a message that carries no
  // language at all — so an all-caps, no-CJK message defers to the model.
  for (const prompt of ['PT-1002', 'NVDA', 'SKU-1001', 'DR-CHEN', 'AAPL MSFT']) {
    assert.equal(replyLanguage(prompt), undefined, `expected undefined for ${prompt}`)
  }
  // But lowercase prose is prose, however short.
  assert.equal(replyLanguage('why'), 'en')
  assert.equal(replyLanguage('What about NVDA'), 'en')
})

test('the directive is appended only when the language is known', () => {
  assert.equal(languageDirective('What moved today?'), '\n\n(Reply in English.)')
  assert.equal(languageDirective('今天什麼在動？'), '\n\n(Reply in Traditional Chinese.)')
  assert.equal(languageDirective('PT-1002'), '')
  assert.equal(languageDirective('2026-08-04'), '')
  assert.equal(languageDirective(''), '')
})

test('the directive never rewrites the prompt it is appended to', () => {
  // agentClient sends `prompt + languageDirective(prompt)` while ChatPanel shows
  // the user's own words. If the directive were ever anything but a suffix, the
  // bubble and the sent text would diverge.
  const prompt = 'Give me a market overview.'
  const sent = prompt + languageDirective(prompt)
  assert.ok(sent.startsWith(prompt))
  assert.equal(sent.slice(prompt.length), '\n\n(Reply in English.)')
})

test('a long Latin prompt is not flipped to zh by the CJK weighting', () => {
  // The 4-chars-per-word weighting deliberately favours CJK. Guard the boundary:
  // one ideograph must not outvote a full English sentence.
  const english =
    'Please compare the fifty day and two hundred day moving averages for the index 值'
  assert.equal(replyLanguage(english), 'en')
})
