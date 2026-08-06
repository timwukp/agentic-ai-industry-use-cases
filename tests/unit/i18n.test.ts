/**
 * The message catalogs and the machinery that reads them.
 *
 * `satisfies Messages` already makes a missing key a compile error, so most of
 * what these tests pin is what the TYPE SYSTEM cannot see:
 *
 *   - interpolation params: a translation that drops or mangles `{n}` type-checks
 *     fine and renders "sessions" with no count. Every param token in English
 *     must appear in every translation of that key.
 *   - empty or whitespace values: typed as string, rendered as a hole.
 *   - untranslated catalogs: a locale file written by copying en.ts wholesale
 *     would ship English under a Thai flag. (Spot-checked, not exhaustive —
 *     UI terms like "OEE" or "SKU" legitimately survive translation.)
 *
 * Run: node --test tests/unit/i18n.test.ts
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { interpolate, LOCALES, LOCALE_NAMES } from '../../web/src/i18n/index.ts'
import { en } from '../../web/src/i18n/messages/en.ts'
import { zhTW } from '../../web/src/i18n/messages/zh-TW.ts'
import { zhCN } from '../../web/src/i18n/messages/zh-CN.ts'
import { ja } from '../../web/src/i18n/messages/ja.ts'
import { ko } from '../../web/src/i18n/messages/ko.ts'
import { fr } from '../../web/src/i18n/messages/fr.ts'
import { es } from '../../web/src/i18n/messages/es.ts'
import { it } from '../../web/src/i18n/messages/it.ts'
import { pt } from '../../web/src/i18n/messages/pt.ts'
import { de } from '../../web/src/i18n/messages/de.ts'
import { id } from '../../web/src/i18n/messages/id.ts'
import { ms } from '../../web/src/i18n/messages/ms.ts'
import { th } from '../../web/src/i18n/messages/th.ts'
import { vi } from '../../web/src/i18n/messages/vi.ts'
import { fil } from '../../web/src/i18n/messages/fil.ts'
import { hi } from '../../web/src/i18n/messages/hi.ts'

const CATALOGS: Record<string, unknown> = {
  en,
  'zh-TW': zhTW,
  'zh-CN': zhCN,
  ja,
  ko,
  fr,
  es,
  it,
  pt,
  de,
  id,
  ms,
  th,
  vi,
  fil,
  hi,
}

function flatten(node: unknown, prefix = ''): Map<string, string> {
  const out = new Map<string, string>()
  if (!node || typeof node !== 'object') return out
  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (typeof value === 'string') out.set(path, value)
    else for (const [p, v] of flatten(value, path)) out.set(p, v)
  }
  return out
}

const EN_FLAT = flatten(en)

test('interpolate fills tokens and leaves unknown ones visible', () => {
  assert.equal(interpolate('{n} sessions', { n: 30 }), '30 sessions')
  assert.equal(interpolate('{a} of {b}', { a: 1, b: 2 }), '1 of 2')
  assert.equal(interpolate('no tokens'), 'no tokens')
  // Unknown token stays verbatim: a visible, greppable failure.
  assert.equal(interpolate('{missing} here', { other: 1 }), '{missing} here')
  // Same token twice.
  assert.equal(interpolate('{n} and {n}', { n: 5 }), '5 and 5')
})

test('every locale is registered coherently', () => {
  assert.equal(LOCALES.length, 16)
  for (const locale of LOCALES) {
    assert.ok(CATALOGS[locale], `no catalog imported for ${locale}`)
    assert.ok(LOCALE_NAMES[locale], `no endonym for ${locale}`)
  }
})

test('every catalog has exactly the English key set', () => {
  // Redundant with `satisfies` at compile time — but node --test never runs tsc,
  // and a stray `as never` in a locale file would slip past it silently.
  for (const [locale, catalog] of Object.entries(CATALOGS)) {
    const flat = flatten(catalog)
    for (const key of EN_FLAT.keys()) {
      assert.ok(flat.has(key), `${locale} is missing ${key}`)
    }
    for (const key of flat.keys()) {
      assert.ok(EN_FLAT.has(key), `${locale} has extra key ${key}`)
    }
  }
})

test('no catalog value is empty', () => {
  for (const [locale, catalog] of Object.entries(CATALOGS)) {
    for (const [key, value] of flatten(catalog)) {
      assert.ok(value.trim().length > 0, `${locale}: ${key} is empty`)
    }
  }
})

test('every {param} token in English survives into every translation', () => {
  // The failure this catches shipped in commercial products for decades:
  // a translator "translates" the braces and the app renders "{n} 세션" as
  // literal text — or drops the token and the count disappears.
  const tokensOf = (text: string) =>
    [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()
  for (const [locale, catalog] of Object.entries(CATALOGS)) {
    if (locale === 'en') continue
    const flat = flatten(catalog)
    for (const [key, enValue] of EN_FLAT) {
      const enTokens = tokensOf(enValue)
      if (!enTokens.length) continue
      const translated = flat.get(key)
      assert.ok(translated !== undefined, `${locale} missing ${key}`)
      assert.deepEqual(
        tokensOf(translated!),
        enTokens,
        `${locale}: ${key} params drifted — en has {${enTokens.join('},{')}}, got "${translated}"`,
      )
    }
  }
})

test('catalogs are actually translated, not copies of English', () => {
  // Whole-catalog identity would mean someone shipped en.ts under another name.
  // Threshold is deliberately loose: acronyms (OEE, SKU, VaR), proper nouns and
  // short labels legitimately match English, so we only require that a MAJORITY
  // of a small probe set differs.
  const PROBES = [
    'chrome.dashboard',
    'chrome.signOut',
    'login.signIn',
    'chat.tryAsking',
    'widgets.loading',
    'finance.positions',
    'healthcare.activePatients',
    'insurance.openClaims',
    'retail.inStockRate',
    'manufacturing.remainingUsefulLife',
    'realestate.activeListings',
    'charts.sectorPerformance',
  ]
  for (const [locale, catalog] of Object.entries(CATALOGS)) {
    if (locale === 'en') continue
    const flat = flatten(catalog)
    const same = PROBES.filter((key) => flat.get(key) === EN_FLAT.get(key))
    assert.ok(
      same.length <= PROBES.length / 2,
      `${locale}: ${same.length}/${PROBES.length} probe strings identical to English (${same.join(', ')})`,
    )
  }
})
