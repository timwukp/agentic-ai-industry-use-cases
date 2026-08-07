/**
 * The chart-spec translation scheme: two representations of every display
 * string, pinned to each other.
 *
 * A ChartSpec carries its English strings (title/subtitle/series[].name/
 * refLines[].label — the spec's IDENTITY: dedupe, pagination, data-chart-title)
 * and, in parallel, catalog keys + params (titleL/subtitleL/nameKey/labelKey)
 * that ChartCard translates at render time. Nothing in the type system stops
 * the two from drifting: a recognizer could change its template string and
 * forget the key, or vice versa, and every locale but English would silently
 * show the stale text.
 *
 * So the load-bearing assertion here is RECONSTRUCTION: rendering the localized
 * fields against the ENGLISH catalog must reproduce the legacy English string
 * exactly, for every chart every captured payload produces. Drift in either
 * representation fails this immediately.
 *
 * Run: node --test tests/unit/chartI18n.test.ts
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { chartFor, type ChartSpec, type LocalizedText } from '../../web/src/lib/chartSpec.ts'
import { chartText } from '../../web/src/lib/chartFormat.ts'
import { en } from '../../web/src/i18n/messages/en.ts'
import { zhTW } from '../../web/src/i18n/messages/zh-TW.ts'
import { th } from '../../web/src/i18n/messages/th.ts'
import { hi } from '../../web/src/i18n/messages/hi.ts'

const payloads = JSON.parse(
  readFileSync(new URL('../fixtures/tool_payloads.json', import.meta.url), 'utf8'),
) as Record<string, unknown>

function specs(): Array<{ key: string; spec: ChartSpec }> {
  const out: Array<{ key: string; spec: ChartSpec }> = []
  for (const [key, payload] of Object.entries(payloads)) {
    const spec = chartFor(key.split('__')[0], payload)
    if (spec) out.push({ key, spec })
  }
  return out
}

function keysUsed(l: LocalizedText | undefined): string[] {
  if (!l) return []
  const out: string[] = []
  if (l.key) out.push(l.key)
  for (const part of l.parts ?? []) {
    if (!('raw' in part)) out.push(...keysUsed(part))
  }
  return out
}

test('every chart a captured payload produces carries localized fields', () => {
  const all = specs()
  assert.ok(all.length >= 40, `only ${all.length} specs — fixture shrank?`)
  for (const { key, spec } of all) {
    assert.ok(spec.titleL, `${key} · "${spec.title}": no titleL`)
    if (spec.subtitle) {
      assert.ok(
        spec.subtitleL,
        `${key} · "${spec.title}": subtitle "${spec.subtitle}" has no subtitleL`,
      )
    }
    for (const s of spec.series) {
      assert.ok(s.nameKey, `${key} · "${spec.title}": series "${s.name}" has no nameKey`)
    }
    for (const line of spec.refLines ?? []) {
      if (line.label) {
        assert.ok(
          line.labelKey,
          `${key} · "${spec.title}": refLine "${line.label}" has no labelKey`,
        )
      }
    }
  }
})

test('rendering the keys against the English catalog reproduces the English strings', () => {
  // THE pin. If this holds, the localized path shows in English exactly what
  // the legacy path shows — so what a translator changes is words, never facts.
  for (const { key, spec } of specs()) {
    assert.equal(
      chartText(spec.titleL, spec.title, en.charts),
      spec.title,
      `${key}: title reconstruction drifted`,
    )
    if (spec.subtitle && spec.subtitleL) {
      assert.equal(
        chartText(spec.subtitleL, spec.subtitle, en.charts),
        spec.subtitle,
        `${key}: subtitle reconstruction drifted`,
      )
    }
    for (const s of spec.series) {
      assert.equal(
        chartText({ key: s.nameKey! }, s.name, en.charts),
        s.name,
        `${key}: series name reconstruction drifted for "${s.name}"`,
      )
    }
    for (const line of spec.refLines ?? []) {
      if (!line.label || !line.labelKey) continue
      assert.equal(
        chartText({ key: line.labelKey, params: line.labelParams }, line.label, en.charts),
        line.label,
        `${key}: refLine label reconstruction drifted for "${line.label}"`,
      )
    }
  }
})

test('every key a recognizer emits exists in every probed catalog', () => {
  // en is covered by reconstruction above; probing three non-Latin catalogs
  // (two scripts + the variant pair's second member) catches a key added to
  // en.ts but forgotten elsewhere — which `satisfies` would catch at compile
  // time, except this suite runs without tsc.
  const catalogs = { 'zh-TW': zhTW.charts, th: th.charts, hi: hi.charts }
  for (const { key, spec } of specs()) {
    const used = [
      ...keysUsed(spec.titleL),
      ...keysUsed(spec.subtitleL),
      ...spec.series.map((s) => s.nameKey!),
      ...(spec.refLines ?? []).flatMap((l) => (l.labelKey ? [l.labelKey] : [])),
    ]
    for (const [locale, dict] of Object.entries(catalogs)) {
      for (const k of used) {
        assert.equal(
          typeof (dict as Record<string, string>)[k],
          'string',
          `${locale} is missing charts.${k} (used by ${key})`,
        )
      }
    }
  }
})

test('raw parts pass through untranslated in every locale', () => {
  // Payload values (ids, sensor names, enums) are data, not copy: the patient
  // id must read PT-1001 in Thai exactly as in English.
  const gaps = chartFor('get_care_gap_analysis', payloads.get_care_gap_analysis)!
  const patient = (payloads.get_care_gap_analysis as { patient_id: string }).patient_id
  for (const dict of [en.charts, zhTW.charts, th.charts, hi.charts]) {
    const subtitle = chartText(gaps.subtitleL, gaps.subtitle, dict)!
    assert.ok(
      subtitle.includes(patient),
      `patient id ${patient} lost in translation: "${subtitle}"`,
    )
  }
})

test('the identity fields are locale-independent by construction', () => {
  // chartFor takes no locale anywhere in its signature — this test is the
  // tripwire for anyone who adds one. Two invocations must be deep-equal on
  // the identity fields regardless of any module state.
  for (const [key, payload] of Object.entries(payloads)) {
    const a = chartFor(key.split('__')[0], payload)
    const b = chartFor(key.split('__')[0], payload)
    assert.deepEqual(
      a && { t: a.title, s: a.subtitle },
      b && { t: b.title, s: b.subtitle },
      `${key}: chartFor is not deterministic`,
    )
  }
})
