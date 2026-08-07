/** Axis formatters, layout metrics and the render-time translator for the
 * answer charts.
 *
 * Split out of AnswerChartPanel.tsx purely so it can be unit-tested: the node
 * test runner strips TypeScript types but does not compile JSX, so nothing in a
 * .tsx file is reachable from `node --test`.
 *
 * That split is not cosmetic. The bug it exists to pin was a formatter whose
 * signature disagreed with how recharts calls it, and it shipped to a live
 * screenshot looking plausible — see shortLabel below.
 */
import { interpolate, type Messages } from '../i18n/index.ts'
import type { LocalizedText } from './chartSpec'

/**
 * Resolves a chart's LocalizedText against the charts.* catalog subtree.
 *
 * The fallback is the spec's English string: chartFor() stays pure and
 * locale-independent (dedupe, pagination and data-chart-title key on English),
 * and this function is the ONLY place the localized fields are read. A missing
 * key falls back to English rather than showing a raw dot-path; the unit suite
 * (chartI18n.test.ts) makes such a miss a test failure, so this path is a
 * safety net, not a workflow.
 */
export function chartText(
  l: LocalizedText | undefined,
  fallback: string | undefined,
  dict: Messages['charts'],
): string | undefined {
  if (!l) return fallback
  if (l.parts) {
    const rendered = l.parts
      .map((part) =>
        'raw' in part ? part.raw : chartText(part, undefined, dict) ?? '',
      )
      .filter(Boolean)
    return rendered.length ? rendered.join(' · ') : fallback
  }
  if (!l.key) return fallback
  const template = (dict as Record<string, string>)[l.key]
  if (typeof template !== 'string') return fallback
  return interpolate(template, l.params)
}

/** Compact numeric tick labels — the panel is narrow and full numbers collide. */
export function tickFormat(value: number): string {
  const abs = Math.abs(value)
  if (abs >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`
  if (abs >= 10_000) return `${Math.round(value / 1000)}k`
  return String(Math.round(value * 100) / 100)
}

/** Longest category label rendered before truncation. */
export const LABEL_MAX = 16

/**
 * Truncates a long category label rather than letting it eat the plot area.
 *
 * Takes exactly ONE parameter, on purpose. It was first written as
 * `shortLabel(value, max = 18)` and passed straight to recharts as
 * `tickFormatter={shortLabel}` — but recharts calls a tick formatter with
 * `(value, index)`, so the tick *index* landed in `max` and the default was
 * never used once. Each label came out truncated to its own axis position: tick
 * 1 rendered as "…", tick 2 as "R…", tick 4 as "Hea…". Nothing threw, the chart
 * drew, and it took a screenshot to notice.
 *
 * So: never give a callback handed to a charting library an optional trailing
 * parameter. The library will fill it.
 */
export function shortLabel(value: unknown): string {
  const text = String(value ?? '')
  return text.length > LABEL_MAX ? `${text.slice(0, LABEL_MAX - 1)}…` : text
}

/** Per-category row height for ranked bars. */
export const ROW_HEIGHT = 22
/** Plot height of a line chart. */
export const LINE_HEIGHT = 200
/**
 * Width of the category label gutter.
 *
 * A judgement value, not a measurement: LABEL_MAX characters of 10px sans is
 * roughly 16 × 6px ≈ 96px, plus the tick gap, so the previous 104px was about
 * exact-fit and this leaves margin. It is NOT what caused the truncated labels
 * in the first screenshot — that was `shortLabel`'s signature (see below), and
 * blaming the gutter for it would have been the wrong fix.
 */
export const LABEL_WIDTH = 132

/** Plot area height for a spec, excluding the title and legend chrome. */
export function plotHeight(kind: 'line' | 'bars', rows: number): number {
  return kind === 'line' ? LINE_HEIGHT : Math.max(160, rows * ROW_HEIGHT + 24)
}

/**
 * Total pixel height a chart card occupies, so a container can be sized to show
 * one whole chart. The overlay's max-height was set from this: at the previous
 * 45% cap an 11-row ranking was clipped mid-bar on a 720px window.
 */
export function chartHeight(
  kind: 'line' | 'bars',
  rows: number,
  hasSubtitle: boolean,
  seriesCount: number,
): number {
  return (
    plotHeight(kind, rows) +
    44 + // title block
    (hasSubtitle ? 14 : 0) +
    (seriesCount > 1 ? 22 : 0) // legend row
  )
}
