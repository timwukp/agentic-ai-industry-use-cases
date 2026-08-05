/**
 * Axis formatters and layout metrics for the answer charts.
 *
 *   node --test tests/unit/chartFormat.test.ts
 *
 * These exist because of one bug that no other test in this repo could have
 * caught. `shortLabel` was written as `(value, max = 18)` and handed to recharts
 * as `tickFormatter={shortLabel}`. recharts calls a tick formatter with
 * `(value, index)`, so the tick index arrived as `max`: tick 1 truncated to 1
 * character ("…"), tick 2 to 2 ("R…"), tick 4 to 4 ("Hea…"). Nothing threw, the
 * chart drew, the unit suite stayed green, and it took a live screenshot to see
 * that a chart of eleven sectors had labelled none of them.
 *
 * The arity assertions below are therefore the point of the file, not padding:
 * the defect was entirely in the *signature*, and a test that only checked
 * `shortLabel('Consumer Discretionary')` would have passed against the broken
 * version too.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  LABEL_MAX,
  LABEL_WIDTH,
  LINE_HEIGHT,
  ROW_HEIGHT,
  chartHeight,
  plotHeight,
  shortLabel,
  tickFormat,
} from '../../web/src/lib/chartFormat.ts'

test('a tick formatter ignores the index recharts passes as a second argument', () => {
  const label = 'Consumer Discretionary'
  // This is the regression. recharts supplies the tick index; the formatter's
  // output must depend only on the value.
  const asFormatter = shortLabel as (...args: unknown[]) => string
  for (let index = 0; index < 11; index++) {
    assert.equal(
      asFormatter(label, index),
      shortLabel(label),
      `label changed with tick index ${index} — a trailing parameter is being filled`,
    )
  }
  // Declared arity is the mechanism, so pin it directly: adding an optional
  // second parameter is the mistake, and it is invisible in the output above
  // once the values happen to agree.
  assert.equal(shortLabel.length, 1, 'shortLabel must take exactly one parameter')
  assert.equal(tickFormat.length, 1, 'tickFormat must take exactly one parameter')
})

test('a truncated label still identifies its category', () => {
  // The truncation must leave enough to match against the answer text; "…" and
  // "R…" were what shipped, and neither names anything.
  const long = shortLabel('Consumer Discretionary')
  assert.ok(long.endsWith('…'), 'over-long labels should be marked as truncated')
  assert.equal(long.length, LABEL_MAX)
  assert.ok(
    long.startsWith('Consumer'),
    `truncation must keep the leading word, got ${JSON.stringify(long)}`,
  )
})

test('a label that fits is left exactly alone', () => {
  for (const name of ['Energy', 'Technology', 'Real Estate', 'Utilities']) {
    assert.equal(shortLabel(name), name)
  }
})

test('the label gutter is wide enough for a full-length label', () => {
  // Approximate: ~6px per character at 10px sans, plus the ~8px tick gap. This
  // is a sanity bound on the relationship between the two constants — if
  // LABEL_MAX is raised without widening the gutter, the axis clips.
  //
  // Deliberately weak, and worth being honest about: the previous 104px passes
  // this bound too, because 104 was near exact-fit rather than wrong. The
  // truncated labels in the live screenshot came from shortLabel's signature,
  // not from this width; only a rendered browser measurement could pin a
  // pixel width, and the E2E label assertions are where that lives.
  const APPROX_CHAR_PX = 6
  const TICK_GAP_PX = 8
  assert.ok(
    LABEL_WIDTH >= LABEL_MAX * APPROX_CHAR_PX + TICK_GAP_PX,
    `gutter ${LABEL_WIDTH}px cannot fit ${LABEL_MAX} characters`,
  )
})

test('missing and non-string label values do not throw', () => {
  // Axis values come from tool payloads, so a null category is possible.
  assert.equal(shortLabel(undefined), '')
  assert.equal(shortLabel(null), '')
  assert.equal(shortLabel(42), '42')
})

test('numeric ticks are abbreviated by magnitude', () => {
  assert.equal(tickFormat(1_250_000), '1.3M')
  assert.equal(tickFormat(45_300), '45k')
  assert.equal(tickFormat(3.14159), '3.14')
  assert.equal(tickFormat(0), '0')
  // Negative values are the common case for a diverging bar chart.
  assert.equal(tickFormat(-1.68), '-1.68')
  assert.equal(tickFormat(-2_400_000), '-2.4M')
})

test('a value just under the abbreviation threshold keeps its digits', () => {
  // 9_999 → "9999" not "10k": rounding into a unit the reader did not ask for is
  // how an axis stops matching the numbers in the prose beside it.
  assert.equal(tickFormat(9_999), '9999')
  assert.equal(tickFormat(10_000), '10k')
})

test('an 11-row ranking fits the height the overlay reserves for it', () => {
  // The concrete failure: the sector chart has 11 rows, and the overlay capped
  // itself at 45% of the viewport, clipping the last bars. The cap is now 55%,
  // so assert the chart fits that on the shortest desktop window we support.
  const rows = 11
  const needed = chartHeight('bars', rows, true, 1)
  const SHORTEST_DESKTOP_VIEWPORT = 720
  const cap = SHORTEST_DESKTOP_VIEWPORT * 0.55
  assert.ok(
    needed <= cap,
    `an ${rows}-row chart needs ${needed}px but the overlay allows ${cap}px`,
  )
  // And it must actually scale with the data — a constant would satisfy the
  // bound above while clipping every chart bigger than the one tested.
  //
  // Bounded against literals, not against ROW_HEIGHT: asserting
  // `delta === ROW_HEIGHT` is vacuous, because mutating ROW_HEIGHT to 0 moves
  // both sides together and the assertion becomes 0 === 0. (Verified — that
  // mutant survived until this was rewritten.) A bar row has to be tall enough
  // for a 12px bar plus its gap and no taller than a comfortable touch target.
  const delta = plotHeight('bars', rows + 1) - plotHeight('bars', rows)
  assert.ok(
    delta >= 16 && delta <= 44,
    `each row adds ${delta}px — outside the legible 16–44px band`,
  )
  assert.equal(delta, ROW_HEIGHT, 'row growth should be exactly ROW_HEIGHT')
})

test('a line chart has a fixed plot height regardless of point count', () => {
  // Time series are dense (90 daily points); scaling height by point count would
  // produce a chart taller than the screen.
  assert.equal(plotHeight('line', 5), LINE_HEIGHT)
  assert.equal(plotHeight('line', 365), LINE_HEIGHT)
})

test('chart height accounts for the chrome around the plot', () => {
  const bare = chartHeight('line', 10, false, 1)
  const withSubtitle = chartHeight('line', 10, true, 1)
  const withLegend = chartHeight('line', 10, false, 2)
  // A subtitle and a legend each occupy real vertical space; ignoring them is how
  // a container sized from this function clips the bottom of the plot.
  assert.ok(withSubtitle > bare, 'a subtitle must add height')
  assert.ok(withLegend > bare, 'a legend row must add height')
  assert.ok(bare > plotHeight('line', 10), 'the title block must add height')
})

/*
 * Mutation results (each applied to web/src/lib/chartFormat.ts, run, reverted):
 *
 *  1. `shortLabel(value)` → `shortLabel(value, max = LABEL_MAX)` with `max` used
 *     in the slice — i.e. the exact bug that shipped        → caught
 *  2. LABEL_WIDTH 132 → 104                                 → SURVIVES
 *  3. ROW_HEIGHT 22 → 0                                     → caught
 *  3b. ROW_HEIGHT 22 → 60                                   → caught
 *  4. plotHeight bars branch returns a constant 160          → caught
 *  5. plotHeight line branch scales with `rows`              → caught
 *  6. tickFormat `>= 10_000` → `>= 1_000`                    → caught
 *  7. chartHeight drops the `hasSubtitle` term               → caught
 *  8. shortLabel returns `text.slice(0, LABEL_MAX)` with no
 *     ellipsis                                               → caught
 *
 * Mutation 1 is the one that matters: it reproduces what shipped, and it fails on
 * the tick-index loop — the check no existing test had.
 *
 * Two corrections came out of running these rather than assuming them, and both
 * are worth keeping in view:
 *
 *   - #2 SURVIVES, and the survivor is honest. I had written that 104px "cut
 *     labels to three characters"; that was wrong. The truncation in the live
 *     screenshot was mutation #1's doing, and I attributed it to the gutter
 *     width. 104px was near exact-fit, so no unit assertion can distinguish it
 *     from 132px — a real pixel bound needs a rendered browser, which is where
 *     the E2E label assertions do the work. The remaining test is a
 *     constants-consistency check, not a layout proof.
 *   - #3 initially SURVIVED because the assertion was vacuous: it compared the
 *     per-row delta to ROW_HEIGHT itself, so setting ROW_HEIGHT to 0 made it
 *     `0 === 0`. A constant can never validate itself; it needs an independent
 *     bound, which is why the legible-band check was added alongside it.
 */
