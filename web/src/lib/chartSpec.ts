/** Turns a tool's JSON payload into a chart the panel can draw.
 *
 * The recognizers are keyed on the bare tool name and hand-written against real
 * captured payloads (`tests/fixtures/tool_payloads.json`), not against guessed
 * shapes. That is deliberate: a generic "find the array of numbers" heuristic
 * would produce a chart for almost anything, including payloads where a chart is
 * meaningless (a single risk score, a list of addresses), and a confidently wrong
 * chart is worse for a demo than no chart. So an unrecognized tool returns null
 * and the panel simply does not appear.
 *
 * Every recognizer re-validates the shape it expects and returns null on a
 * mismatch, because the payload comes off the wire — a tool whose output changes
 * shape must degrade to "no chart", never to a half-drawn axis.
 */

export type ChartKind = 'line' | 'bars'

/** A UI string by catalog key, for render-time translation.
 *
 * The English strings on ChartSpec remain the spec's IDENTITY — chart dedupe,
 * pagination signatures and E2E's data-chart-title all key on them, and
 * chartFor() must stay locale-independent (unit tests import it with no React
 * at all). These parallel fields let the component translate what it DISPLAYS
 * without the identity ever changing under a locale switch.
 *
 * `key` is a dot-path into messages.charts.*; `params` carries payload-derived
 * values (ids, counts, sensor names) verbatim — they are data, not copy.
 * `parts` composes a line from fragments joined with ' · ', the pattern the
 * subtitles already use; `{ raw }` parts (a patient id, a payload enum) pass
 * through untranslated by design.
 */
export interface LocalizedText {
  key?: string
  params?: Record<string, string | number>
  parts?: Array<LocalizedText | { raw: string }>
}

export interface ChartSeries {
  key: string
  name: string
  /** charts.* catalog key for the display name. */
  nameKey?: string
  color: string
}

export interface ChartSpec {
  kind: ChartKind
  /** Card title, e.g. "S&P 500 · sector performance". */
  title: string
  titleL?: LocalizedText
  /** One-line note under the title: units, scope, or the id this describes. */
  subtitle?: string
  subtitleL?: LocalizedText
  /** Row objects; every series key indexes into these. */
  data: Array<Record<string, unknown>>
  /** Category axis key. */
  xKey: string
  series: ChartSeries[]
  /** Dashed target/threshold markers. Never a data series. */
  refLines?: Array<{
    y: number
    label?: string
    labelKey?: string
    labelParams?: Record<string, string | number>
  }>
  /** Suffix appended in tooltips, e.g. "%". */
  unit?: string
  /** Rows are ranked categories rather than a time axis (drives bar direction). */
  ranked?: boolean
}

/** Shorthand for building LocalizedText values inside recognizers. */
export function lt(
  key: string,
  params?: Record<string, string | number>,
): LocalizedText {
  return params ? { key, params } : { key }
}

/* Series palette. Matches the dashboard dataviz rules: status colors
 * (green/amber/red) are reserved for pills and never used as a series color, so
 * these are the two neutral series colors plus the accents already in use. */
const PRIMARY = '#38bdf8' // sky-400
const SECOND = '#fb7185' // rose-400
const THIRD = '#a78bfa' // violet-400

type Row = Record<string, unknown>

function rows(value: unknown): Row[] | null {
  if (!Array.isArray(value) || value.length === 0) return null
  if (!value.every((r) => r && typeof r === 'object')) return null
  return value as Row[]
}

function num(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  // HEDIS measures report "81%" — a string that is a number plus a unit.
  if (typeof value === 'string') {
    const parsed = Number.parseFloat(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return undefined
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function get(payload: unknown, key: string): unknown {
  return payload && typeof payload === 'object'
    ? (payload as Row)[key]
    : undefined
}

/** Keeps only rows where every listed key is numeric, then projects them. */
function project(
  source: Row[],
  xKey: string,
  xFrom: string,
  numericKeys: Array<[out: string, from: string]>,
): Array<Row> | null {
  const out: Row[] = []
  for (const row of source) {
    const x = str(row[xFrom]) ?? num(row[xFrom])
    if (x === undefined) continue
    const projected: Row = { [xKey]: x }
    let complete = true
    for (const [outKey, fromKey] of numericKeys) {
      const value = num(row[fromKey])
      if (value === undefined) {
        complete = false
        break
      }
      projected[outKey] = value
    }
    if (complete) out.push(projected)
  }
  return out.length >= 2 ? out : null
}

/** Turns a `{name: {…}}` object into rows, pulling one number out of each value.
 *
 * Several tools key their breakdown by name rather than returning an array
 * (`by_sector`, `scenarios`, `property_types`), so this is the object-shaped
 * counterpart to `project` and applies the same rule: a value that is not a
 * finite number drops the row, and fewer than two rows means no chart.
 */
function fromMap(
  value: unknown,
  xKey: string,
  yKey: string,
  pick: (entry: unknown) => number | undefined,
): Row[] | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const out: Row[] = []
  for (const [name, entry] of Object.entries(value as Row)) {
    const y = pick(entry)
    if (y === undefined) continue
    out.push({ [xKey]: name.replace(/_/g, ' '), [yKey]: y })
  }
  return out.length >= 2 ? out : null
}

/** The share of the value axis the data still occupies once it has been stretched
 *  to include `lines`, given the values actually plotted.
 *
 * The component sets `ifOverflow="extendDomain"`, because recharts' default is to
 * discard an out-of-domain reference line silently and a threshold that vanishes
 * with no trace is the worse failure. That trade has a cost, though: a line far
 * outside the data pushes the axis out and squashes the series into a corner. This
 * is how a recognizer decides whether a given threshold is worth that cost.
 *
 * A bar axis is anchored at zero (`type="number"` with no explicit domain); a line
 * axis follows the data (`domain={['auto','auto']}`).
 */
function dataShare(kind: ChartKind, values: number[], lines: number[]): number {
  const finite = values.filter((v) => Number.isFinite(v))
  if (!finite.length) return 0
  const lo = kind === 'bars' ? Math.min(0, ...finite) : Math.min(...finite)
  const hi = kind === 'bars' ? Math.max(0, ...finite) : Math.max(...finite)
  const axis = Math.max(hi, ...lines) - Math.min(lo, ...lines)
  return axis === 0 ? 1 : (hi - lo) / axis
}

/** A reference line must leave the data at least this much of its own axis.
 *
 * At 42% — 3.7 mm/s vibration readings under a 7.1 mm/s warning limit — the trend
 * is still legible and the line is what makes the reading mean anything. At 29% (a
 * 224h weekly-capacity line over a 66h busiest week) the bars are stubs against
 * four fifths whitespace, and the subtitle's "24% utilisation" says the same thing
 * in one word. Asserted over every captured payload in
 * tests/unit/chartSpec.test.ts.
 */
const MIN_DATA_SHARE = 1 / 3

/** Whole days from `iso` until now; positive means the date has passed. */
function daysPast(iso: unknown): number | undefined {
  const text = str(iso)
  if (!text) return undefined
  const at = Date.parse(text)
  if (!Number.isFinite(at)) return undefined
  return Math.round((Date.now() - at) / 86_400_000)
}

type Recognizer = (payload: unknown) => ChartSpec | null

/* ------------------------------- finance --------------------------------- */

const sectorPerformance: Recognizer = (payload) => {
  const source = rows(get(payload, 'sectors'))
  if (!source) return null
  const data = project(source, 'sector', 'name', [
    ['daily', 'daily_change_pct'],
    ['ytd', 'ytd_change_pct'],
  ])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Sector performance',
    titleL: lt('sectorPerformance'),
    subtitle: 'Daily change, ranked',
    subtitleL: lt('dailyChangeRanked'),
    // Ranked descending so "leading" and "lagging" read off the ends, which is
    // how the question is normally phrased.
    data: [...data].sort((a, b) => Number(b.daily) - Number(a.daily)),
    xKey: 'sector',
    series: [{ key: 'daily', name: 'Daily %', nameKey: 'seriesDailyPct', color: PRIMARY }],
    unit: '%',
    ranked: true,
    refLines: [{ y: 0 }],
  }
}

const historicalPrices: Recognizer = (payload) => {
  const source = rows(get(payload, 'data'))
  if (!source) return null
  const data = project(source, 'date', 'date', [['close', 'close']])
  if (!data) return null
  const symbol = str(get(payload, 'symbol')) ?? ''
  return {
    kind: 'line',
    title: `${symbol} closing price`.trim(),
    titleL: lt('closingPrice', { symbol }),
    subtitle: `${data.length} sessions`,
    subtitleL: lt('sessions', { n: data.length }),
    data,
    xKey: 'date',
    series: [{ key: 'close', name: 'Close', nameKey: 'seriesClose', color: PRIMARY }],
  }
}

const marketOverview: Recognizer = (payload) => {
  const indices = get(payload, 'indices')
  if (!indices || typeof indices !== 'object') return null
  const data: Row[] = []
  for (const [name, value] of Object.entries(indices as Row)) {
    const change = num(get(value, 'change_pct'))
    if (change !== undefined) data.push({ index: name, change })
  }
  if (data.length < 2) return null
  return {
    kind: 'bars',
    title: 'Index moves today',
    titleL: lt('indexMoves'),
    subtitle: 'Change vs previous close',
    subtitleL: lt('changeVsClose'),
    data,
    xKey: 'index',
    series: [{ key: 'change', name: 'Change %', nameKey: 'seriesChangePct', color: PRIMARY }],
    unit: '%',
    ranked: true,
    refLines: [{ y: 0 }],
  }
}

const portfolioAllocation: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'by_sector'), 'sector', 'weight', (v) =>
    num(v),
  )
  if (!data) return null
  const top = num(get(get(payload, 'concentration'), 'top_position_weight_pct'))
  return {
    kind: 'bars',
    title: 'Allocation by sector',
    titleL: lt('allocationBySector'),
    subtitle: top === undefined ? undefined : `Largest position ${top}% of book`,
    subtitleL: top === undefined ? undefined : lt('largestPosition', { p: top }),
    data: [...data].sort((a, b) => Number(b.weight) - Number(a.weight)),
    xKey: 'sector',
    series: [{ key: 'weight', name: 'Weight %', nameKey: 'seriesWeightPct', color: PRIMARY }],
    unit: '%',
    ranked: true,
  }
}

const portfolioPositions: Recognizer = (payload) => {
  const source = rows(get(payload, 'positions'))
  if (!source) return null
  // Return percent rather than dollar P&L: a 6-figure NVDA gain next to a
  // 3-figure one flattens every other bar to nothing, and the question
  // ("review my portfolio") is about which holdings are working.
  const data = project(source, 'symbol', 'symbol', [
    ['ret', 'unrealized_pnl_pct'],
  ])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Unrealized return by position',
    titleL: lt('unrealizedByPosition'),
    subtitle: (() => {
      const total = num(get(get(payload, 'summary'), 'total_return_pct'))
      return total === undefined ? undefined : `Portfolio ${total}%`
    })(),
    subtitleL: (() => {
      const total = num(get(get(payload, 'summary'), 'total_return_pct'))
      return total === undefined ? undefined : lt('portfolioPct', { p: total })
    })(),
    data: [...data].sort((a, b) => Number(b.ret) - Number(a.ret)),
    xKey: 'symbol',
    series: [{ key: 'ret', name: 'Return %', nameKey: 'seriesReturnPct', color: PRIMARY }],
    unit: '%',
    ranked: true,
    refLines: [{ y: 0 }],
  }
}

const valueAtRisk: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'all_levels'), 'level', 'amount', (v) =>
    num(get(v, 'var_amount')),
  )
  if (!data) return null
  // "var 95" reads as noise on an axis; the confidence level is the label.
  for (const row of data) {
    const level = String(row.level).replace(/\D/g, '')
    if (level) row.level = `${level}%`
  }
  const horizon = num(get(payload, 'time_horizon_days'))
  return {
    kind: 'bars',
    title: 'Value at Risk by confidence level',
    titleL: lt('varByConfidence'),
    subtitle: [
      horizon === undefined ? '' : `${horizon}-day horizon`,
      str(get(payload, 'method'))?.replace(/_/g, ' '),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        ...(horizon === undefined ? [] : [lt('dayHorizon', { n: horizon })]),
        // The method name is a payload enum ("parametric variance covariance"),
        // passed through untranslated like every other payload value.
        { raw: str(get(payload, 'method'))?.replace(/_/g, ' ') ?? '' },
      ],
    },
    data,
    xKey: 'level',
    series: [{ key: 'amount', name: 'VaR', nameKey: 'seriesVar', color: PRIMARY }],
    ranked: true,
  }
}

const stressTest: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'scenarios'), 'scenario', 'drawdown', (v) =>
    num(get(v, 'drawdown_pct')),
  )
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Stress scenario drawdown',
    titleL: lt('stressDrawdown'),
    subtitle: (() => {
      const value = num(get(payload, 'portfolio_value'))
      return value === undefined
        ? undefined
        : `On a $${value.toLocaleString('en-US')} book`
    })(),
    subtitleL: (() => {
      const value = num(get(payload, 'portfolio_value'))
      return value === undefined
        ? undefined
        : lt('onABook', { amount: value.toLocaleString('en-US') })
    })(),
    // Ascending, so the deepest drawdown is the leftmost bar — the answer to
    // "what is my downside" is the worst case, not the alphabetically first.
    data: [...data].sort((a, b) => Number(a.drawdown) - Number(b.drawdown)),
    xKey: 'scenario',
    series: [{ key: 'drawdown', name: 'Drawdown %', nameKey: 'seriesDrawdownPct', color: PRIMARY }],
    unit: '%',
    ranked: true,
    refLines: [{ y: 0 }],
  }
}

/* ------------------------------ healthcare ------------------------------- */

const patientAnalytics: Recognizer = (payload) => {
  const bp = get(get(payload, 'trends'), 'blood_pressure')
  const source = rows(get(bp, 'data'))
  if (!source) return null
  const data = project(source, 'month', 'month', [
    ['systolic', 'systolic'],
    ['diastolic', 'diastolic'],
  ])
  if (!data) return null
  const patient = str(get(payload, 'patient_id')) ?? ''
  return {
    kind: 'line',
    title: 'Blood pressure trend',
    titleL: lt('bloodPressureTrend'),
    subtitle: [patient, str(get(bp, 'current'))].filter(Boolean).join(' · '),
    subtitleL: {
      parts: [{ raw: patient ?? '' }, { raw: str(get(bp, 'current')) ?? '' }],
    },
    data,
    xKey: 'month',
    series: [
      { key: 'systolic', name: 'Systolic', nameKey: 'seriesSystolic', color: SECOND },
      { key: 'diastolic', name: 'Diastolic', nameKey: 'seriesDiastolic', color: PRIMARY },
    ],
    unit: 'mmHg',
    // Clinical targets, which is the one legitimate use of a dashed line here.
    refLines: [
      { y: 130, label: 'target 130', labelKey: 'refTarget', labelParams: { n: 130 } },
      { y: 80, label: '80', labelKey: 'refValue', labelParams: { n: 80 } },
    ],
  }
}

const populationHealth: Recognizer = (payload) => {
  const measures = get(payload, 'quality_measures_hedis')
  if (!measures || typeof measures !== 'object') return null
  const data: Row[] = []
  for (const [key, value] of Object.entries(measures as Row)) {
    const performance = num(get(value, 'performance'))
    const target = num(get(value, 'target'))
    if (performance === undefined || target === undefined) continue
    data.push({
      measure: key.replace(/_/g, ' '),
      performance,
      target,
    })
  }
  if (data.length < 2) return null
  return {
    kind: 'bars',
    title: 'HEDIS quality measures',
    titleL: lt('hedisMeasures'),
    subtitle: 'Performance vs target',
    subtitleL: lt('performanceVsTarget'),
    data,
    xKey: 'measure',
    series: [
      { key: 'performance', name: 'Performance %', nameKey: 'seriesPerformancePct', color: PRIMARY },
      { key: 'target', name: 'Target %', nameKey: 'seriesTargetPct', color: THIRD },
    ],
    unit: '%',
    ranked: true,
  }
}

const careGaps: Recognizer = (payload) => {
  const source = rows(get(payload, 'care_gaps'))
  if (!source) return null
  // Days overdue, not a count by priority: the care manager's question is which
  // gap to close first, and "180 days past due" ranks that where "HIGH" cannot.
  const data: Row[] = []
  for (const row of source) {
    const measure = str(row.measure)
    const overdue = daysPast(row.due_date)
    if (!measure || overdue === undefined) continue
    data.push({ measure, overdue })
  }
  if (data.length < 2) return null
  const high = num(get(payload, 'high_priority_gaps'))
  return {
    kind: 'bars',
    title: 'Care gaps by days past due',
    titleL: lt('careGapsByDays'),
    subtitle: [
      str(get(payload, 'patient_id')),
      high === undefined ? '' : `${high} high priority`,
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'patient_id')) ?? '' },
        ...(high === undefined ? [] : [lt('highPriority', { n: high })]),
      ],
    },
    data: [...data].sort((a, b) => Number(b.overdue) - Number(a.overdue)),
    xKey: 'measure',
    series: [{ key: 'overdue', name: 'Days past due', nameKey: 'seriesDaysPastDue', color: PRIMARY }],
    unit: 'days',
    ranked: true,
    // No line at zero. The intent was "bars left of it are not yet overdue", but a
    // bar axis is already anchored at zero, so the line landed exactly on the axis
    // and its "due" label was clipped to "du" by the plot edge — a two-letter
    // smudge next to the tick labels. It could not have been anything else: every
    // gap the tool reports carries a due date in the past (the rest are prose like
    // "Next flu season (Oct)", which is dropped above), so no bar is ever negative
    // and there is no side of zero to distinguish. If one ever were, the component
    // draws its own unlabelled zero rule whenever values straddle it.
  }
}

const readmissionRisk: Recognizer = (payload) => {
  const factors = get(payload, 'social_determinants')
  const score = num(get(payload, 'risk_score'))
  if (score === undefined || !factors || typeof factors !== 'object') return null
  // A single score is not a chart, so this plots it against the two benchmarks
  // the payload itself carries — which is the comparison the number needs.
  const data: Row[] = [{ who: 'This patient', rate: score }]
  const national = num(get(get(payload, 'benchmark'), 'national_avg_readmission_rate'))
  const penalty = num(get(get(payload, 'benchmark'), 'cms_penalty_threshold'))
  if (national !== undefined) data.push({ who: 'National average', rate: national })
  if (penalty !== undefined) data.push({ who: 'CMS penalty threshold', rate: penalty })
  if (data.length < 2) return null
  return {
    kind: 'bars',
    title: '30-day readmission risk vs benchmarks',
    titleL: lt('readmissionVsBenchmarks'),
    subtitle: [
      str(get(payload, 'patient_id')),
      str(get(payload, 'risk_level')),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'patient_id')) ?? '' },
        { raw: str(get(payload, 'risk_level')) ?? '' },
      ],
    },
    data,
    xKey: 'who',
    series: [{ key: 'rate', name: 'Rate %', nameKey: 'seriesRatePct', color: PRIMARY }],
    unit: '%',
    ranked: true,
  }
}

const providerAvailability: Recognizer = (payload) => {
  const source = rows(get(payload, 'availability'))
  if (!source) return null
  const data = project(source, 'day', 'date', [['slots', 'total_open_slots']])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Open slots by day',
    titleL: lt('openSlotsByDay'),
    subtitle: [
      str(get(get(payload, 'provider'), 'name')),
      (() => {
        const total = num(get(get(payload, 'summary'), 'total_available_slots'))
        return total === undefined ? '' : `${total} slots`
      })(),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(get(payload, 'provider'), 'name')) ?? '' },
        ...(() => {
          const total = num(get(get(payload, 'summary'), 'total_available_slots'))
          return total === undefined ? [] : [lt('slots', { n: total })]
        })(),
      ],
    },
    // Chronological, not ranked: this is a calendar, and reordering it by slot
    // count would make "when is the next opening" unanswerable from the chart.
    data,
    xKey: 'day',
    series: [{ key: 'slots', name: 'Open slots', nameKey: 'seriesOpenSlots', color: PRIMARY }],
  }
}

const labResults: Recognizer = (payload) => {
  const panels = rows(get(payload, 'results'))
  if (!panels) return null
  // Values are plotted as a percentage of the top of their reference range, since
  // WBC (x10^3/uL) and cholesterol (mg/dL) share no scale. 100% is the limit.
  const data: Row[] = []
  for (const panel of panels) {
    for (const test of rows(panel.tests) ?? []) {
      const name = str(test.test)
      const value = num(test.value)
      const range = str(test.ref_range)
      if (!name || value === undefined || !range) continue
      const high = num(range.split('-')[1] ?? range.replace(/^[<>]/, ''))
      if (high === undefined || high === 0) continue
      data.push({ test: name, pctOfLimit: Math.round((value / high) * 100) })
    }
  }
  if (data.length < 2) return null
  const abnormal = num(get(get(payload, 'summary'), 'abnormal_count'))
  return {
    kind: 'bars',
    title: 'Lab results vs upper reference limit',
    titleL: lt('labsVsLimit'),
    subtitle: [
      str(get(payload, 'patient_id')),
      abnormal === undefined ? '' : `${abnormal} abnormal`,
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'patient_id')) ?? '' },
        ...(abnormal === undefined ? [] : [lt('abnormal', { n: abnormal })]),
      ],
    },
    data: [...data].sort((a, b) => Number(b.pctOfLimit) - Number(a.pctOfLimit)),
    xKey: 'test',
    series: [{ key: 'pctOfLimit', name: '% of limit', nameKey: 'seriesPctOfLimit', color: PRIMARY }],
    unit: '%',
    ranked: true,
    refLines: [{ y: 100, label: 'ref limit', labelKey: 'refLimit' }],
  }
}

const medicationList: Recognizer = (payload) => {
  const source = rows(get(payload, 'medications'))
  if (!source) return null
  // adherence_rate arrives as "92%" — num() parses the leading number.
  const data = project(source, 'med', 'name', [['adherence', 'adherence_rate']])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Medication adherence',
    titleL: lt('medicationAdherence'),
    subtitle: str(get(payload, 'patient_id')),
    subtitleL: { parts: [{ raw: str(get(payload, 'patient_id')) ?? '' }] },
    data: [...data].sort((a, b) => Number(a.adherence) - Number(b.adherence)),
    xKey: 'med',
    series: [{ key: 'adherence', name: 'Adherence %', nameKey: 'seriesAdherencePct', color: PRIMARY }],
    unit: '%',
    ranked: true,
    // 80% is the conventional adherence threshold in medication-possession
    // measures, so it marks which fills need intervention.
    refLines: [{ y: 80, label: 'target 80', labelKey: 'refTarget', labelParams: { n: 80 } }],
  }
}

const drugInteractions: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'severity_summary'), 'severity', 'count', (v) =>
    num(v),
  )
  if (!data) return null
  // "No interactions found" is the common case and the good news, and it arrives
  // as a severity_summary of all zeroes with an empty interactions list. Three
  // zero-height bars titled "Interactions by severity" reads as a chart that
  // failed to load, so the empty list is the signal to show nothing and let the
  // reply say "no significant interactions" in words.
  const checked = rows(get(payload, 'interactions'))
  if (!checked) return null
  return {
    kind: 'bars',
    title: 'Interactions by severity',
    titleL: lt('interactionsBySeverity'),
    subtitle: (() => {
      const pairs = num(get(payload, 'pairs_analyzed'))
      return pairs === undefined ? undefined : `${pairs} pairs analyzed`
    })(),
    subtitleL: (() => {
      const pairs = num(get(payload, 'pairs_analyzed'))
      return pairs === undefined ? undefined : lt('pairsAnalyzed', { n: pairs })
    })(),
    data,
    xKey: 'severity',
    series: [{ key: 'count', name: 'Interactions', nameKey: 'seriesInteractions', color: PRIMARY }],
    ranked: true,
  }
}

/* ------------------------------- insurance ------------------------------- */

const fraudDashboard: Recognizer = (payload) => {
  const source = rows(get(payload, 'top_fraud_types'))
  if (!source) return null
  const data = project(source, 'type', 'type', [['count', 'count']])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Top fraud types',
    titleL: lt('topFraudTypes'),
    subtitle: str(get(payload, 'period')),
    subtitleL: { parts: [{ raw: str(get(payload, 'period')) ?? '' }] },
    data,
    xKey: 'type',
    series: [{ key: 'count', name: 'Claims', nameKey: 'seriesClaims', color: PRIMARY }],
    ranked: true,
  }
}

const settlementAnalytics: Recognizer = (payload) => {
  const byType = get(payload, 'by_claim_type')
  if (!byType || typeof byType !== 'object') return null
  const data: Row[] = []
  for (const [type, value] of Object.entries(byType as Row)) {
    const avg = num(get(value, 'avg_amount'))
    if (avg !== undefined) data.push({ type, avg })
  }
  if (data.length < 2) return null
  return {
    kind: 'bars',
    title: 'Average settlement by claim type',
    titleL: lt('avgSettlementByType'),
    subtitle: str(get(payload, 'period')),
    subtitleL: { parts: [{ raw: str(get(payload, 'period')) ?? '' }] },
    data,
    xKey: 'type',
    series: [{ key: 'avg', name: 'Avg settlement', nameKey: 'seriesAvgSettlement', color: PRIMARY }],
    ranked: true,
  }
}

const claimsList: Recognizer = (payload) => {
  const source = rows(get(payload, 'claims'))
  if (!source) return null
  // Claim rows have no time series; the useful chart is the status mix.
  const counts = new Map<string, number>()
  for (const row of source) {
    const status = str(row.status)
    if (!status) continue
    counts.set(status, (counts.get(status) ?? 0) + 1)
  }
  if (counts.size < 2) return null
  return {
    kind: 'bars',
    title: 'Claims by status',
    titleL: lt('claimsByStatus'),
    subtitle: `${source.length} claims in the queue`,
    subtitleL: lt('claimsInQueue', { n: source.length }),
    data: [...counts].map(([status, count]) => ({ status, count })),
    xKey: 'status',
    series: [{ key: 'count', name: 'Claims', nameKey: 'seriesClaims', color: PRIMARY }],
    ranked: true,
  }
}

const coverageCheck: Recognizer = (payload) => {
  const claimed = num(get(payload, 'claimed_amount'))
  const deductible = num(get(payload, 'deductible'))
  const payable = num(get(payload, 'payable_amount'))
  const limit = num(get(payload, 'coverage_limit'))
  if (
    claimed === undefined ||
    deductible === undefined ||
    payable === undefined ||
    limit === undefined
  ) {
    return null
  }
  // The determination is a word; what the policyholder asks is "how much do I
  // get", and that is the claimed → deductible → payable → limit waterfall.
  return {
    kind: 'bars',
    title: 'Coverage determination',
    titleL: lt('coverageDetermination'),
    subtitle: [
      str(get(payload, 'policy_number')),
      str(get(payload, 'coverage_determination')),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'policy_number')) ?? '' },
        { raw: str(get(payload, 'coverage_determination')) ?? '' },
      ],
    },
    data: [
      { part: 'Claimed', amount: claimed },
      { part: 'Deductible', amount: deductible },
      { part: 'Payable', amount: payable },
      { part: 'Coverage limit', amount: limit },
    ],
    xKey: 'part',
    series: [{ key: 'amount', name: 'Amount', nameKey: 'seriesAmount', color: PRIMARY }],
    ranked: true,
  }
}

const fraudRisk: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'analysis_details'), 'signal', 'score', (v) =>
    num(v),
  )
  if (!data) return null
  // The component scores are 0-1; shown as percentages they read against the
  // headline risk score in the prose without a second axis.
  for (const row of data) {
    row.score = Math.round(Number(row.score) * 1000) / 10
    row.signal = String(row.signal).replace(/ score$/, '')
  }
  return {
    kind: 'bars',
    title: 'Fraud signal contributions',
    titleL: lt('fraudSignalContributions'),
    subtitle: [
      str(get(payload, 'claim_id')),
      str(get(payload, 'risk_level')),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'claim_id')) ?? '' },
        { raw: str(get(payload, 'risk_level')) ?? '' },
      ],
    },
    data: [...data].sort((a, b) => Number(b.score) - Number(a.score)),
    xKey: 'signal',
    series: [{ key: 'score', name: 'Score %', nameKey: 'seriesScorePct', color: PRIMARY }],
    unit: '%',
    ranked: true,
  }
}

const settlementCalculation: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'breakdown'), 'component', 'amount', (v) =>
    num(v),
  )
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Settlement damage breakdown',
    titleL: lt('settlementBreakdown'),
    subtitle: (() => {
      const net = num(
        get(get(payload, 'settlement_calculation'), 'net_settlement_amount'),
      )
      return [
        str(get(payload, 'claim_id')),
        net === undefined ? '' : `net $${net.toLocaleString('en-US')}`,
      ]
        .filter(Boolean)
        .join(' · ')
    })(),
    subtitleL: (() => {
      const net = num(
        get(get(payload, 'settlement_calculation'), 'net_settlement_amount'),
      )
      return {
        parts: [
          { raw: str(get(payload, 'claim_id')) ?? '' },
          ...(net === undefined
            ? []
            : [lt('netAmount', { amount: net.toLocaleString('en-US') })]),
        ],
      }
    })(),
    data: [...data].sort((a, b) => Number(b.amount) - Number(a.amount)),
    xKey: 'component',
    series: [{ key: 'amount', name: 'Amount', nameKey: 'seriesAmount', color: PRIMARY }],
    ranked: true,
  }
}

/* --------------------------------- retail -------------------------------- */

const demandTrends: Recognizer = (payload) => {
  const source = rows(get(payload, 'weekly_data'))
  if (!source) return null
  const data = project(source, 'week', 'week', [['units', 'units_sold']])
  if (!data) return null
  return {
    kind: 'line',
    title: 'Weekly units sold',
    titleL: lt('weeklyUnitsSold'),
    subtitle: str(get(payload, 'category')),
    subtitleL: { parts: [{ raw: str(get(payload, 'category')) ?? '' }] },
    data,
    xKey: 'week',
    series: [{ key: 'units', name: 'Units', nameKey: 'seriesUnits', color: PRIMARY }],
  }
}

const demandForecast: Recognizer = (payload) => {
  const source = rows(get(payload, 'forecasts'))
  if (!source) return null
  const data = project(source, 'date', 'date', [
    ['predicted', 'predicted_units'],
    ['low', 'lower_bound'],
    ['high', 'upper_bound'],
  ])
  if (!data) return null
  return {
    kind: 'line',
    title: 'Demand forecast',
    titleL: lt('demandForecast'),
    subtitle: [str(get(payload, 'sku')), str(get(payload, 'product_name'))]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'sku')) ?? '' },
        { raw: str(get(payload, 'product_name')) ?? '' },
      ],
    },
    data,
    xKey: 'date',
    series: [
      { key: 'predicted', name: 'Predicted', nameKey: 'seriesPredicted', color: PRIMARY },
      { key: 'low', name: 'Lower bound', nameKey: 'seriesLowerBound', color: THIRD },
      { key: 'high', name: 'Upper bound', nameKey: 'seriesUpperBound', color: THIRD },
    ],
    unit: 'units',
  }
}

const inventorySummary: Recognizer = (payload) => {
  const source = rows(get(payload, 'summary'))
  if (!source) return null
  const data = project(source, 'category', 'category', [
    ['inStock', 'in_stock_pct'],
  ])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'In-stock rate by category',
    titleL: lt('inStockByCategory'),
    data,
    xKey: 'category',
    series: [{ key: 'inStock', name: 'In stock %', nameKey: 'seriesInStockPct', color: PRIMARY }],
    unit: '%',
    ranked: true,
  }
}

const stockoutReport: Recognizer = (payload) => {
  const source = rows(get(payload, 'items'))
  if (!source) return null
  const data = project(source, 'sku', 'product_name', [
    ['loss', 'estimated_total_loss'],
  ])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Stockout revenue impact',
    titleL: lt('stockoutImpact'),
    subtitle: str(get(payload, 'scope')),
    subtitleL: { parts: [{ raw: str(get(payload, 'scope')) ?? '' }] },
    data: [...data].sort((a, b) => Number(b.loss) - Number(a.loss)),
    xKey: 'sku',
    series: [{ key: 'loss', name: 'Estimated loss', nameKey: 'seriesEstimatedLoss', color: PRIMARY }],
    ranked: true,
  }
}

const pricingAnalysis: Recognizer = (payload) => {
  const source = rows(get(payload, 'competitor_prices'))
  if (!source) return null
  const data = project(source, 'seller', 'name', [['price', 'price']])
  if (!data) return null
  const ours = num(get(payload, 'current_price'))
  const recommended = num(get(payload, 'recommended_price'))
  if (ours !== undefined) data.unshift({ seller: 'Us', price: ours })
  const refLines: ChartSpec['refLines'] = []
  if (recommended !== undefined) {
    refLines.push({
      y: recommended,
      label: `rec $${recommended}`,
      labelKey: 'refRecommended',
      labelParams: { n: recommended },
    })
  }
  return {
    kind: 'bars',
    title: 'Price vs competitors',
    titleL: lt('priceVsCompetitors'),
    subtitle: [
      str(get(payload, 'product_name')),
      str(get(payload, 'market_position'))?.replace(/_/g, ' ').toLowerCase(),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'product_name')) ?? '' },
        {
          raw:
            str(get(payload, 'market_position'))?.replace(/_/g, ' ').toLowerCase() ??
            '',
        },
      ],
    },
    data,
    xKey: 'seller',
    series: [{ key: 'price', name: 'Price', nameKey: 'seriesPrice', color: PRIMARY }],
    ranked: true,
    refLines,
  }
}

const pricingOptimization: Recognizer = (payload) => {
  const current = get(payload, 'current')
  const recommended = get(payload, 'recommended')
  if (!current || !recommended) return null
  // The tradeoff is the answer: margin up, revenue down. Both bars per metric,
  // so the sacrifice is visible rather than buried in the prose.
  const pairs: Array<[string, unknown, unknown]> = [
    ['Price', get(current, 'price'), get(recommended, 'price')],
    [
      'Daily revenue',
      get(current, 'daily_revenue'),
      get(recommended, 'projected_daily_revenue'),
    ],
    [
      'Daily margin',
      get(current, 'daily_margin'),
      get(recommended, 'projected_daily_margin'),
    ],
  ]
  const data: Row[] = []
  for (const [metric, now, next] of pairs) {
    const a = num(now)
    const b = num(next)
    if (a === undefined || b === undefined) continue
    data.push({ metric, now: a, next: b })
  }
  if (data.length < 2) return null
  return {
    kind: 'bars',
    title: 'Pricing tradeoff',
    titleL: lt('pricingTradeoff'),
    subtitle: [
      str(get(payload, 'product_name')),
      str(get(payload, 'objective'))?.replace(/_/g, ' '),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'product_name')) ?? '' },
        { raw: str(get(payload, 'objective'))?.replace(/_/g, ' ') ?? '' },
      ],
    },
    data,
    xKey: 'metric',
    series: [
      { key: 'now', name: 'Current', nameKey: 'seriesCurrent', color: THIRD },
      { key: 'next', name: 'Recommended', nameKey: 'seriesRecommended', color: PRIMARY },
    ],
    ranked: true,
  }
}

const supplierPerformance: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'metrics'), 'metric', 'value', (v) => num(v))
  if (!data) return null
  // Only the 0-100 scorecard metrics: defect_rate_ppm is in the thousands and
  // lead times in single digits, so plotting all of them together would leave
  // every percentage flattened against one PPM bar.
  const scored = data.filter((row) => {
    const value = Number(row.value)
    const name = String(row.metric)
    return value >= 0 && value <= 100 && !/ppm|days/.test(name)
  })
  if (scored.length < 2) return null
  return {
    kind: 'bars',
    title: 'Supplier scorecard',
    titleL: lt('supplierScorecard'),
    subtitle: [
      str(get(payload, 'supplier_name')),
      str(get(payload, 'rating')),
      (() => {
        const overall = num(get(payload, 'overall_score'))
        return overall === undefined ? '' : `overall ${overall}`
      })(),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'supplier_name')) ?? '' },
        { raw: str(get(payload, 'rating')) ?? '' },
        ...(() => {
          const overall = num(get(payload, 'overall_score'))
          return overall === undefined ? [] : [lt('overall', { n: overall })]
        })(),
      ],
    },
    data: [...scored].sort((a, b) => Number(a.value) - Number(b.value)),
    xKey: 'metric',
    series: [{ key: 'value', name: 'Score', nameKey: 'seriesScore', color: PRIMARY }],
    ranked: true,
  }
}

const abcAnalysis: Recognizer = (payload) => {
  const classification = get(payload, 'classification')
  if (!classification || typeof classification !== 'object') return null
  const data: Row[] = []
  for (const [cls, entry] of Object.entries(classification as Row)) {
    const revenue = num(get(entry, 'revenue_pct'))
    const skus = num(get(entry, 'sku_pct'))
    if (revenue === undefined || skus === undefined) continue
    data.push({ cls: `Class ${cls}`, revenue, skus })
  }
  if (data.length < 2) return null
  return {
    kind: 'bars',
    title: 'ABC classification',
    titleL: lt('abcClassification'),
    subtitle: (() => {
      const total = num(get(payload, 'total_skus'))
      return total === undefined
        ? 'Share of revenue vs share of SKUs'
        : `${total.toLocaleString('en-US')} SKUs · revenue vs SKU share`
    })(),
    subtitleL: (() => {
      const total = num(get(payload, 'total_skus'))
      return total === undefined
        ? lt('shareOfRevenue')
        : lt('skusRevenueShare', { n: total.toLocaleString('en-US') })
    })(),
    data,
    xKey: 'cls',
    series: [
      { key: 'revenue', name: 'Revenue %', nameKey: 'seriesRevenuePct', color: PRIMARY },
      { key: 'skus', name: 'SKU %', nameKey: 'seriesSkuPct', color: THIRD },
    ],
    unit: '%',
    ranked: true,
  }
}

const inventoryCheck: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'by_location'), 'location', 'units', (v) =>
    num(v),
  )
  if (!data) return null
  const metrics = get(payload, 'metrics')
  // No reorder-point or safety-stock line here, deliberately. Those figures are
  // network-wide (reorder_point 1498 against a total_on_hand of 2375, which is the
  // sum of these six locations), while every bar is a single location whose largest
  // is 539. Drawn on this axis the line sits above all six bars and says "every
  // location is critically short" when the payload's own needs_reorder is false.
  // Labelling it "network reorder pt" was the first attempt and it is not enough:
  // a caption cannot undo a wrong axis, and the per-location thresholds that would
  // belong on this chart are not in the payload. The reorder status is prose the
  // reply already states.
  return {
    kind: 'bars',
    title: 'On-hand units by location',
    titleL: lt('onHandByLocation'),
    subtitle: [
      str(get(payload, 'product_name')),
      (() => {
        const days = num(get(metrics, 'days_of_supply'))
        return days === undefined ? '' : `${days} days of supply`
      })(),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'product_name')) ?? '' },
        ...(() => {
          const days = num(get(metrics, 'days_of_supply'))
          return days === undefined ? [] : [lt('daysOfSupply', { n: days })]
        })(),
      ],
    },
    data: [...data].sort((a, b) => Number(b.units) - Number(a.units)),
    xKey: 'location',
    series: [{ key: 'units', name: 'Units', nameKey: 'seriesUnits', color: PRIMARY }],
    unit: 'units',
    ranked: true,
  }
}

/* ----------------------------- manufacturing ----------------------------- */

const sensorData: Recognizer = (payload) => {
  const source = rows(get(payload, 'readings'))
  if (!source) return null
  const data = project(source, 'time', 'timestamp', [['value', 'value']])
  if (!data) return null
  // Timestamps are full ISO strings; the axis only has room for the clock part.
  for (const row of data) {
    const time = String(row.time)
    const at = time.indexOf('T')
    if (at !== -1) row.time = time.slice(at + 1, at + 6)
  }
  const thresholds = get(payload, 'thresholds')
  const warning = num(get(thresholds, 'warning'))
  const critical = num(get(thresholds, 'critical'))
  // Unlike the bar charts, here the threshold IS the answer: 3.7 mm/s means
  // nothing on its own, and "3.7 against a 7.1 warning limit" is what the question
  // "is the vibration on CNC-001 a problem" is asking. So the nearest limit is
  // ALWAYS drawn, whatever it costs the axis — a series running low under a high
  // warning line is not a distorted chart, it is the honest picture of a healthy
  // margin, and the margin is the information. (This exception is deliberate and
  // singular: gating the warning line on MIN_DATA_SHARE shipped a vibration chart
  // with no line at all on a quiet day — readings 1.3–3.1 put the share at 0.31 —
  // while the reply discussed ISO zones the reader could not see.)
  //
  // The farther limit is different: it is context, not the answer. Readings of
  // 2.6–4.5 mm/s beside a critical limit of 11.0 leave the series 22% of the axis
  // — a flat smear — to show a line the warning line has already answered. It
  // earns its compression only when the reading is actually climbing towards it.
  const values = data.map((row) => Number(row.value))
  const refLines: ChartSpec['refLines'] = []
  for (const [limit, label, labelKey] of [
    [warning, 'warning', 'refWarning'],
    [critical, 'critical', 'refCritical'],
  ] as const) {
    if (limit === undefined) continue
    const candidate = [...refLines.map((l) => l.y), limit]
    if (refLines.length > 0 && dataShare('line', values, candidate) < MIN_DATA_SHARE) continue
    refLines.push({ y: limit, label, labelKey })
  }
  return {
    kind: 'line',
    title: `${str(get(payload, 'sensor_type')) ?? 'Sensor'} readings`,
    titleL: lt('sensorReadings', {
      sensor: str(get(payload, 'sensor_type')) ?? 'Sensor',
    }),
    subtitle: [
      str(get(payload, 'equipment_id')),
      `${str(get(payload, 'unit')) ?? ''}`,
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'equipment_id')) ?? '' },
        { raw: str(get(payload, 'unit')) ?? '' },
      ],
    },
    data,
    xKey: 'time',
    series: [{ key: 'value', name: 'Reading', nameKey: 'seriesReading', color: PRIMARY }],
    unit: str(get(payload, 'unit')),
    refLines,
  }
}

const equipmentList: Recognizer = (payload) => {
  const source = rows(get(payload, 'equipment'))
  if (!source) return null
  const data = project(source, 'asset', 'equipment_id', [
    ['health', 'health_score'],
  ])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Equipment health scores',
    titleL: lt('equipmentHealth'),
    subtitle: `${data.length} assets, lowest first`,
    subtitleL: lt('assetsLowestFirst', { n: data.length }),
    data: [...data].sort((a, b) => Number(a.health) - Number(b.health)),
    xKey: 'asset',
    series: [{ key: 'health', name: 'Health', nameKey: 'seriesHealth', color: PRIMARY }],
    ranked: true,
  }
}

const reliabilityMetrics: Recognizer = (payload) => {
  const source = rows(get(get(payload, 'failure_history'), 'top_failure_modes'))
  if (!source) return null
  const data = project(source, 'mode', 'mode', [['count', 'count']])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Failure modes (12 months)',
    titleL: lt('failureModes'),
    subtitle: str(get(payload, 'equipment_id')),
    subtitleL: { parts: [{ raw: str(get(payload, 'equipment_id')) ?? '' }] },
    data,
    xKey: 'mode',
    series: [{ key: 'count', name: 'Failures', nameKey: 'seriesFailures', color: PRIMARY }],
    ranked: true,
  }
}

const vibrationSpectrum: Recognizer = (payload) => {
  const source = rows(get(payload, 'frequency_peaks'))
  if (!source) return null
  const data = project(source, 'peak', 'label', [['amp', 'amplitude_mm_s']])
  if (!data) return null
  // Frequency order, not amplitude order: the diagnosis comes from *which*
  // harmonic is high (1X = imbalance, BPFO = outer race), and sorting by
  // amplitude destroys the spectrum's shape that makes that readable.
  const byFreq = new Map<string, number>()
  for (const row of source) {
    const label = str(row.label)
    const hz = num(row.frequency_hz)
    if (label && hz !== undefined) byFreq.set(label, hz)
  }
  data.sort((a, b) => (byFreq.get(String(a.peak)) ?? 0) - (byFreq.get(String(b.peak)) ?? 0))
  const overall = num(get(get(payload, 'overall_vibration'), 'velocity_rms_mm_s'))
  return {
    kind: 'bars',
    title: 'Vibration spectrum peaks',
    titleL: lt('vibrationPeaks'),
    subtitle: [
      str(get(payload, 'equipment_id')),
      overall === undefined ? '' : `overall ${overall} mm/s RMS`,
      str(get(get(payload, 'iso_10816_classification'), 'zone'))
        ? `ISO zone ${str(get(get(payload, 'iso_10816_classification'), 'zone'))}`
        : '',
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'equipment_id')) ?? '' },
        ...(overall === undefined ? [] : [lt('overallMmS', { n: overall })]),
        ...(() => {
          const zone = str(get(get(payload, 'iso_10816_classification'), 'zone'))
          return zone ? [lt('isoZone', { zone })] : []
        })(),
      ],
    },
    data,
    xKey: 'peak',
    series: [{ key: 'amp', name: 'Amplitude', nameKey: 'seriesAmplitude', color: PRIMARY }],
    unit: 'mm/s',
    ranked: true,
  }
}

const failurePrediction: Recognizer = (payload) => {
  const primary = get(payload, 'primary_prediction')
  const first = num(get(primary, 'failure_probability'))
  if (first === undefined) return null
  // Two components with probabilities is the whole chart; the interesting number
  // — remaining useful life — is a single value and belongs in the subtitle.
  const data: Row[] = [
    {
      component: str(get(primary, 'affected_component')) ?? 'Primary',
      probability: Math.round(first * 1000) / 10,
    },
  ]
  const secondary = get(payload, 'secondary_prediction')
  const second = num(get(secondary, 'probability'))
  if (second !== undefined) {
    data.push({
      component: str(get(secondary, 'affected_component')) ?? 'Secondary',
      probability: Math.round(second * 1000) / 10,
    })
  }
  if (data.length < 2) return null
  const rul = num(get(primary, 'remaining_useful_life_days'))
  return {
    kind: 'bars',
    title: 'Failure probability by component',
    titleL: lt('failureProbability'),
    subtitle: [
      str(get(payload, 'equipment_id')),
      rul === undefined ? '' : `${rul} days remaining useful life`,
      str(get(payload, 'risk_level')),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'equipment_id')) ?? '' },
        ...(rul === undefined ? [] : [lt('rulDays', { n: rul })]),
        { raw: str(get(payload, 'risk_level')) ?? '' },
      ],
    },
    data,
    xKey: 'component',
    series: [{ key: 'probability', name: 'Probability %', nameKey: 'seriesProbabilityPct', color: PRIMARY }],
    unit: '%',
    ranked: true,
  }
}

const equipmentAlerts: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'severity_counts'), 'severity', 'count', (v) =>
    num(v),
  )
  if (!data) return null
  for (const row of data) {
    const s = String(row.severity)
    row.severity = s.charAt(0).toUpperCase() + s.slice(1)
  }
  const unack = num(get(payload, 'unacknowledged'))
  return {
    kind: 'bars',
    title: 'Alerts by severity',
    titleL: lt('alertsBySeverity'),
    subtitle: [
      (() => {
        const total = num(get(payload, 'total_alerts'))
        return total === undefined ? '' : `${total} open`
      })(),
      unack === undefined ? '' : `${unack} unacknowledged`,
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        ...(() => {
          const total = num(get(payload, 'total_alerts'))
          return total === undefined ? [] : [lt('openAlerts', { n: total })]
        })(),
        ...(unack === undefined ? [] : [lt('unacknowledged', { n: unack })]),
      ],
    },
    data,
    xKey: 'severity',
    series: [{ key: 'count', name: 'Alerts', nameKey: 'seriesAlerts', color: PRIMARY }],
    ranked: true,
  }
}

const maintenanceCalendar: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'weekly_capacity'), 'week', 'hours', (v) =>
    num(get(v, 'maintenance_hours')),
  )
  if (!data) return null
  const util = get(payload, 'resource_utilization')
  const available = num(get(util, 'technician_hours_available'))
  const period = num(get(payload, 'period_days'))
  const refLines: ChartSpec['refLines'] = []
  // technician_hours_available covers the whole period, so it is divided down to
  // a weekly line — plotted as-is it would sit far above every bar and read as
  // "no week is anywhere near capacity", which is not what it says.
  //
  // Dividing is necessary but not sufficient: 960h over 30 days is 224h/week
  // against a busiest week of 65.9h, so the line is still off the axis. recharts
  // silently DISCARDS a ReferenceLine outside the domain (ifOverflow defaults to
  // "discard"), so the chart shipped with no line at all and nothing said so — the
  // spec carried it and the unit tests asserted the spec. The component now extends
  // the domain instead, which means the line always draws — so it is on the
  // recognizer to withhold one that would leave the five bars as stubs against four
  // fifths whitespace. Past that point, utilization_pct in the subtitle says the
  // same thing in one word, and it is already there.
  if (available !== undefined && period !== undefined && period > 0) {
    const weekly = Math.round((available / period) * 7)
    const share = dataShare('bars', data.map((row) => Number(row.hours)), [weekly])
    if (share >= MIN_DATA_SHARE) {
      refLines.push({
        y: weekly,
        label: `${weekly}h weekly capacity`,
        labelKey: 'refWeeklyCapacity',
        labelParams: { n: weekly },
      })
    }
  }
  return {
    kind: 'bars',
    title: 'Maintenance hours by week',
    titleL: lt('maintenanceByWeek'),
    subtitle: (() => {
      const pct = num(get(util, 'utilization_pct'))
      return [
        (() => {
          const total = num(get(payload, 'total_scheduled'))
          return total === undefined ? '' : `${total} jobs`
        })(),
        pct === undefined ? '' : `${pct}% utilization`,
      ]
        .filter(Boolean)
        .join(' · ')
    })(),
    subtitleL: (() => {
      const pct = num(get(util, 'utilization_pct'))
      const total = num(get(payload, 'total_scheduled'))
      return {
        parts: [
          ...(total === undefined ? [] : [lt('jobs', { n: total })]),
          ...(pct === undefined ? [] : [lt('utilization', { p: pct })]),
        ],
      }
    })(),
    // Chronological: it is a schedule.
    data,
    xKey: 'week',
    series: [{ key: 'hours', name: 'Hours', nameKey: 'seriesHours', color: PRIMARY }],
    unit: 'h',
    refLines,
  }
}

const partsForecast: Recognizer = (payload) => {
  const source = rows(get(payload, 'parts'))
  if (!source) return null
  const data = project(source, 'part', 'part_number', [
    ['needed', 'quantity_needed'],
    ['stock', 'current_stock'],
  ])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Parts needed vs on hand',
    titleL: lt('partsNeededVsOnHand'),
    subtitle: [
      str(get(payload, 'equipment_id')),
      (() => {
        const order = num(get(get(payload, 'procurement_summary'), 'parts_to_order'))
        return order === undefined ? '' : `${order} to order`
      })(),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'equipment_id')) ?? '' },
        ...(() => {
          const order = num(
            get(get(payload, 'procurement_summary'), 'parts_to_order'),
          )
          return order === undefined ? [] : [lt('toOrder', { n: order })]
        })(),
      ],
    },
    data,
    xKey: 'part',
    series: [
      { key: 'needed', name: 'Needed', nameKey: 'seriesNeeded', color: PRIMARY },
      { key: 'stock', name: 'On hand', nameKey: 'seriesOnHand', color: THIRD },
    ],
    ranked: true,
  }
}

/* ------------------------------ real estate ------------------------------ */

const marketTrends: Recognizer = (payload) => {
  const source = rows(get(payload, 'trends'))
  if (!source) return null
  const data = project(source, 'month', 'date', [
    ['price', 'median_sale_price'],
  ])
  if (!data) return null
  return {
    kind: 'line',
    title: 'Median sale price',
    titleL: lt('medianSalePrice'),
    subtitle: [str(get(payload, 'zipcode')), str(get(payload, 'period'))]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'zipcode')) ?? '' },
        { raw: str(get(payload, 'period')) ?? '' },
      ],
    },
    data,
    xKey: 'month',
    series: [{ key: 'price', name: 'Median price', nameKey: 'seriesMedianPrice', color: PRIMARY }],
  }
}

const marketForecast: Recognizer = (payload) => {
  const source = rows(get(payload, 'forecast'))
  if (!source) return null
  const data = project(source, 'month', 'date', [
    ['price', 'forecasted_median_price'],
    ['low', 'confidence_low'],
    ['high', 'confidence_high'],
  ])
  if (!data) return null
  return {
    kind: 'line',
    title: 'Price forecast',
    titleL: lt('priceForecast'),
    subtitle: [
      str(get(payload, 'zipcode')),
      `${data.length} months`,
      str(get(get(payload, 'summary'), 'forecast_confidence')),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'zipcode')) ?? '' },
        lt('months', { n: data.length }),
        { raw: str(get(get(payload, 'summary'), 'forecast_confidence')) ?? '' },
      ],
    },
    data,
    xKey: 'month',
    series: [
      { key: 'price', name: 'Forecast', nameKey: 'seriesForecast', color: PRIMARY },
      { key: 'low', name: 'Low', nameKey: 'seriesLow', color: THIRD },
      { key: 'high', name: 'High', nameKey: 'seriesHigh', color: THIRD },
    ],
  }
}

const comparables: Recognizer = (payload) => {
  const source = rows(get(payload, 'comparables'))
  if (!source) return null
  const data = project(source, 'address', 'address', [
    ['ppsf', 'price_per_sqft'],
  ])
  if (!data) return null
  return {
    kind: 'bars',
    title: 'Comparable price per sqft',
    titleL: lt('compPricePerSqft'),
    subtitle: str(get(payload, 'subject_address')),
    subtitleL: { parts: [{ raw: str(get(payload, 'subject_address')) ?? '' }] },
    data,
    xKey: 'address',
    series: [{ key: 'ppsf', name: '$/sqft', nameKey: 'seriesPpsf', color: PRIMARY }],
    ranked: true,
  }
}

const marketConditions: Recognizer = (payload) => {
  const types = get(payload, 'property_types')
  if (!types || typeof types !== 'object') return null
  const data: Row[] = []
  for (const [type, entry] of Object.entries(types as Row)) {
    const price = num(get(entry, 'median_price'))
    if (price === undefined) continue
    data.push({ type: type.replace(/_/g, ' '), price })
  }
  if (data.length < 2) return null
  const snapshot = get(payload, 'market_snapshot')
  const median = num(get(snapshot, 'median_sale_price'))
  return {
    kind: 'bars',
    title: 'Median price by property type',
    titleL: lt('medianByPropertyType'),
    subtitle: [
      str(get(payload, 'zipcode')),
      str(get(get(payload, 'market_indicators'), 'market_type')),
      (() => {
        const supply = num(get(snapshot, 'months_of_supply'))
        return supply === undefined ? '' : `${supply} months of supply`
      })(),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'zipcode')) ?? '' },
        { raw: str(get(get(payload, 'market_indicators'), 'market_type')) ?? '' },
        ...(() => {
          const supply = num(get(snapshot, 'months_of_supply'))
          return supply === undefined ? [] : [lt('monthsOfSupply', { n: supply })]
        })(),
      ],
    },
    data: [...data].sort((a, b) => Number(b.price) - Number(a.price)),
    xKey: 'type',
    series: [{ key: 'price', name: 'Median price', nameKey: 'seriesMedianPrice', color: PRIMARY }],
    ranked: true,
    // The all-types median, so each type reads as above or below the market.
    refLines:
      median === undefined
        ? undefined
        : [{ y: median, label: 'market median', labelKey: 'refMarketMedian' }],
  }
}

const propertyValuation: Recognizer = (payload) => {
  const source = rows(get(payload, 'comparables'))
  if (!source) return null
  const data = project(source, 'address', 'address', [['price', 'sale_price']])
  if (!data) return null
  const valuation = get(payload, 'valuation')
  const estimate = num(get(valuation, 'estimated_value'))
  return {
    kind: 'bars',
    title: 'Comparable sale prices',
    titleL: lt('compSalePrices'),
    subtitle: [
      str(get(payload, 'address')),
      estimate === undefined ? '' : `estimate $${estimate.toLocaleString('en-US')}`,
      (() => {
        const conf = num(get(valuation, 'confidence_score'))
        return conf === undefined ? '' : `${conf}% confidence`
      })(),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(payload, 'address')) ?? '' },
        ...(estimate === undefined
          ? []
          : [lt('estimateAmount', { amount: estimate.toLocaleString('en-US') })]),
        ...(() => {
          const conf = num(get(valuation, 'confidence_score'))
          return conf === undefined ? [] : [lt('confidencePct', { p: conf })]
        })(),
      ],
    },
    data: [...data].sort((a, b) => Number(b.price) - Number(a.price)),
    xKey: 'address',
    series: [{ key: 'price', name: 'Sale price', nameKey: 'seriesSalePrice', color: PRIMARY }],
    ranked: true,
    refLines:
      estimate === undefined
        ? undefined
        : [{ y: estimate, label: 'estimate', labelKey: 'refEstimate' }],
  }
}

const cmaReport: Recognizer = (payload) => {
  const source = rows(get(payload, 'comparable_sales'))
  if (!source) return null
  // Sale price beside adjusted price: the adjustments are the substance of a
  // CMA, and a chart of the raw sales alone would not show the analyst's work.
  const data = project(source, 'address', 'address', [
    ['sale', 'sale_price'],
    ['adjusted', 'adjusted_price'],
  ])
  if (!data) return null
  const reconciled = num(get(get(payload, 'value_conclusion'), 'reconciled_value'))
  return {
    kind: 'bars',
    title: 'Comparable sales, before and after adjustment',
    titleL: lt('compBeforeAfter'),
    subtitle: [
      str(get(get(payload, 'subject_property'), 'address')),
      reconciled === undefined
        ? ''
        : `reconciled $${reconciled.toLocaleString('en-US')}`,
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        { raw: str(get(get(payload, 'subject_property'), 'address')) ?? '' },
        ...(reconciled === undefined
          ? []
          : [lt('reconciledAmount', { amount: reconciled.toLocaleString('en-US') })]),
      ],
    },
    data: [...data].sort((a, b) => Number(b.adjusted) - Number(a.adjusted)),
    xKey: 'address',
    series: [
      { key: 'sale', name: 'Sale price', nameKey: 'seriesSalePrice', color: THIRD },
      { key: 'adjusted', name: 'Adjusted', nameKey: 'seriesAdjusted', color: PRIMARY },
    ],
    ranked: true,
    refLines:
      reconciled === undefined
        ? undefined
        : [{ y: reconciled, label: 'reconciled', labelKey: 'refReconciled' }],
  }
}

const propertySearch: Recognizer = (payload) => {
  const source = rows(get(payload, 'listings'))
  if (!source) return null
  const data = project(source, 'address', 'address', [['price', 'list_price']])
  if (!data) return null
  // Truncate to the street part; a full "2973 Spruce Blvd, 78701" on ten bars
  // pushes the label column wide enough to squeeze the plot out.
  for (const row of data) {
    row.address = String(row.address).split(',')[0]
  }
  const median = num(get(payload, 'market_median_price'))
  return {
    kind: 'bars',
    title: 'Listing prices',
    titleL: lt('listingPrices'),
    subtitle: [
      (() => {
        const total = num(get(payload, 'total_results'))
        return total === undefined
          ? `${data.length} listings`
          : `${data.length} of ${total} matches`
      })(),
      str(get(payload, 'zipcode')),
    ]
      .filter(Boolean)
      .join(' · '),
    subtitleL: {
      parts: [
        (() => {
          const total = num(get(payload, 'total_results'))
          return total === undefined
            ? lt('listings', { n: data.length })
            : lt('ofMatches', { n: data.length, total })
        })(),
        { raw: str(get(payload, 'zipcode')) ?? '' },
      ],
    },
    data: [...data].sort((a, b) => Number(a.price) - Number(b.price)),
    xKey: 'address',
    series: [{ key: 'price', name: 'List price', nameKey: 'seriesListPrice', color: PRIMARY }],
    ranked: true,
    // The question is which listings sit below the market median, so the median
    // has to be on the chart for the answer to be visible rather than asserted.
    refLines:
      median === undefined
        ? undefined
        : [{ y: median, label: 'market median', labelKey: 'refMarketMedian' }],
  }
}

const neighborhoodAnalysis: Recognizer = (payload) => {
  const data = fromMap(get(payload, 'scores'), 'score', 'value', (v) => num(v))
  if (!data) return null
  for (const row of data) {
    row.score = String(row.score).replace(/ score$/, '')
  }
  return {
    kind: 'bars',
    title: 'Neighborhood scores',
    titleL: lt('neighborhoodScores'),
    subtitle: str(get(payload, 'address')),
    subtitleL: { parts: [{ raw: str(get(payload, 'address')) ?? '' }] },
    data: [...data].sort((a, b) => Number(b.value) - Number(a.value)),
    xKey: 'score',
    series: [{ key: 'value', name: 'Score', nameKey: 'seriesScore', color: PRIMARY }],
    ranked: true,
    // All five are 0-100 indices, so the midpoint says which are above average.
    refLines: [{ y: 50, label: '50', labelKey: 'refValue', labelParams: { n: 50 } }],
  }
}

/** Bare tool name → recognizer. Gateway target prefixes are stripped first, so
 *  one entry covers a tool however its gateway target happens to be named. */
const RECOGNIZERS: Record<string, Recognizer> = {
  // finance
  get_sector_performance: sectorPerformance,
  get_historical_prices: historicalPrices,
  get_market_overview: marketOverview,
  get_portfolio_allocation: portfolioAllocation,
  get_portfolio_positions: portfolioPositions,
  calculate_var: valueAtRisk,
  stress_test_portfolio: stressTest,
  // healthcare
  get_patient_analytics: patientAnalytics,
  get_population_health_metrics: populationHealth,
  get_care_gap_analysis: careGaps,
  get_readmission_risk: readmissionRisk,
  get_provider_availability: providerAvailability,
  get_lab_results: labResults,
  get_medication_list: medicationList,
  check_drug_interactions: drugInteractions,
  // insurance
  get_fraud_dashboard: fraudDashboard,
  get_settlement_analytics: settlementAnalytics,
  list_claims: claimsList,
  check_coverage: coverageCheck,
  analyze_fraud_risk: fraudRisk,
  calculate_settlement: settlementCalculation,
  // retail
  get_demand_trends: demandTrends,
  forecast_demand: demandForecast,
  get_inventory_summary: inventorySummary,
  get_stockout_report: stockoutReport,
  get_pricing_analysis: pricingAnalysis,
  optimize_pricing: pricingOptimization,
  get_supplier_performance: supplierPerformance,
  get_abc_analysis: abcAnalysis,
  check_inventory: inventoryCheck,
  // manufacturing
  get_sensor_data: sensorData,
  get_equipment_list: equipmentList,
  get_reliability_metrics: reliabilityMetrics,
  analyze_vibration: vibrationSpectrum,
  predict_failure: failurePrediction,
  get_equipment_alerts: equipmentAlerts,
  get_maintenance_calendar: maintenanceCalendar,
  get_parts_forecast: partsForecast,
  // real estate
  get_market_trends: marketTrends,
  get_market_forecast: marketForecast,
  get_comparables: comparables,
  get_market_conditions: marketConditions,
  estimate_property_value: propertyValuation,
  generate_cma_report: cmaReport,
  search_properties: propertySearch,
  get_neighborhood_analysis: neighborhoodAnalysis,
}

/** Tool names this module can chart — used by the coverage test. */
export const CHARTABLE_TOOLS = Object.keys(RECOGNIZERS)

/** A chart for this tool's payload, or null when there is nothing worth drawing. */
export function chartFor(tool: string, payload: unknown): ChartSpec | null {
  // An errored tool result is still valid JSON, and its keys would fail every
  // shape check anyway — but checking explicitly documents the case.
  if (payload && typeof payload === 'object' && 'error' in (payload as Row)) {
    return null
  }
  const recognizer = RECOGNIZERS[tool]
  if (!recognizer) return null
  try {
    return recognizer(payload)
  } catch {
    // A recognizer must never take the chat panel down with it.
    return null
  }
}
