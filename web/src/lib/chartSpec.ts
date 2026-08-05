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

export interface ChartSeries {
  key: string
  name: string
  color: string
}

export interface ChartSpec {
  kind: ChartKind
  /** Card title, e.g. "S&P 500 · sector performance". */
  title: string
  /** One-line note under the title: units, scope, or the id this describes. */
  subtitle?: string
  /** Row objects; every series key indexes into these. */
  data: Array<Record<string, unknown>>
  /** Category axis key. */
  xKey: string
  series: ChartSeries[]
  /** Dashed target/threshold markers. Never a data series. */
  refLines?: Array<{ y: number; label?: string }>
  /** Suffix appended in tooltips, e.g. "%". */
  unit?: string
  /** Rows are ranked categories rather than a time axis (drives bar direction). */
  ranked?: boolean
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
    subtitle: 'Daily change, ranked',
    // Ranked descending so "leading" and "lagging" read off the ends, which is
    // how the question is normally phrased.
    data: [...data].sort((a, b) => Number(b.daily) - Number(a.daily)),
    xKey: 'sector',
    series: [{ key: 'daily', name: 'Daily %', color: PRIMARY }],
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
    subtitle: `${data.length} sessions`,
    data,
    xKey: 'date',
    series: [{ key: 'close', name: 'Close', color: PRIMARY }],
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
    subtitle: 'Change vs previous close',
    data,
    xKey: 'index',
    series: [{ key: 'change', name: 'Change %', color: PRIMARY }],
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
    subtitle: [patient, str(get(bp, 'current'))].filter(Boolean).join(' · '),
    data,
    xKey: 'month',
    series: [
      { key: 'systolic', name: 'Systolic', color: SECOND },
      { key: 'diastolic', name: 'Diastolic', color: PRIMARY },
    ],
    unit: 'mmHg',
    // Clinical targets, which is the one legitimate use of a dashed line here.
    refLines: [
      { y: 130, label: 'target 130' },
      { y: 80, label: '80' },
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
    subtitle: 'Performance vs target',
    data,
    xKey: 'measure',
    series: [
      { key: 'performance', name: 'Performance %', color: PRIMARY },
      { key: 'target', name: 'Target %', color: THIRD },
    ],
    unit: '%',
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
    subtitle: str(get(payload, 'period')),
    data,
    xKey: 'type',
    series: [{ key: 'count', name: 'Claims', color: PRIMARY }],
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
    subtitle: str(get(payload, 'period')),
    data,
    xKey: 'type',
    series: [{ key: 'avg', name: 'Avg settlement', color: PRIMARY }],
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
    subtitle: `${source.length} claims in the queue`,
    data: [...counts].map(([status, count]) => ({ status, count })),
    xKey: 'status',
    series: [{ key: 'count', name: 'Claims', color: PRIMARY }],
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
    subtitle: str(get(payload, 'category')),
    data,
    xKey: 'week',
    series: [{ key: 'units', name: 'Units', color: PRIMARY }],
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
    subtitle: [str(get(payload, 'sku')), str(get(payload, 'product_name'))]
      .filter(Boolean)
      .join(' · '),
    data,
    xKey: 'date',
    series: [
      { key: 'predicted', name: 'Predicted', color: PRIMARY },
      { key: 'low', name: 'Lower bound', color: THIRD },
      { key: 'high', name: 'Upper bound', color: THIRD },
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
    data,
    xKey: 'category',
    series: [{ key: 'inStock', name: 'In stock %', color: PRIMARY }],
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
    subtitle: str(get(payload, 'scope')),
    data: [...data].sort((a, b) => Number(b.loss) - Number(a.loss)),
    xKey: 'sku',
    series: [{ key: 'loss', name: 'Estimated loss', color: PRIMARY }],
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
  const refLines: ChartSpec['refLines'] = []
  if (warning !== undefined) refLines.push({ y: warning, label: 'warning' })
  if (critical !== undefined) refLines.push({ y: critical, label: 'critical' })
  return {
    kind: 'line',
    title: `${str(get(payload, 'sensor_type')) ?? 'Sensor'} readings`,
    subtitle: [
      str(get(payload, 'equipment_id')),
      `${str(get(payload, 'unit')) ?? ''}`,
    ]
      .filter(Boolean)
      .join(' · '),
    data,
    xKey: 'time',
    series: [{ key: 'value', name: 'Reading', color: PRIMARY }],
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
    subtitle: `${data.length} assets, lowest first`,
    data: [...data].sort((a, b) => Number(a.health) - Number(b.health)),
    xKey: 'asset',
    series: [{ key: 'health', name: 'Health', color: PRIMARY }],
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
    subtitle: str(get(payload, 'equipment_id')),
    data,
    xKey: 'mode',
    series: [{ key: 'count', name: 'Failures', color: PRIMARY }],
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
    subtitle: [str(get(payload, 'zipcode')), str(get(payload, 'period'))]
      .filter(Boolean)
      .join(' · '),
    data,
    xKey: 'month',
    series: [{ key: 'price', name: 'Median price', color: PRIMARY }],
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
    subtitle: [
      str(get(payload, 'zipcode')),
      `${data.length} months`,
      str(get(get(payload, 'summary'), 'forecast_confidence')),
    ]
      .filter(Boolean)
      .join(' · '),
    data,
    xKey: 'month',
    series: [
      { key: 'price', name: 'Forecast', color: PRIMARY },
      { key: 'low', name: 'Low', color: THIRD },
      { key: 'high', name: 'High', color: THIRD },
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
    subtitle: str(get(payload, 'subject_address')),
    data,
    xKey: 'address',
    series: [{ key: 'ppsf', name: '$/sqft', color: PRIMARY }],
    ranked: true,
  }
}

/** Bare tool name → recognizer. Gateway target prefixes are stripped first, so
 *  one entry covers a tool however its gateway target happens to be named. */
const RECOGNIZERS: Record<string, Recognizer> = {
  // finance
  get_sector_performance: sectorPerformance,
  get_historical_prices: historicalPrices,
  get_market_overview: marketOverview,
  // healthcare
  get_patient_analytics: patientAnalytics,
  get_population_health_metrics: populationHealth,
  // insurance
  get_fraud_dashboard: fraudDashboard,
  get_settlement_analytics: settlementAnalytics,
  list_claims: claimsList,
  // retail
  get_demand_trends: demandTrends,
  forecast_demand: demandForecast,
  get_inventory_summary: inventorySummary,
  get_stockout_report: stockoutReport,
  // manufacturing
  get_sensor_data: sensorData,
  get_equipment_list: equipmentList,
  get_reliability_metrics: reliabilityMetrics,
  // real estate
  get_market_trends: marketTrends,
  get_market_forecast: marketForecast,
  get_comparables: comparables,
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
