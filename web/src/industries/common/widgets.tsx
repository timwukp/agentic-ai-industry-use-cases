/** Cross-industry dashboard widgets.
 *
 * Generic panes (Card/StatCard/LoadingPane/ErrorPane/SimulatedBadge) live in
 * ../finance/widgets; healthcare keeps its clinical-specific wrappers in
 * ../healthcare/widgets. Anything used by two or more industries belongs here.
 *
 * Dataviz rules (same as healthcare): status colors (green/amber/red) appear
 * ONLY in pills/banners/meters — never as a chart series color. Series use the
 * industry accent plus sky-400 (#38bdf8) as the second series. Dashed lines are
 * reserved for target/threshold reference lines. Grid stroke is #1e293b.
 */

import type { ReactNode } from 'react'
import { Bot } from 'lucide-react'
import {
  Area,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { getCurrentLocale } from '../../i18n'
import { useLocale } from '../../i18n/LocaleContext'
import { askAgent } from '../../lib/promptBus'

/* ---------------------------------- pills --------------------------------- */

export type PillTone = 'red' | 'amber' | 'green' | 'violet' | 'sky' | 'slate'

const PILL_TONES: Record<PillTone, string> = {
  red: 'bg-red-950/50 border-red-800/50 text-red-300',
  amber: 'bg-amber-950/50 border-amber-800/50 text-amber-300',
  green: 'bg-green-950/50 border-green-800/50 text-green-300',
  violet: 'bg-violet-950/50 border-violet-800/50 text-violet-300',
  sky: 'bg-sky-950/50 border-sky-800/50 text-sky-300',
  slate: 'bg-slate-800/70 border-slate-700 text-slate-300',
}

export function StatusPill({ tone, label }: { tone: PillTone; label: string }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] border font-medium whitespace-nowrap ${PILL_TONES[tone]}`}
    >
      {label}
    </span>
  )
}

/** CRITICAL/HIGH → red, WARNING/MEDIUM → amber, else slate. */
export function SeverityPill({ severity }: { severity?: string }) {
  const s = (severity ?? '').toUpperCase()
  const tone: PillTone =
    s === 'CRITICAL' || s === 'HIGH'
      ? 'red'
      : s === 'WARNING' || s === 'MEDIUM' || s === 'MODERATE'
        ? 'amber'
        : s === 'LOW' || s === 'INFO'
          ? 'slate'
          : 'slate'
  return <StatusPill tone={tone} label={s || '—'} />
}

/* ------------------------------ section header ---------------------------- */

export function SectionHeader({
  title,
  accentClass,
  action,
}: {
  title: string
  /** Industry accent, e.g. "text-indigo-400". */
  accentClass: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3
        className={`text-sm font-semibold uppercase tracking-wider ${accentClass}`}
      >
        {title}
      </h3>
      {action}
    </div>
  )
}

/* ----------------------------- ask-agent button --------------------------- */

/** Ghost button that prefills the chat panel with a suggested prompt.
 *  The dashboard deliberately has no write tools — actions hand off to chat. */
export function AskAgentButton({
  prompt,
  hoverClass = 'hover:text-sky-300',
}: {
  prompt: string
  hoverClass?: string
}) {
  const { t } = useLocale()
  return (
    <button
      type="button"
      onClick={() => askAgent(prompt)}
      title={prompt}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg border border-transparent text-slate-400 hover:border-slate-700 hover:bg-slate-800/60 transition-colors shrink-0 ${hoverClass}`}
    >
      <Bot className="w-3.5 h-3.5" />
      {t('widgets.askAgent')}
    </button>
  )
}

/* --------------------------------- charts --------------------------------- */

const TOOLTIP_STYLE = {
  background: '#1e293b',
  border: '1px solid #334155',
  borderRadius: '8px',
  color: '#e2e8f0',
  fontSize: 12,
} as const

const AXIS = {
  stroke: '#64748b',
  fontSize: 10,
  tickLine: false,
  axisLine: false,
} as const

/** Smallest 1/2/5 x 10^n step at or above `rough` — keeps axis ticks readable. */
function niceStep(rough: number): number {
  if (!(rough > 0)) return 1
  const mag = 10 ** Math.floor(Math.log10(rough))
  const norm = rough / mag
  return (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag
}

export interface Series {
  key: string
  color: string
  name: string
  /** Put this series on the right-hand axis. Required when two series differ by
   *  more than ~10x in magnitude — a shared axis flattens the smaller one onto
   *  the baseline, which reads as "no data" rather than "different scale". */
  axis?: 'left' | 'right'
  /** Tick/tooltip formatter for this series' own axis. */
  formatter?: (value: number) => string
}

/** Multi-series line chart with optional dashed threshold reference lines. */
export function LineTrend({
  data,
  xKey,
  series,
  refLines = [],
  height = 170,
  unit,
  yFormatter,
}: {
  data: Array<Record<string, unknown>>
  xKey: string
  series: Series[]
  /** Dashed target/threshold markers — never a data series. */
  refLines?: Array<{ y: number; label?: string; color?: string }>
  height?: number
  unit?: string
  yFormatter?: (value: number) => string
}) {
  const right = series.find((s) => s.axis === 'right')
  return (
    <div>
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ left: 0, right: 10, top: 8, bottom: 0 }}>
          <CartesianGrid stroke="#1e293b" vertical={false} />
          <XAxis dataKey={xKey} {...AXIS} minTickGap={20} />
          <YAxis
            yAxisId="left"
            {...AXIS}
            width={46}
            domain={['auto', 'auto']}
            tickFormatter={yFormatter}
          />
          {right && (
            <YAxis
              yAxisId="right"
              orientation="right"
              {...AXIS}
              stroke={right.color}
              width={44}
              domain={['auto', 'auto']}
              tickFormatter={right.formatter}
            />
          )}
          <Tooltip
            cursor={{ stroke: '#334155' }}
            contentStyle={TOOLTIP_STYLE}
            labelStyle={{ color: '#94a3b8' }}
            formatter={(value: number, name: string) => {
              const s = series.find((item) => item.name === name)
              const fmt = s?.formatter ?? yFormatter
              return [
                `${fmt ? fmt(value) : value.toLocaleString()}${unit ? ` ${unit}` : ''}`,
                name,
              ]
            }}
          />
          {refLines.map((r) => (
            <ReferenceLine
              key={`${r.y}-${r.label ?? ''}`}
              yAxisId="left"
              y={r.y}
              stroke={r.color ?? '#64748b'}
              strokeDasharray="4 4"
              strokeWidth={1}
              label={
                r.label
                  ? { value: r.label, position: 'insideTopRight', fill: '#64748b', fontSize: 10 }
                  : undefined
              }
            />
          ))}
          {series.map((s) => (
            <Line
              key={s.key}
              yAxisId={s.axis === 'right' ? 'right' : 'left'}
              type="monotone"
              dataKey={s.key}
              name={s.name}
              stroke={s.color}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
      {series.length > 1 && <Legend series={series} />}
    </div>
  )
}

/** Forecast band: shaded confidence interval behind a projection line.
 *
 *  Uses ComposedChart, not AreaChart: recharts only renders the cartesian
 *  children a chart type declares, so a <Line> inside <AreaChart> is silently
 *  dropped and the projection disappears, leaving the band alone. */
export function ForecastBand({
  data,
  xKey,
  lowKey,
  highKey,
  lineKey,
  color,
  height = 190,
  yFormatter,
}: {
  data: Array<Record<string, unknown>>
  xKey: string
  lowKey: string
  highKey: string
  lineKey: string
  color: string
  height?: number
  yFormatter?: (value: number) => string
}) {
  const { t } = useLocale()
  // Stacked areas make recharts anchor its own domain at 0, which squashes a
  // band sitting far from zero into a flat line near the top. Derive the real
  // range, snap it to a round step, and pass explicit ticks — recharts still
  // runs its nice-tick pass over a numeric domain and would reintroduce 0.
  const lows = data.map((d) => Number(d[lowKey]) || 0)
  const tops = data.map((d) => (Number(d[lowKey]) || 0) + (Number(d[highKey]) || 0))
  const rawLo = lows.length ? Math.min(...lows) : 0
  const rawHi = tops.length ? Math.max(...tops) : 0
  const step = niceStep((rawHi - rawLo || rawHi || 1) / 3)
  const lo = Math.max(0, Math.floor(rawLo / step - 0.5) * step)
  const hi = Math.ceil(rawHi / step + 0.5) * step
  const ticks: number[] = []
  for (let t = lo; t <= hi + step / 2; t += step) ticks.push(Math.round(t))

  return (
    <ResponsiveContainer width="100%" height={height}>
      <ComposedChart data={data} margin={{ left: 0, right: 10, top: 8, bottom: 0 }}>
        <CartesianGrid stroke="#1e293b" vertical={false} />
        <XAxis dataKey={xKey} {...AXIS} minTickGap={20} />
        <YAxis
          {...AXIS}
          width={52}
          domain={[lo, hi]}
          ticks={ticks}
          allowDataOverflow
          tickFormatter={yFormatter}
        />
        <Tooltip
          cursor={{ stroke: '#334155' }}
          contentStyle={TOOLTIP_STYLE}
          labelStyle={{ color: '#94a3b8' }}
          formatter={(value: number, name: string) => [
            yFormatter ? yFormatter(value) : value.toLocaleString(),
            name,
          ]}
        />
        {/* stacked pair renders the interval as a band without a second axis */}
        <Area
          dataKey={lowKey}
          name={t('widgets.forecastLow')}
          stackId="band"
          stroke="none"
          fill="transparent"
          isAnimationActive={false}
        />
        <Area
          dataKey={highKey}
          name={t('widgets.forecastRange')}
          stackId="band"
          stroke="none"
          fill={color}
          fillOpacity={0.14}
          isAnimationActive={false}
        />
        <Line
          type="monotone"
          dataKey={lineKey}
          name={t('widgets.forecastProjection')}
          stroke={color}
          strokeWidth={2}
          dot={false}
          isAnimationActive={false}
        />
      </ComposedChart>
    </ResponsiveContainer>
  )
}

/** Horizontal bar chart for ranked categories. */
export function RankedBars({
  data,
  categoryKey,
  valueKey,
  color,
  /** Per-row override, e.g. red for below-threshold rows. */
  colorFor,
  labelWidth = 130,
  barSize = 14,
  valueFormatter,
}: {
  data: Array<Record<string, unknown>>
  categoryKey: string
  valueKey: string
  color: string
  colorFor?: (row: Record<string, unknown>) => string
  labelWidth?: number
  barSize?: number
  valueFormatter?: (value: number) => string
}) {
  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 34)}>
      <BarChart
        data={data}
        layout="vertical"
        margin={{ left: 4, right: 16, top: 4, bottom: 4 }}
      >
        <XAxis type="number" {...AXIS} fontSize={11} tickFormatter={valueFormatter} />
        <YAxis
          type="category"
          dataKey={categoryKey}
          {...AXIS}
          fontSize={11}
          width={labelWidth}
        />
        <Tooltip
          cursor={{ fill: 'rgba(148, 163, 184, 0.06)' }}
          contentStyle={TOOLTIP_STYLE}
          labelStyle={{ color: '#94a3b8' }}
          formatter={(value: number) => [
            valueFormatter ? valueFormatter(value) : value.toLocaleString(),
            '',
          ]}
        />
        <Bar dataKey={valueKey} barSize={barSize} radius={[0, 4, 4, 0]}>
          {data.map((row, i) => (
            <Cell key={i} fill={colorFor ? colorFor(row) : color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

function Legend({ series }: { series: Series[] }) {
  return (
    <div className="flex flex-wrap items-center gap-4 px-1 mt-1">
      {series.map((s) => (
        <span
          key={s.key}
          className="inline-flex items-center gap-1.5 text-[11px] text-slate-400"
        >
          <span
            className="inline-block w-2.5 h-0.5 rounded-full"
            style={{ background: s.color }}
          />
          {s.name}
        </span>
      ))}
    </div>
  )
}

/* ---------------------------------- meter --------------------------------- */

/** Progress meter with optional benchmark tick. Fill color is a status color. */
export function MeterBar({
  pct,
  fillClass,
  ticks = [],
}: {
  pct: number
  fillClass: string
  ticks?: Array<{ at: number; title: string; className?: string }>
}) {
  return (
    <div className="relative h-2 bg-slate-800 rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full ${fillClass}`}
        style={{ width: `${Math.min(Math.max(pct, 0), 100)}%` }}
      />
      {ticks.map((t) => (
        <div
          key={t.title}
          className={`absolute top-0 h-full w-0.5 ${t.className ?? 'bg-slate-300'}`}
          style={{ left: `${Math.min(Math.max(t.at, 0), 100)}%` }}
          title={t.title}
        />
      ))}
    </div>
  )
}

/* ---------------------------------- table --------------------------------- */

export interface Column<T> {
  header: string
  /** Right-align + tabular-nums for numeric columns. */
  numeric?: boolean
  className?: string
  render: (row: T) => ReactNode
}

/** Scrollable table that collapses to stacked rows under @2xl. */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  empty,
  maxHeight = 'max-h-80',
}: {
  columns: Array<Column<T>>
  rows: T[]
  rowKey: (row: T, index: number) => string
  empty?: string
  maxHeight?: string
}) {
  const { t } = useLocale()
  if (rows.length === 0) {
    return (
      <p className="py-6 text-center text-sm text-slate-500">
        {empty ?? t('widgets.noRows')}
      </p>
    )
  }
  return (
    <div className={`overflow-auto ${maxHeight}`}>
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-slate-900 z-10">
          <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
            {columns.map((c) => (
              <th
                key={c.header}
                className={`px-4 py-2.5 font-medium whitespace-nowrap ${
                  c.numeric ? 'text-right' : ''
                }`}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/70">
          {rows.map((row, i) => (
            <tr key={rowKey(row, i)} className="hover:bg-slate-800/40">
              {columns.map((c) => (
                <td
                  key={c.header}
                  className={`px-4 py-2.5 ${
                    c.numeric ? 'text-right tabular-nums' : ''
                  } ${c.className ?? 'text-slate-300'}`}
                >
                  {c.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* -------------------------------- formatters ------------------------------ */

export const fmtCompactUsd = (n: number | undefined | null): string =>
  n == null
    ? '—'
    : n.toLocaleString(getCurrentLocale(), {
        style: 'currency',
        currency: 'USD',
        notation: 'compact',
        maximumFractionDigits: 1,
      })

export const fmtUsd0 = (n: number | undefined | null): string =>
  n == null
    ? '—'
    : n.toLocaleString(getCurrentLocale(), {
        style: 'currency',
        currency: 'USD',
        maximumFractionDigits: 0,
      })

export const fmtNum = (n: number | undefined | null): string =>
  n == null ? '—' : n.toLocaleString(getCurrentLocale())

export const fmtPct = (n: number | undefined | null, digits = 1): string =>
  n == null ? '—' : `${n.toFixed(digits)}%`

/** Signed delta with a class hint; `goodWhenNegative` flips the coloring for
 *  metrics where down is better (processing time, lead time, days on market). */
export function deltaClass(n: number, goodWhenNegative = false): string {
  const good = goodWhenNegative ? n <= 0 : n >= 0
  return good ? 'text-green-400' : 'text-red-400'
}

export const fmtSignedPct = (n: number | undefined | null): string =>
  n == null ? '—' : `${n >= 0 ? '+' : ''}${n.toFixed(1)}%`
