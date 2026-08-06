/** Healthcare-specific presentational widgets.
 *
 * Generic panes (Card/StatCard/LoadingPane/ErrorPane/SimulatedBadge) still come
 * from ../finance/widgets — these are the healthcare additions.
 *
 * Dataviz rules: status colors (green/amber/red) appear ONLY in pills/banners;
 * chart series use rose-400 (#fb7185) and sky-400 (#38bdf8) only; dashed lines
 * are reserved for clinical-target ReferenceLines; grid stroke is #1e293b.
 */

import type { ReactNode } from 'react'
import { Bot } from 'lucide-react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { askAgent } from '../../lib/promptBus'
import { useLocale } from '../../i18n/LocaleContext'

/* ---------------------------------- pills -------------------------------------- */

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

/** HIGH → amber, everything else (MEDIUM/LOW/unknown) → slate. */
export function PriorityPill({ priority }: { priority?: string }) {
  const p = (priority ?? '').toUpperCase()
  return <StatusPill tone={p === 'HIGH' ? 'amber' : 'slate'} label={p || '—'} />
}

/* ------------------------------- section header --------------------------------- */

export function SectionHeader({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 className="text-sm font-semibold uppercase tracking-wider text-rose-400">
        {title}
      </h3>
      {action}
    </div>
  )
}

/* ------------------------------- ask-agent button ------------------------------- */

/** Ghost button that prefills the chat panel with a suggested prompt. */
export function AskAgentButton({ prompt }: { prompt: string }) {
  const { t } = useLocale()
  return (
    <button
      type="button"
      onClick={() => askAgent(prompt)}
      title={prompt}
      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg border border-transparent text-slate-400 hover:text-rose-300 hover:border-slate-700 hover:bg-slate-800/60 transition-colors shrink-0"
    >
      <Bot className="w-3.5 h-3.5" />
      {t('widgets.askAgent')}
    </button>
  )
}

/* --------------------------------- trend chart ---------------------------------- */

export interface TrendSeries {
  key: string
  color: string // series colors: rose-400 #fb7185 / sky-400 #38bdf8 only
  name: string
}

/** Recharts LineChart wrapper for small-multiple clinical trends.
 *
 * `target` renders a dashed slate ReferenceLine (clinical target only).
 * Dots are hidden by default; enable via `showDots` for sparse series (A1C).
 * No legend is rendered for single-series charts (the header names it).
 */
export function TrendChart({
  data,
  series,
  target,
  unit,
  height = 150,
  showDots = false,
}: {
  data: Array<Record<string, unknown>>
  series: TrendSeries[]
  target?: number
  unit?: string
  height?: number
  showDots?: boolean
}) {
  const multi = series.length > 1
  return (
    <div>
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ left: 0, right: 8, top: 8, bottom: 0 }}>
          <CartesianGrid stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="month"
            stroke="#64748b"
            fontSize={10}
            tickLine={false}
            axisLine={false}
            minTickGap={24}
          />
          <YAxis
            stroke="#64748b"
            fontSize={10}
            width={34}
            tickLine={false}
            axisLine={false}
            domain={['auto', 'auto']}
          />
          <Tooltip
            cursor={{ stroke: '#334155' }}
            contentStyle={{
              background: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#e2e8f0',
              fontSize: 12,
            }}
            labelStyle={{ color: '#94a3b8' }}
            formatter={(value: number, name: string) => [
              `${value}${unit ? ` ${unit}` : ''}`,
              name,
            ]}
          />
          {target != null && (
            <ReferenceLine
              y={target}
              stroke="#64748b"
              strokeDasharray="4 4"
              strokeWidth={1}
            />
          )}
          {series.map((s) => (
            <Line
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.name}
              stroke={s.color}
              strokeWidth={2}
              dot={showDots ? { r: 3, fill: s.color, strokeWidth: 0 } : false}
              activeDot={{ r: 4 }}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
      {multi && (
        <div className="flex items-center gap-4 px-1 mt-1">
          {series.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5 text-[11px] text-slate-400">
              <span
                className="inline-block w-2.5 h-0.5 rounded-full"
                style={{ background: s.color }}
              />
              {s.name}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
