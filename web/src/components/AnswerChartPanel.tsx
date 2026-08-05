/** Transient chart panel for the charts behind an agent's answer.
 *
 * Why this exists: the reply to "which sectors are leading and lagging" is an
 * eleven-row table rendered into a ~340px chat bubble. Markdown rendering made
 * that legible (see components/Markdown.tsx), but legible is not the same as
 * readable — ranked numbers are a chart, and a chart does not fit in the bubble.
 *
 * It slides in ABOVE the industry dashboard rather than replacing it, and is
 * dismissible: the dashboard is the standing view and this is a by-product of one
 * question, so it must never be the thing the user has to close to get back to
 * work. Below lg the dashboard and chat are separate views, so the panel is
 * rendered inline under the message instead (see ChatPanel) and this component is
 * only mounted on the desktop split.
 *
 * The data is the tool payload the agent itself received, extracted from the
 * invoke stream (lib/toolTrace.ts) and shaped by lib/chartSpec.ts. It is
 * deliberately NOT a re-fetch of the matching dashboard REST route: a re-fetch
 * could return different numbers than the reply on screen (different arguments, a
 * later timestamp), and a chart that silently disagrees with the text beside it is
 * worse than no chart.
 */

import { useEffect, useState } from 'react'
import { BarChart3, ChevronLeft, ChevronRight, X } from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { ChartSpec } from '../lib/chartSpec'
import {
  LABEL_WIDTH,
  LINE_HEIGHT,
  plotHeight,
  shortLabel,
  tickFormat,
} from '../lib/chartFormat'

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

export function ChartCard({ spec }: { spec: ChartSpec }) {
  const negative = spec.data.some((row) =>
    spec.series.some((s) => Number(row[s.key]) < 0),
  )
  return (
    <div data-testid="answer-chart" data-chart-title={spec.title}>
      <div className="px-1 pb-2">
        <h4 className="text-sm font-medium text-white">{spec.title}</h4>
        {spec.subtitle && (
          <p className="text-[11px] text-slate-500 mt-0.5">{spec.subtitle}</p>
        )}
      </div>

      {spec.kind === 'line' ? (
        <ResponsiveContainer width="100%" height={LINE_HEIGHT}>
          <LineChart data={spec.data} margin={{ left: 0, right: 12, top: 6, bottom: 0 }}>
            <CartesianGrid stroke="#1e293b" vertical={false} />
            <XAxis dataKey={spec.xKey} {...AXIS} minTickGap={24} />
            <YAxis {...AXIS} width={46} domain={['auto', 'auto']} tickFormatter={tickFormat} />
            <Tooltip
              cursor={{ stroke: '#334155' }}
              contentStyle={TOOLTIP_STYLE}
              labelStyle={{ color: '#94a3b8' }}
              formatter={(value: number, name: string) => [
                `${value.toLocaleString()}${spec.unit ? ` ${spec.unit}` : ''}`,
                name,
              ]}
            />
            {(spec.refLines ?? []).map((line) => (
              <ReferenceLine
                key={`${line.y}-${line.label ?? ''}`}
                y={line.y}
                stroke="#64748b"
                strokeDasharray="4 4"
                strokeWidth={1}
                label={
                  line.label
                    ? {
                        value: line.label,
                        position: 'insideTopRight',
                        fill: '#64748b',
                        fontSize: 10,
                      }
                    : undefined
                }
              />
            ))}
            {spec.series.map((s) => (
              <Line
                key={s.key}
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
      ) : (
        // Ranked categories go horizontal: category names are words, and words on
        // a vertical axis stay readable at any count without rotating them.
        <ResponsiveContainer
          width="100%"
          height={plotHeight('bars', spec.data.length)}
        >
          <BarChart
            data={spec.data}
            layout="vertical"
            margin={{ left: 4, right: 16, top: 4, bottom: 4 }}
          >
            <XAxis type="number" {...AXIS} tickFormatter={tickFormat} />
            <YAxis
              type="category"
              dataKey={spec.xKey}
              {...AXIS}
              width={LABEL_WIDTH}
              tickFormatter={shortLabel}
              interval={0}
            />
            <Tooltip
              cursor={{ fill: 'rgba(148, 163, 184, 0.06)' }}
              contentStyle={TOOLTIP_STYLE}
              labelStyle={{ color: '#94a3b8' }}
              formatter={(value: number, name: string) => [
                `${value.toLocaleString()}${spec.unit ? ` ${spec.unit}` : ''}`,
                name,
              ]}
            />
            {/* Zero line only where values straddle it, so a positive-only chart
                does not carry an axis marker that means nothing. */}
            {negative && <ReferenceLine x={0} stroke="#475569" strokeWidth={1} />}
            {spec.series.map((s) => (
              <Bar key={s.key} dataKey={s.key} name={s.name} barSize={12} radius={[0, 3, 3, 0]}>
                {spec.data.map((row, i) => (
                  // Diverging bars are tinted by sign — this is the one place a
                  // status color is legitimate, because the sign IS the status.
                  <Cell
                    key={i}
                    fill={
                      negative && Number(row[s.key]) < 0 ? '#f87171' : s.color
                    }
                  />
                ))}
              </Bar>
            ))}
          </BarChart>
        </ResponsiveContainer>
      )}

      {spec.series.length > 1 && (
        <div className="flex flex-wrap items-center gap-3 px-1 mt-1">
          {spec.series.map((s) => (
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
      )}
    </div>
  )
}

/**
 * The overlay itself. Stacks above the dashboard, dismissible, and paginated when
 * one answer produced several charts (the market question calls two tools).
 */
export default function AnswerChartPanel({
  specs,
  onDismiss,
}: {
  specs: ChartSpec[]
  onDismiss: () => void
}) {
  const [index, setIndex] = useState(0)

  // A new answer resets to the first chart. Keyed on the titles rather than the
  // array identity: the parent re-renders on every stream chunk, and depending on
  // identity would snap the view back to chart 1 while the user is reading 2.
  const signature = specs.map((s) => s.title).join('|')
  useEffect(() => setIndex(0), [signature])

  if (specs.length === 0) return null
  const spec = specs[Math.min(index, specs.length - 1)]

  return (
    <div
      data-testid="answer-chart-panel"
      className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm"
    >
      <div className="px-4 pt-3 pb-1 flex items-center gap-2">
        <BarChart3 className="w-4 h-4 text-sky-400 shrink-0" />
        <span className="text-[11px] uppercase tracking-wider text-slate-500 font-medium flex-1 truncate">
          From the assistant’s answer
        </span>
        {specs.length > 1 && (
          <div className="flex items-center gap-1 shrink-0">
            <button
              type="button"
              onClick={() => setIndex((i) => Math.max(0, i - 1))}
              disabled={index === 0}
              title="Previous chart"
              className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-40 disabled:hover:bg-transparent transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-[11px] text-slate-500 tabular-nums">
              {index + 1}/{specs.length}
            </span>
            <button
              type="button"
              onClick={() => setIndex((i) => Math.min(specs.length - 1, i + 1))}
              disabled={index >= specs.length - 1}
              title="Next chart"
              className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-40 disabled:hover:bg-transparent transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
        <button
          type="button"
          onClick={onDismiss}
          title="Dismiss charts"
          aria-label="Dismiss charts"
          data-testid="dismiss-answer-chart"
          className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors shrink-0"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="px-3 pb-3">
        <ChartCard spec={spec} />
      </div>
    </div>
  )
}
