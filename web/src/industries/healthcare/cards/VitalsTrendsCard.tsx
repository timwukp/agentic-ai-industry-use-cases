import { Card } from '../../finance/widgets'
import { StatusPill, TrendChart, type PillTone, type TrendSeries } from '../widgets'
import type { PatientAnalytics, TrendMetric } from '../types'

const ROSE = '#fb7185' // rose-400
const SKY = '#38bdf8' // sky-400

function statusTone(status?: string): { tone: PillTone; label: string } | null {
  if (!status) return null
  const s = status.toUpperCase()
  if (s === 'AT TARGET') return { tone: 'green', label: 'AT TARGET' }
  if (s === 'ABOVE TARGET') return { tone: 'amber', label: 'ABOVE TARGET' }
  return { tone: 'slate', label: s }
}

function ChartTile({
  name,
  metric,
  series,
  target,
  unit,
  showDots,
}: {
  name: string
  metric?: Omit<TrendMetric, 'data'> & { data?: object[] }
  series: TrendSeries[]
  target?: number
  unit?: string
  showDots?: boolean
}) {
  const data = (metric?.data ?? []) as Array<Record<string, unknown>>
  const status = statusTone(metric?.status)
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 @lg:p-4">
      <div className="flex items-center justify-between gap-2 mb-1">
        <div className="flex items-baseline gap-2 min-w-0">
          <span className="text-xs text-slate-400 truncate">{name}</span>
          <span className="text-sm font-semibold text-white tabular-nums whitespace-nowrap">
            {metric?.current ?? '—'}
          </span>
        </div>
        {status && <StatusPill tone={status.tone} label={status.label} />}
      </div>
      {data.length === 0 ? (
        <p className="py-8 text-center text-xs text-slate-600">No trend data</p>
      ) : (
        <TrendChart
          data={data}
          series={series}
          target={target}
          unit={unit}
          showDots={showDots}
        />
      )}
    </div>
  )
}

export default function VitalsTrendsCard({
  analytics,
}: {
  analytics?: PatientAnalytics
}) {
  const trends = analytics?.trends ?? {}

  return (
    <Card
      title="Vitals & Trends"
      action={
        analytics?.analysis_period ? (
          <span className="text-[11px] text-slate-500">{analytics.analysis_period}</span>
        ) : undefined
      }
    >
      <div className="p-4 @lg:p-5 grid grid-cols-1 @2xl:grid-cols-2 gap-3 @lg:gap-4">
        <ChartTile
          name="Blood Pressure"
          metric={trends.blood_pressure}
          series={[
            { key: 'systolic', color: ROSE, name: 'Systolic' },
            { key: 'diastolic', color: SKY, name: 'Diastolic' },
          ]}
          target={130}
          unit="mmHg"
        />
        <ChartTile
          name="Hemoglobin A1C"
          metric={trends.hemoglobin_a1c}
          series={[{ key: 'value', color: ROSE, name: 'A1C' }]}
          target={7}
          unit="%"
          showDots
        />
        <ChartTile
          name="Weight"
          metric={trends.weight}
          series={[{ key: 'value', color: ROSE, name: 'Weight' }]}
          unit="lbs"
        />
        <ChartTile
          name="LDL Cholesterol"
          metric={trends.ldl_cholesterol}
          series={[{ key: 'value', color: ROSE, name: 'LDL' }]}
          target={100}
          unit="mg/dL"
        />
      </div>
    </Card>
  )
}
