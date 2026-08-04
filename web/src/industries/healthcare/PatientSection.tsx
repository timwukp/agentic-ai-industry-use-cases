import { useState } from 'react'
import type { FormEvent } from 'react'
import { Activity, HeartPulse, Scale, Search, Stethoscope } from 'lucide-react'
import { useApi } from '../../lib/api'
import { Card, ErrorPane, LoadingPane } from '../finance/widgets'
import type { PatientResponse, TrendMetric } from './types'

const DEFAULT_PATIENT_ID = 'PT-1001'

const RISK_STYLES: Record<string, { badge: string; bar: string; text: string }> = {
  LOW: {
    badge: 'bg-green-950/50 border-green-800/50 text-green-300',
    bar: 'bg-green-500',
    text: 'text-green-400',
  },
  MODERATE: {
    badge: 'bg-amber-950/50 border-amber-800/50 text-amber-300',
    bar: 'bg-amber-500',
    text: 'text-amber-400',
  },
  HIGH: {
    badge: 'bg-red-950/50 border-red-800/50 text-red-300',
    bar: 'bg-red-500',
    text: 'text-red-400',
  },
}

function statusClass(status?: string): string {
  if (!status) return 'text-slate-400'
  return status.toUpperCase().includes('AT TARGET') ? 'text-green-400' : 'text-amber-400'
}

function MetricTile({
  label,
  icon: Icon,
  metric,
}: {
  label: string
  icon: typeof Activity
  metric?: TrendMetric | (Omit<TrendMetric, 'data'> & { data?: unknown })
}) {
  if (!metric) return null
  const sub =
    metric.status ?? metric.classification ?? metric.change_12mo ?? metric.trend_direction
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-slate-400">{label}</span>
        <Icon className="w-4 h-4 text-slate-500" />
      </div>
      <div className="text-lg font-bold text-white tabular-nums">
        {metric.current ?? '—'}
      </div>
      <div className="flex flex-wrap items-center gap-x-2 text-[11px] mt-1">
        {sub && <span className={statusClass(metric.status)}>{sub}</span>}
        {metric.target && <span className="text-slate-500">target {metric.target}</span>}
      </div>
    </div>
  )
}

function PatientDetails({ patientId }: { patientId: string }) {
  const { data, loading, error, reload } = useApi<PatientResponse>(
    `/api/healthcare/patient?patientId=${encodeURIComponent(patientId)}`,
  )

  if (loading) return <LoadingPane label={`Loading ${patientId}…`} />
  if (error || !data || data.error || (!data.analytics && !data.readmission)) {
    return (
      <ErrorPane
        message={error ?? data?.error ?? `No data for patient ${patientId}`}
        onRetry={reload}
      />
    )
  }

  const trends = data.analytics?.trends ?? {}
  const insights = data.analytics?.clinical_insights ?? []
  const risk = data.readmission
  const riskLevel = (risk?.risk_level ?? '').toUpperCase()
  const riskStyle = RISK_STYLES[riskLevel] ?? RISK_STYLES.MODERATE
  const riskScore = risk?.risk_score
  const factors = risk?.contributing_factors ?? []

  return (
    <div className="p-4 @lg:p-5 grid grid-cols-1 @4xl:grid-cols-2 gap-4 @lg:gap-5">
      {/* Analytics summary */}
      <div className="space-y-3">
        <div className="flex items-baseline justify-between">
          <h4 className="text-sm font-medium text-slate-300">Clinical Trends</h4>
          {data.analytics?.analysis_period && (
            <span className="text-[11px] text-slate-500">
              {data.analytics.analysis_period}
            </span>
          )}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <MetricTile label="Blood Pressure" icon={HeartPulse} metric={trends.blood_pressure} />
          <MetricTile label="Hemoglobin A1C" icon={Activity} metric={trends.hemoglobin_a1c} />
          <MetricTile label="BMI" icon={Scale} metric={trends.bmi} />
          <MetricTile label="Weight" icon={Scale} metric={trends.weight} />
          <MetricTile label="LDL Cholesterol" icon={Stethoscope} metric={trends.ldl_cholesterol} />
        </div>
        {insights.length > 0 && (
          <ul className="space-y-1.5 pt-1">
            {insights.map((insight) => (
              <li key={insight} className="flex gap-2 text-xs text-slate-400">
                <span className="text-rose-400 shrink-0">•</span>
                {insight}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Readmission risk */}
      <div className="space-y-3">
        <h4 className="text-sm font-medium text-slate-300">30-Day Readmission Risk</h4>
        {risk ? (
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-4 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-baseline gap-2">
                <span className={`text-3xl font-bold tabular-nums ${riskStyle.text}`}>
                  {riskScore != null ? `${riskScore}%` : '—'}
                </span>
                <span className="text-xs text-slate-500">probability</span>
              </div>
              <span
                className={`px-2.5 py-1 rounded-full text-[11px] border font-medium ${riskStyle.badge}`}
              >
                {riskLevel || 'UNKNOWN'} RISK
              </span>
            </div>
            {/* Risk gauge: model scores range 0–55 */}
            <div>
              <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${riskStyle.bar}`}
                  style={{
                    width: `${Math.min(((riskScore ?? 0) / 55) * 100, 100)}%`,
                  }}
                />
              </div>
              <div className="flex justify-between text-[11px] text-slate-500 mt-1">
                <span>Low</span>
                <span>Moderate</span>
                <span>High</span>
              </div>
            </div>
            {factors.length > 0 && (
              <div>
                <div className="text-xs text-slate-400 mb-1.5">Contributing factors</div>
                <ul className="space-y-1">
                  {factors.map((factor) => (
                    <li key={factor} className="flex gap-2 text-xs text-slate-400">
                      <span className="text-slate-600 shrink-0">–</span>
                      {factor}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {risk.risk_model && (
              <p className="text-[11px] text-slate-600">{risk.risk_model}</p>
            )}
          </div>
        ) : (
          <p className="text-sm text-slate-500">No readmission risk data</p>
        )}
      </div>
    </div>
  )
}

export default function PatientSection() {
  const [inputValue, setInputValue] = useState(DEFAULT_PATIENT_ID)
  const [patientId, setPatientId] = useState(DEFAULT_PATIENT_ID)

  const apply = (event: FormEvent) => {
    event.preventDefault()
    const next = inputValue.trim()
    if (next) setPatientId(next)
  }

  return (
    <section className="space-y-4 @container">
      <h3 className="text-sm font-semibold uppercase tracking-wider text-rose-400">
        Patient Spotlight
      </h3>
      <Card
        title={`Patient ${patientId}`}
        action={
          <form onSubmit={apply} className="flex items-center gap-2">
            <input
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="PT-1001"
              aria-label="Patient ID"
              className="w-28 px-2.5 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-rose-500/60"
            />
            <button
              type="submit"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors"
            >
              <Search className="w-3.5 h-3.5" />
              Apply
            </button>
          </form>
        }
      >
        <PatientDetails patientId={patientId} />
      </Card>
    </section>
  )
}
