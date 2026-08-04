import { CalendarClock, Users, UserPlus } from 'lucide-react'
import {
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { useApi } from '../../lib/api'
import { Card, ErrorPane, LoadingPane, StatCard } from '../finance/widgets'
import type { PopulationResponse } from './types'
import { labelize, parsePct } from './types'

const CONDITION_LABELS: Record<string, string> = {
  diabetes_type_2: 'Type 2 Diabetes',
  hypertension: 'Hypertension',
  hyperlipidemia: 'Hyperlipidemia',
  obesity_bmi_30_plus: 'Obesity (BMI 30+)',
  depression_anxiety: 'Depression / Anxiety',
  asthma_copd: 'Asthma / COPD',
  heart_failure: 'Heart Failure',
}

const HEDIS_LABELS: Record<string, string> = {
  diabetes_a1c_control_lt8: 'Diabetes A1C Control (<8%)',
  blood_pressure_control: 'Blood Pressure Control',
  breast_cancer_screening: 'Breast Cancer Screening',
  colorectal_cancer_screening: 'Colorectal Cancer Screening',
  flu_vaccination_rate: 'Flu Vaccination Rate',
  depression_screening: 'Depression Screening',
}

export default function PopulationSection() {
  const { data, loading, error, reload } = useApi<PopulationResponse>(
    '/api/healthcare/population',
  )

  if (loading) return <LoadingPane label="Loading population health…" />
  if (error || !data || data.error) {
    return (
      <Card title="Population Health">
        <ErrorPane
          message={error ?? data?.error ?? 'No population health data'}
          onRetry={reload}
        />
      </Card>
    )
  }

  const panel = data.practice_panel ?? {}
  const sex = panel.sex_distribution ?? {}
  const sexSub = [sex.male && `${sex.male} male`, sex.female && `${sex.female} female`]
    .filter(Boolean)
    .join(' · ')

  const prevalence = Object.entries(data.chronic_disease_prevalence ?? {}).map(
    ([key, entry]) => ({
      name: CONDITION_LABELS[key] ?? labelize(key),
      count: entry.count ?? 0,
      rate: entry.rate ?? '',
    }),
  )

  const measures = Object.entries(data.quality_measures_hedis ?? {}).map(
    ([key, m]) => {
      const performance = parsePct(m.performance)
      const target = parsePct(m.target)
      const national = parsePct(m.national_avg)
      const onTarget =
        performance !== null && target !== null && performance >= target
      return { key, label: HEDIS_LABELS[key] ?? labelize(key), performance, target, national, onTarget }
    },
  )

  return (
    <section className="space-y-4 @container">
      <h3 className="text-sm font-semibold uppercase tracking-wider text-rose-400">
        Population Health
      </h3>

      {/* Panel stat cards */}
      <div className="grid grid-cols-2 @3xl:grid-cols-3 gap-3 @lg:gap-4">
        <StatCard
          title="Active Patients"
          value={panel.total_active_patients?.toLocaleString() ?? '—'}
          icon={Users}
          sub={sexSub || undefined}
        />
        <StatCard
          title="New Patients (30d)"
          value={panel.new_patients_30d?.toLocaleString() ?? '—'}
          icon={UserPlus}
          sub="last 30 days"
        />
        <StatCard
          title="Average Age"
          value={panel.average_age != null ? panel.average_age.toFixed(1) : '—'}
          icon={CalendarClock}
          sub="years"
        />
      </div>

      {/* Chronic disease prevalence */}
      <Card title="Chronic Disease Prevalence (patients)">
        <div className="p-4 @lg:p-5">
          {prevalence.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-500">
              No prevalence data
            </p>
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(180, prevalence.length * 38)}>
              <BarChart
                data={prevalence}
                layout="vertical"
                margin={{ left: 8, right: 16, top: 4, bottom: 4 }}
              >
                <XAxis
                  type="number"
                  stroke="#64748b"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#64748b"
                  fontSize={11}
                  width={140}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(148, 163, 184, 0.06)' }}
                  contentStyle={{
                    background: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                  }}
                  labelStyle={{ color: '#94a3b8' }}
                  formatter={(value: number, _name, item) => [
                    `${value.toLocaleString()} patients${item?.payload?.rate ? ` (${item.payload.rate})` : ''}`,
                    'Prevalence',
                  ]}
                />
                <Bar dataKey="count" fill="#f43f5e" barSize={14} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </Card>

      {/* HEDIS quality measures */}
      <Card title="HEDIS Quality Measures">
        {measures.length === 0 ? (
          <p className="py-6 text-center text-sm text-slate-500">No quality measures</p>
        ) : (
          <div className="p-4 @lg:p-5 grid grid-cols-1 @2xl:grid-cols-2 @5xl:grid-cols-3 gap-3 @lg:gap-4">
            {measures.map((m) => (
              <div
                key={m.key}
                className="rounded-lg border border-slate-800 bg-slate-950/40 p-4"
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="text-xs text-slate-400">{m.label}</span>
                  <span
                    className={`shrink-0 px-2 py-0.5 rounded-full text-[11px] border ${
                      m.onTarget
                        ? 'bg-green-950/50 border-green-800/50 text-green-300'
                        : 'bg-amber-950/50 border-amber-800/50 text-amber-300'
                    }`}
                  >
                    {m.onTarget ? 'On target' : 'Below target'}
                  </span>
                </div>
                <div
                  className={`text-xl font-bold tabular-nums ${
                    m.onTarget ? 'text-green-400' : 'text-amber-400'
                  }`}
                >
                  {m.performance !== null ? `${m.performance}%` : '—'}
                </div>
                {/* Performance meter with target marker */}
                <div className="relative mt-3 h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${m.onTarget ? 'bg-green-500' : 'bg-amber-500'}`}
                    style={{ width: `${Math.min(m.performance ?? 0, 100)}%` }}
                  />
                  {m.target !== null && (
                    <div
                      className="absolute top-0 h-full w-0.5 bg-slate-300"
                      style={{ left: `${Math.min(m.target, 100)}%` }}
                    />
                  )}
                </div>
                <div className="flex justify-between text-[11px] text-slate-500 mt-1.5 tabular-nums">
                  <span>target {m.target !== null ? `${m.target}%` : '—'}</span>
                  <span>national avg {m.national !== null ? `${m.national}%` : '—'}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </section>
  )
}
