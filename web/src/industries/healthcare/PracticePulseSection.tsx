import { Activity, Ambulance, Users, Video } from 'lucide-react'
import {
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { useApi } from '../../lib/api'
import { useLocale } from '../../i18n/LocaleContext'
import { Card, ErrorPane, LoadingPane, StatCard } from '../finance/widgets'
import { SectionHeader, StatusPill } from './widgets'
import type { PopulationResponse } from './types'
import { labelize, parsePct } from './types'

/** Payload condition key → catalog key under healthcare.conditions.*; unknown
 *  payload keys fall back to labelize(). */
const CONDITION_KEYS: Record<string, string> = {
  diabetes_type_2: 'diabetes_type_2',
  hypertension: 'hypertension',
  hyperlipidemia: 'hyperlipidemia',
  obesity_bmi_30_plus: 'obesity',
  depression_anxiety: 'depression_anxiety',
  asthma_copd: 'asthma_copd',
  heart_failure: 'heart_failure',
}

/** Payload HEDIS key → catalog key under healthcare.hedis.*. */
const HEDIS_KEYS: Record<string, string> = {
  diabetes_a1c_control_lt8: 'diabetes_a1c_control',
  blood_pressure_control: 'blood_pressure_control',
  breast_cancer_screening: 'breast_cancer_screening',
  colorectal_cancer_screening: 'colorectal_cancer_screening',
  flu_vaccination_rate: 'flu_vaccination',
  depression_screening: 'depression_screening',
}

const CMS_READMIT_THRESHOLD = 15.4

export default function PracticePulseSection() {
  const { t } = useLocale()
  const { data, loading, error, reload } = useApi<PopulationResponse>(
    '/api/healthcare/population',
  )

  if (loading) return <LoadingPane label={t('healthcare.loadingPulse')} />
  if (error || !data || data.error) {
    return (
      <Card title={t('healthcare.practicePulse')}>
        <ErrorPane
          message={error ?? data?.error ?? t('healthcare.noPopulationData')}
          onRetry={reload}
        />
      </Card>
    )
  }

  const panel = data.practice_panel ?? {}
  const sex = panel.sex_distribution ?? {}
  const util = data.utilization_metrics ?? {}

  const demoSub = [
    panel.average_age != null
      ? t('healthcare.avgAge', { n: panel.average_age.toFixed(1) })
      : null,
    sex.male && sex.female
      ? t('healthcare.sexSplit', { m: sex.male, f: sex.female })
      : null,
  ]
    .filter(Boolean)
    .join(' · ')

  const readmit = parsePct(util.readmission_rate_30d)
  const readmitAboveCms = readmit != null && readmit > CMS_READMIT_THRESHOLD

  const prevalence = Object.entries(data.chronic_disease_prevalence ?? {}).map(
    ([key, entry]) => ({
      name: CONDITION_KEYS[key]
        ? t(`healthcare.conditions.${CONDITION_KEYS[key]}`)
        : labelize(key),
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
      return {
        key,
        label: HEDIS_KEYS[key] ? t(`healthcare.hedis.${HEDIS_KEYS[key]}`) : labelize(key),
        performance,
        target,
        national,
        onTarget,
      }
    },
  )

  const opportunities = data.improvement_opportunities ?? []

  return (
    <section className="space-y-4 @container">
      <SectionHeader title={t('healthcare.practicePulse')} />

      {/* KPI row */}
      <div className="grid grid-cols-2 @xl:grid-cols-4 gap-3 @lg:gap-4">
        <StatCard
          title={t('healthcare.activePatients')}
          kpiKey="Active Patients"
          value={panel.total_active_patients?.toLocaleString() ?? '—'}
          icon={Users}
          sub={demoSub || undefined}
        />
        <StatCard
          title={t('healthcare.readmit30')}
          kpiKey="30d Readmit %"
          value={readmit != null ? `${readmit}%` : '—'}
          icon={Activity}
          sub={t('healthcare.cmsThreshold', { n: CMS_READMIT_THRESHOLD })}
          subClass={readmitAboveCms ? 'text-amber-400' : 'text-slate-400'}
        />
        <StatCard
          title={t('healthcare.edVisits')}
          kpiKey="ED Visits /1000"
          value={util.ed_visits_per_1000?.toLocaleString() ?? '—'}
          icon={Ambulance}
          sub={t('healthcare.perThousand')}
        />
        <StatCard
          title={t('healthcare.telehealth')}
          kpiKey="Telehealth %"
          value={util.telehealth_utilization ?? '—'}
          icon={Video}
          sub={t('healthcare.ofAllEncounters')}
        />
      </div>

      {/* HEDIS quality measures */}
      <Card title={t('healthcare.hedisMeasures')}>
        {measures.length === 0 ? (
          <p className="py-6 text-center text-sm text-slate-500">
            {t('healthcare.noQualityMeasures')}
          </p>
        ) : (
          <div className="p-4 @lg:p-5 grid grid-cols-1 @2xl:grid-cols-2 @5xl:grid-cols-3 gap-3 @lg:gap-4">
            {measures.map((m) => (
              <div
                key={m.key}
                className="rounded-lg border border-slate-800 bg-slate-950/40 p-4"
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="text-xs text-slate-400">{m.label}</span>
                  <StatusPill
                    tone={m.onTarget ? 'green' : 'amber'}
                    label={m.onTarget ? t('widgets.onTarget') : t('widgets.belowTarget')}
                  />
                </div>
                <div
                  className={`text-xl font-bold tabular-nums ${
                    m.onTarget ? 'text-green-400' : 'text-amber-400'
                  }`}
                >
                  {m.performance !== null ? `${m.performance}%` : '—'}
                </div>
                {/* Performance meter with target + national-average ticks */}
                <div className="relative mt-3 h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${m.onTarget ? 'bg-green-500' : 'bg-amber-500'}`}
                    style={{ width: `${Math.min(m.performance ?? 0, 100)}%` }}
                  />
                  {m.national !== null && (
                    <div
                      className="absolute top-0 h-full w-0.5 bg-slate-500"
                      style={{ left: `${Math.min(m.national, 100)}%` }}
                      title={t('healthcare.nationalAvgPct', { n: `${m.national}%` })}
                    />
                  )}
                  {m.target !== null && (
                    <div
                      className="absolute top-0 h-full w-0.5 bg-slate-300"
                      style={{ left: `${Math.min(m.target, 100)}%` }}
                      title={t('healthcare.targetPct', { n: `${m.target}%` })}
                    />
                  )}
                </div>
                <div className="flex justify-between text-[11px] text-slate-500 mt-1.5 tabular-nums">
                  <span>
                    {t('healthcare.targetPct', {
                      n: m.target !== null ? `${m.target}%` : '—',
                    })}
                  </span>
                  <span>
                    {t('healthcare.nationalAvgPct', {
                      n: m.national !== null ? `${m.national}%` : '—',
                    })}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Prevalence chart + improvement opportunities */}
      <div className="grid grid-cols-1 @3xl:grid-cols-[3fr_2fr] gap-3 @lg:gap-4">
        <Card title={t('healthcare.chronicPrevalence')}>
          <div className="p-4 @lg:p-5">
            {prevalence.length === 0 ? (
              <p className="py-6 text-center text-sm text-slate-500">
                {t('healthcare.noPrevalenceData')}
              </p>
            ) : (
              <ResponsiveContainer
                width="100%"
                height={Math.max(180, prevalence.length * 38)}
              >
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
                      t('healthcare.patientsTooltip', {
                        n: value.toLocaleString(),
                        rate: item?.payload?.rate ?? '',
                      }).replace(/ \(\)$/, ''),
                      t('healthcare.prevalence'),
                    ]}
                  />
                  <Bar dataKey="count" fill="#f43f5e" barSize={14} radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card title={t('healthcare.improvementOpportunities')}>
          {opportunities.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-500">
              {t('healthcare.noOpportunities')}
            </p>
          ) : (
            <ul className="p-2 @lg:p-3 divide-y divide-slate-800/70">
              {opportunities.map((opp, i) => (
                <li
                  key={`${opp.area ?? 'area'}-${i}`}
                  className="flex items-start justify-between gap-3 px-2 py-2.5"
                >
                  <div className="min-w-0">
                    <div className="text-sm text-white">{opp.area ?? '—'}</div>
                    {opp.gap && (
                      <div className="text-xs text-slate-400 mt-0.5">{opp.gap}</div>
                    )}
                  </div>
                  <StatusPill
                    tone={(opp.impact ?? '').toUpperCase() === 'HIGH' ? 'amber' : 'slate'}
                    label={(opp.impact ?? '—').toUpperCase()}
                  />
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </section>
  )
}
