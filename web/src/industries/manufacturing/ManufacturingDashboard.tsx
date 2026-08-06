import { useState } from 'react'
import {
  Activity,
  AlertOctagon,
  CalendarClock,
  Gauge,
  HeartPulse,
  Wrench,
} from 'lucide-react'
import { useApi } from '../../lib/api'
import { useLocale } from '../../i18n/LocaleContext'
import { Card, ErrorPane, LoadingPane, SimulatedBadge, StatCard } from '../finance/widgets'
import {
  AskAgentButton,
  DataTable,
  LineTrend,
  MeterBar,
  RankedBars,
  SectionHeader,
  SeverityPill,
  StatusPill,
  fmtCompactUsd,
  fmtNum,
  fmtPct,
  type Column,
} from '../common/widgets'
import type {
  EquipmentAlert,
  EquipmentDetailResponse,
  EquipmentRow,
  OverviewResponse,
  ScheduleEntry,
  SensorResponse,
} from './types'
import { SENSOR_TYPES } from './types'

const ACCENT = 'text-amber-400'
const SERIES = '#fbbf24' // amber-400
const HOVER = 'hover:text-amber-300'

/** Below this health score an asset needs intervention. */
const HEALTH_WARN = 70
const HEALTH_CRIT = 50

function healthClass(score: number) {
  if (score < HEALTH_CRIT) return 'text-red-400'
  if (score < HEALTH_WARN) return 'text-amber-400'
  return 'text-green-400'
}

function healthFill(score: number) {
  if (score < HEALTH_CRIT) return 'bg-red-500'
  if (score < HEALTH_WARN) return 'bg-amber-500'
  return 'bg-green-500'
}

function statusTone(status: string) {
  const s = status.toUpperCase()
  if (s === 'STOPPED' || s === 'FAILED') return 'red' as const
  if (s === 'DEGRADED') return 'amber' as const
  if (s === 'RUNNING') return 'green' as const
  return 'slate' as const
}

export default function ManufacturingDashboard() {
  const { t } = useLocale()
  const [equipmentId, setEquipmentId] = useState<string | null>(null)

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 @container">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">
            {t('manufacturing.heading')}
          </h2>
          <SimulatedBadge />
        </div>

        <PlantSection
          selectedId={equipmentId}
          onSelect={setEquipmentId}
        />
        {equipmentId && <AssetSection equipmentId={equipmentId} />}
      </div>
    </div>
  )
}

/* ------------------------------- plant overview ---------------------------- */

function PlantSection({
  selectedId,
  onSelect,
}: {
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  const { t } = useLocale()
  const { data, loading, error, reload } = useApi<OverviewResponse>(
    '/api/manufacturing/overview',
  )

  if (loading) return <LoadingPane label={t('manufacturing.loadingPlant')} />
  if (error || !data || data.error) {
    return (
      <Card title={t('manufacturing.plantStatus')}>
        <ErrorPane
          message={error ?? data?.error ?? t('manufacturing.noOverviewData')}
          onRetry={reload}
        />
      </Card>
    )
  }

  const fleet = data.fleet ?? {}
  const alerts = data.alerts ?? {}
  const counts = alerts.severity_counts ?? {}
  const calendar = data.calendar ?? {}
  const util = calendar.resource_utilization ?? {}
  const parts = data.parts ?? {}
  const partsKpis = parts.kpis ?? {}
  const statusSummary = fleet.status_summary ?? {}

  const equipment = fleet.equipment ?? []
  const avgHealth = fleet.avg_health_score ?? 0

  const weekly = Object.entries(calendar.weekly_capacity ?? {}).map(([week, entry]) => ({
    week: week.replace('Week ', 'W'),
    hours: entry.maintenance_hours ?? 0,
    events: entry.events ?? 0,
  }))

  const equipmentColumns: Array<Column<EquipmentRow>> = [
    {
      header: t('manufacturing.colAsset'),
      render: (row) => (
        <button
          type="button"
          onClick={() => row.equipment_id && onSelect(row.equipment_id)}
          className={`text-left hover:underline ${
            selectedId === row.equipment_id ? 'text-amber-300' : 'text-white'
          }`}
        >
          <span className="font-mono text-xs">{row.equipment_id ?? '—'}</span>
          <span className="block text-[11px] text-slate-500">{row.name ?? ''}</span>
        </button>
      ),
    },
    { header: t('manufacturing.colDept'), render: (row) => row.department ?? '—' },
    {
      header: t('manufacturing.colStatus'),
      render: (row) => (
        <StatusPill tone={statusTone(row.status ?? '')} label={row.status ?? '—'} />
      ),
    },
    {
      header: t('manufacturing.colCriticality'),
      render: (row) => (
        <StatusPill
          tone={(row.criticality ?? '').toUpperCase() === 'HIGH' ? 'amber' : 'slate'}
          label={row.criticality ?? '—'}
        />
      ),
    },
    {
      header: t('manufacturing.colHealth'),
      numeric: true,
      render: (row) => {
        const score = row.health_score ?? 0
        return (
          <div className="inline-flex items-center gap-2 w-32 justify-end">
            <span className={`tabular-nums ${healthClass(score)}`}>
              {score.toFixed(1)}
            </span>
            <span className="w-14">
              <MeterBar pct={score} fillClass={healthFill(score)} />
            </span>
          </div>
        )
      },
    },
    {
      header: t('manufacturing.colNextPm'),
      render: (row) => (
        <span className="tabular-nums text-slate-400">
          {row.next_scheduled_maintenance ?? '—'}
        </span>
      ),
    },
  ]

  const alertColumns: Array<Column<EquipmentAlert>> = [
    {
      header: t('manufacturing.colSeverity'),
      render: (row) => <SeverityPill severity={row.severity} />,
    },
    {
      header: t('manufacturing.colAsset'),
      render: (row) => (
        <button
          type="button"
          onClick={() => row.equipment_id && onSelect(row.equipment_id)}
          className="font-mono text-xs text-white hover:underline"
        >
          {row.equipment_id ?? '—'}
        </button>
      ),
    },
    {
      header: t('manufacturing.colAlert'),
      render: (row) => (
        <div className="min-w-0">
          <div className="text-slate-200">{row.message ?? '—'}</div>
          {row.action && (
            <div className="text-[11px] text-slate-500 mt-0.5">{row.action}</div>
          )}
        </div>
      ),
    },
    {
      header: t('manufacturing.colAck'),
      render: (row) => (
        <StatusPill
          tone={row.acknowledged ? 'slate' : 'amber'}
          label={row.acknowledged ? t('manufacturing.pillAck') : t('manufacturing.pillOpen')}
        />
      ),
    },
  ]

  const scheduleColumns: Array<Column<ScheduleEntry>> = [
    {
      header: t('manufacturing.colDate'),
      render: (row) => (
        <span className="tabular-nums text-white">
          {row.date ?? '—'}
          <span className="block text-[11px] text-slate-500">
            {row.start_time ?? ''} ·{' '}
            {t('manufacturing.hoursSuffix', { n: row.duration_hours ?? 0 })}
          </span>
        </span>
      ),
    },
    {
      header: t('manufacturing.colAsset'),
      render: (row) => (
        <span className="font-mono text-xs">{row.equipment_id ?? '—'}</span>
      ),
    },
    { header: t('manufacturing.colWork'), render: (row) => row.description ?? '—' },
    {
      header: t('manufacturing.colPriority'),
      render: (row) => (
        <StatusPill
          tone={(row.priority ?? '').toUpperCase() === 'HIGH' ? 'amber' : 'slate'}
          label={row.priority ?? '—'}
        />
      ),
    },
    { header: t('manufacturing.colTech'), render: (row) => row.assigned_to ?? '—' },
  ]

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title={t('manufacturing.plantStatus')}
        accentClass={ACCENT}
        action={
          <AskAgentButton
            hoverClass={HOVER}
            prompt="Review the critical equipment alerts and the assets below a 50 health score, then generate work orders for the ones that cannot wait."
          />
        }
      />

      <div className="grid grid-cols-2 @xl:grid-cols-4 gap-3 @lg:gap-4">
        <StatCard
          title={t('manufacturing.fleetHealth')}
          kpiKey="Fleet Health"
          value={avgHealth.toFixed(1)}
          icon={HeartPulse}
          sub={t('manufacturing.assetsRunning', {
            n: fmtNum(fleet.total_equipment),
            running: fmtNum(statusSummary.running),
          })}
          subClass={avgHealth < HEALTH_WARN ? 'text-amber-400' : 'text-slate-400'}
        />
        <StatCard
          title={t('manufacturing.criticalAlerts')}
          kpiKey="Critical Alerts"
          value={fmtNum(counts.critical)}
          icon={AlertOctagon}
          sub={t('manufacturing.unacknowledgedOf', {
            n: fmtNum(alerts.unacknowledged),
            total: fmtNum(alerts.total_alerts),
          })}
          subClass={(counts.critical ?? 0) > 0 ? 'text-red-400' : 'text-slate-400'}
        />
        <StatCard
          title={t('manufacturing.pmUtilization')}
          kpiKey="PM Utilization"
          value={fmtPct(util.utilization_pct, 0)}
          icon={CalendarClock}
          sub={t('manufacturing.jobsBooked', {
            n: fmtNum(calendar.total_scheduled),
            hours: fmtNum(util.total_maintenance_hours),
          })}
        />
        <StatCard
          title={t('manufacturing.partsFillRate')}
          kpiKey="Parts Fill Rate"
          value={fmtPct(partsKpis.fill_rate_pct)}
          icon={Wrench}
          sub={t('manufacturing.stockoutsAmount', {
            n: fmtNum(parts.inventory_summary?.total_stockout_items),
            amount: fmtCompactUsd(parts.inventory_summary?.total_inventory_value),
          })}
          subClass={
            (partsKpis.fill_rate_pct ?? 100) < 95 ? 'text-amber-400' : 'text-slate-400'
          }
        />
      </div>

      <Card
        title={t('manufacturing.equipmentFleet')}
        action={
          <span className="text-[11px] text-slate-500">
            {t('manufacturing.selectAssetHint')}
          </span>
        }
      >
        <DataTable
          columns={equipmentColumns}
          rows={equipment}
          rowKey={(row, i) => row.equipment_id ?? String(i)}
          empty={t('manufacturing.noEquipment')}
          maxHeight="max-h-96"
        />
      </Card>

      <div className="grid grid-cols-1 @4xl:grid-cols-2 gap-3 @lg:gap-4">
        <Card title={t('manufacturing.activeAlerts')}>
          <DataTable
            columns={alertColumns}
            rows={alerts.alerts ?? []}
            rowKey={(row, i) => row.alert_id ?? String(i)}
            empty={t('manufacturing.noActiveAlerts')}
          />
        </Card>

        <Card title={t('manufacturing.maintenanceLoad')}>
          <div className="p-4 @lg:p-5">
            {weekly.length === 0 ? (
              <p className="py-6 text-center text-sm text-slate-500">
                {t('manufacturing.nothingScheduled')}
              </p>
            ) : (
              <RankedBars
                data={weekly}
                categoryKey="week"
                valueKey="hours"
                color={SERIES}
                labelWidth={50}
                barSize={18}
                valueFormatter={(v) => t('manufacturing.hoursSuffix', { n: v })}
              />
            )}
          </div>
        </Card>
      </div>

      <Card title={t('manufacturing.maintenanceSchedule')}>
        <DataTable
          columns={scheduleColumns}
          rows={calendar.schedule ?? []}
          rowKey={(row, i) => row.schedule_id ?? String(i)}
          empty={t('manufacturing.nothingScheduled')}
          maxHeight="max-h-80"
        />
      </Card>
    </section>
  )
}

/* --------------------------- selected-asset detail ------------------------- */

function AssetSection({ equipmentId }: { equipmentId: string }) {
  const { t } = useLocale()
  const [sensorType, setSensorType] = useState<string>(SENSOR_TYPES[0])
  const detail = useApi<EquipmentDetailResponse>(
    `/api/manufacturing/equipment?equipmentId=${equipmentId}`,
  )
  const sensor = useApi<SensorResponse>(
    `/api/manufacturing/sensor?equipmentId=${equipmentId}&sensorType=${sensorType}&hours=24`,
  )

  const prediction = detail.data?.prediction
  const primary = prediction?.primary_prediction ?? {}
  const degradation = prediction?.degradation_trend ?? {}
  const reliability = detail.data?.reliability
  const oee = reliability?.oee_breakdown ?? {}
  const metrics = reliability?.reliability_metrics ?? {}
  const benchmarks = reliability?.benchmarks ?? {}
  const failures = reliability?.failure_history ?? {}

  const readings = (sensor.data?.readings ?? []).map((r) => ({
    time: (r.timestamp ?? '').slice(11, 16),
    value: r.value ?? 0,
  }))
  const thresholds = sensor.data?.thresholds ?? {}
  // "below 2.0 bar" is the fault for oil pressure, "above 11.0 mm/s" for the rest
  const breachSign = thresholds.breach_direction === 'BELOW' ? '↓' : '↑'
  // Whether the critical line lies outside the plotted data's own span, in which
  // case recharts' auto domain drops it and the caption has to carry the number.
  const seriesMax = readings.length ? Math.max(...readings.map((r) => r.value)) : 0
  const seriesMin = readings.length ? Math.min(...readings.map((r) => r.value)) : 0
  const offChart =
    thresholds.critical != null &&
    (thresholds.breach_direction === 'BELOW'
      ? thresholds.critical < seriesMin
      : thresholds.critical > seriesMax)

  const rul = primary.remaining_useful_life_days ?? 0
  const prob = (primary.failure_probability ?? 0) * 100

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title={t('manufacturing.assetDetail', { id: equipmentId })}
        accentClass={ACCENT}
        action={
          <AskAgentButton
            hoverClass={HOVER}
            prompt={`Analyze ${equipmentId}: check its failure prediction and vibration data against our ISO 10816 standard, then schedule maintenance and reserve the spare parts.`}
          />
        }
      />

      <div className="grid grid-cols-1 @4xl:grid-cols-2 gap-3 @lg:gap-4">
        <Card title={t('manufacturing.failurePrediction')}>
          <div className="p-4 @lg:p-5">
            {detail.loading ? (
              <LoadingPane label={t('manufacturing.loadingPrediction')} />
            ) : detail.error || !prediction ? (
              <ErrorPane
                message={detail.error ?? detail.data?.error ?? t('manufacturing.noPrediction')}
                onRetry={detail.reload}
              />
            ) : (
              <>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-xs text-slate-400">
                      {t('manufacturing.remainingUsefulLife')}
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span
                        className={`text-3xl font-bold tabular-nums ${
                          rul < 14 ? 'text-red-400' : rul < 45 ? 'text-amber-400' : 'text-green-400'
                        }`}
                      >
                        {rul}
                      </span>
                      <span className="text-sm text-slate-400">
                        {t('manufacturing.days')}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5 tabular-nums">
                      {t('manufacturing.ciEst', {
                        low: primary.confidence_interval?.lower_days ?? '—',
                        high: primary.confidence_interval?.upper_days ?? '—',
                        date: primary.estimated_failure_date ?? '—',
                      })}
                    </div>
                  </div>
                  <SeverityPill severity={prediction.risk_level} />
                </div>

                <dl className="mt-4 space-y-2 text-sm">
                  <div className="flex justify-between gap-3">
                    <dt className="text-slate-400">{t('manufacturing.failureMode')}</dt>
                    <dd className="text-white text-right">
                      {(primary.failure_mode ?? '—').replace(/_/g, ' ')}
                      <span className="block text-[11px] text-slate-500">
                        {primary.affected_component ?? ''}
                      </span>
                    </dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-slate-400">
                      {t('manufacturing.failureProbability')}
                    </dt>
                    <dd className="text-white tabular-nums">{fmtPct(prob)}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-slate-400">{t('manufacturing.degradation')}</dt>
                    <dd className="text-white tabular-nums text-right">
                      {fmtPct(degradation.current_degradation_pct)}
                      <span className="block text-[11px] text-slate-500">
                        {t('manufacturing.degradationRate', {
                          rate: degradation.degradation_rate_per_day ?? '—',
                          accel: (degradation.acceleration ?? '').toLowerCase(),
                        })}
                      </span>
                    </dd>
                  </div>
                </dl>

                <MeterBar
                  pct={degradation.current_degradation_pct ?? 0}
                  fillClass={
                    (degradation.current_degradation_pct ?? 0) > 70
                      ? 'bg-red-500'
                      : 'bg-amber-500'
                  }
                />

                {(prediction.contributing_factors ?? []).length > 0 && (
                  <ul className="mt-4 space-y-1.5">
                    {(prediction.contributing_factors ?? []).map((f, i) => (
                      <li
                        key={`${f.factor ?? 'factor'}-${i}`}
                        className="flex items-center justify-between gap-3 text-xs"
                      >
                        <span className="text-slate-300">{f.factor ?? '—'}</span>
                        <SeverityPill severity={f.impact} />
                      </li>
                    ))}
                  </ul>
                )}

                {prediction.recommended_action && (
                  <p className="mt-4 rounded-lg border border-amber-800/50 bg-amber-950/30 px-3 py-2 text-xs text-amber-100">
                    {prediction.recommended_action}
                  </p>
                )}
                <p className="mt-2 text-[11px] text-slate-500">
                  {t('manufacturing.modelAccuracy', {
                    model: prediction.prediction_model ?? '—',
                    p: fmtPct((prediction.model_accuracy ?? 0) * 100, 0),
                  })}
                </p>
              </>
            )}
          </div>
        </Card>

        <Card
          title={t('manufacturing.sensorTitle', { unit: sensor.data?.unit ?? '' })}
          action={
            <select
              value={sensorType}
              onChange={(event) => setSensorType(event.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200"
              aria-label={t('manufacturing.sensorTypeLabel')}
            >
              {SENSOR_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          }
        >
          <div className="p-4 @lg:p-5">
            {sensor.loading ? (
              <LoadingPane label={t('manufacturing.loadingSensor')} />
            ) : sensor.error || !sensor.data || sensor.data.error ? (
              <ErrorPane
                message={sensor.error ?? sensor.data?.error ?? t('manufacturing.noSensorData')}
                onRetry={sensor.reload}
              />
            ) : (
              <>
                <LineTrend
                  data={readings}
                  xKey="time"
                  series={[
                    {
                      key: 'value',
                      color: SERIES,
                      name: sensor.data.sensor_type ?? t('manufacturing.valueFallback'),
                    },
                  ]}
                  refLines={[
                    // Oil pressure fails LOW, so an unqualified "critical" label
                    // on a line the series sits above reads as if the asset were
                    // in breach when it is fine.
                    ...(thresholds.warning != null
                      ? [
                          {
                            y: thresholds.warning,
                            label: t('manufacturing.warningSign', { sign: breachSign }),
                          },
                        ]
                      : []),
                    ...(thresholds.critical != null
                      ? [
                          {
                            y: thresholds.critical,
                            label: t('manufacturing.criticalSign', { sign: breachSign }),
                          },
                        ]
                      : []),
                  ]}
                  height={190}
                  unit={sensor.data.unit}
                />
                <div className="flex flex-wrap gap-x-5 gap-y-1 mt-3 text-[11px] text-slate-500 tabular-nums">
                  <span>
                    {t('manufacturing.meanLegend', {
                      n: sensor.data.statistics?.mean ?? '—',
                    })}
                  </span>
                  <span>
                    {t('manufacturing.rangeLegend', {
                      min: sensor.data.statistics?.min ?? '—',
                      max: sensor.data.statistics?.max ?? '—',
                    })}
                  </span>
                  <span>
                    {t('manufacturing.sigmaLegend', {
                      n: sensor.data.statistics?.std_dev ?? '—',
                    })}
                  </span>
                  <span
                    className={
                      sensor.data.statistics?.trend === 'INCREASING'
                        ? 'text-amber-400'
                        : ''
                    }
                  >
                    {t('manufacturing.trendLegend', {
                      t: (sensor.data.statistics?.trend ?? '—').toLowerCase(),
                    })}
                  </span>
                  {thresholds.critical != null ? (
                    // A healthy asset's series sits far from its limits, so the
                    // reference lines fall outside the auto-scaled domain and
                    // recharts clips them — the chart would then show no limits
                    // at all. Stating them here keeps them legible either way.
                    <span className={offChart ? '' : 'text-slate-600'}>
                      {offChart
                        ? t('manufacturing.limitOffChart', {
                            sign: breachSign,
                            n: thresholds.critical,
                            unit: sensor.data.unit ?? '',
                          })
                        : t('manufacturing.limitOnChart', {
                            sign: breachSign,
                            n: thresholds.critical,
                            unit: sensor.data.unit ?? '',
                          })}
                    </span>
                  ) : null}
                </div>
                {(thresholds.breaches_critical ?? 0) > 0 ? (
                  <p className="mt-2 rounded-lg border border-red-800/50 bg-red-950/30 px-3 py-2 text-xs text-red-200">
                    {t('manufacturing.criticalBreaches', {
                      n: thresholds.breaches_critical ?? 0,
                    })}
                  </p>
                ) : (thresholds.breaches_warning ?? 0) > 0 ? (
                  <p className="mt-2 rounded-lg border border-amber-800/50 bg-amber-950/30 px-3 py-2 text-xs text-amber-100">
                    {t('manufacturing.warningBreaches', {
                      n: thresholds.breaches_warning ?? 0,
                    })}
                  </p>
                ) : null}
              </>
            )}
          </div>
        </Card>
      </div>

      <Card title={t('manufacturing.reliability')}>
        <div className="p-4 @lg:p-5">
          {detail.loading ? (
            <LoadingPane label={t('manufacturing.loadingReliability')} />
          ) : !reliability ? (
            <p className="py-6 text-center text-sm text-slate-500">
              {t('manufacturing.noReliabilityMetrics')}
            </p>
          ) : (
            <div className="grid grid-cols-2 @2xl:grid-cols-4 gap-3 @lg:gap-4">
              <StatCard
                title={t('manufacturing.oee')}
                kpiKey="OEE"
                value={fmtPct(oee.oee_pct)}
                icon={Gauge}
                sub={t('manufacturing.industryAvg', {
                  cls: oee.oee_class ?? '',
                  p: fmtPct(benchmarks.industry_avg_oee, 0),
                })}
                subClass={
                  (benchmarks.vs_industry_oee ?? 0) >= 0
                    ? 'text-green-400'
                    : 'text-amber-400'
                }
              />
              <StatCard
                title={t('manufacturing.mtbf')}
                kpiKey="MTBF"
                value={t('manufacturing.hoursSuffix', { n: fmtNum(metrics.mtbf_hours) })}
                icon={Activity}
                sub={t('manufacturing.daysBetweenFailures', {
                  n: metrics.mtbf_days ?? '—',
                })}
              />
              <StatCard
                title={t('manufacturing.mttr')}
                kpiKey="MTTR"
                value={t('manufacturing.hoursSuffix', { n: metrics.mttr_hours ?? '—' })}
                icon={Wrench}
                sub={t('manufacturing.failuresPer12mo', {
                  n: fmtNum(failures.total_failures_12m),
                })}
              />
              <StatCard
                title={t('manufacturing.unplannedDowntime')}
                kpiKey="Unplanned Downtime"
                value={fmtPct(failures.unplanned_downtime_pct)}
                icon={AlertOctagon}
                // The breakdown hours ARE the unplanned share, so labelling them
                // "total" contradicted the percentage above them; the total is
                // breakdown + planned.
                sub={t('manufacturing.breakdownOf', {
                  n: fmtNum(failures.total_downtime_hours),
                  total: fmtNum(
                    (failures.total_downtime_hours ?? 0) +
                      (failures.planned_downtime_hours ?? 0),
                  ),
                })}
                subClass={
                  (failures.unplanned_downtime_pct ?? 0) > 50
                    ? 'text-amber-400'
                    : 'text-slate-400'
                }
              />
            </div>
          )}
          {(failures.top_failure_modes ?? []).length > 0 ? (
            <div className="mt-4 border-t border-slate-800 pt-3">
              <p className="mb-2 text-[11px] uppercase tracking-wide text-slate-500">
                {t('manufacturing.failuresByMode', {
                  n: fmtNum(failures.total_failures_12m),
                })}
              </p>
              <ul className="space-y-1.5">
                {(failures.top_failure_modes ?? []).map((mode) => (
                  <li
                    key={mode.mode}
                    className="flex items-baseline justify-between gap-3 text-xs"
                  >
                    <span className="text-slate-300">{mode.mode}</span>
                    <span className="tabular-nums text-slate-500">
                      {t('manufacturing.avgRepair', {
                        n: mode.count ?? '—',
                        hours: mode.avg_repair_hours ?? '—',
                      })}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      </Card>
    </section>
  )
}
