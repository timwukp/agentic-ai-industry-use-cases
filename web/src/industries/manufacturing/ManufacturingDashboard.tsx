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
  const [equipmentId, setEquipmentId] = useState<string | null>(null)

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 @container">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">
            Manufacturing Maintenance
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
  const { data, loading, error, reload } = useApi<OverviewResponse>(
    '/api/manufacturing/overview',
  )

  if (loading) return <LoadingPane label="Loading plant status…" />
  if (error || !data || data.error) {
    return (
      <Card title="Plant Status">
        <ErrorPane message={error ?? data?.error ?? 'No overview data'} onRetry={reload} />
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
      header: 'Asset',
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
    { header: 'Dept', render: (row) => row.department ?? '—' },
    {
      header: 'Status',
      render: (row) => (
        <StatusPill tone={statusTone(row.status ?? '')} label={row.status ?? '—'} />
      ),
    },
    {
      header: 'Criticality',
      render: (row) => (
        <StatusPill
          tone={(row.criticality ?? '').toUpperCase() === 'HIGH' ? 'amber' : 'slate'}
          label={row.criticality ?? '—'}
        />
      ),
    },
    {
      header: 'Health',
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
      header: 'Next PM',
      render: (row) => (
        <span className="tabular-nums text-slate-400">
          {row.next_scheduled_maintenance ?? '—'}
        </span>
      ),
    },
  ]

  const alertColumns: Array<Column<EquipmentAlert>> = [
    {
      header: 'Severity',
      render: (row) => <SeverityPill severity={row.severity} />,
    },
    {
      header: 'Asset',
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
      header: 'Alert',
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
      header: 'Ack',
      render: (row) => (
        <StatusPill
          tone={row.acknowledged ? 'slate' : 'amber'}
          label={row.acknowledged ? 'ACK' : 'OPEN'}
        />
      ),
    },
  ]

  const scheduleColumns: Array<Column<ScheduleEntry>> = [
    {
      header: 'Date',
      render: (row) => (
        <span className="tabular-nums text-white">
          {row.date ?? '—'}
          <span className="block text-[11px] text-slate-500">
            {row.start_time ?? ''} · {row.duration_hours ?? 0}h
          </span>
        </span>
      ),
    },
    {
      header: 'Asset',
      render: (row) => (
        <span className="font-mono text-xs">{row.equipment_id ?? '—'}</span>
      ),
    },
    { header: 'Work', render: (row) => row.description ?? '—' },
    {
      header: 'Priority',
      render: (row) => (
        <StatusPill
          tone={(row.priority ?? '').toUpperCase() === 'HIGH' ? 'amber' : 'slate'}
          label={row.priority ?? '—'}
        />
      ),
    },
    { header: 'Tech', render: (row) => row.assigned_to ?? '—' },
  ]

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title="Plant Status"
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
          title="Fleet Health"
          value={avgHealth.toFixed(1)}
          icon={HeartPulse}
          sub={`${fmtNum(fleet.total_equipment)} assets · ${fmtNum(statusSummary.running)} running`}
          subClass={avgHealth < HEALTH_WARN ? 'text-amber-400' : 'text-slate-400'}
        />
        <StatCard
          title="Critical Alerts"
          value={fmtNum(counts.critical)}
          icon={AlertOctagon}
          sub={`${fmtNum(alerts.unacknowledged)} unacknowledged of ${fmtNum(alerts.total_alerts)}`}
          subClass={(counts.critical ?? 0) > 0 ? 'text-red-400' : 'text-slate-400'}
        />
        <StatCard
          title="PM Utilization"
          value={fmtPct(util.utilization_pct, 0)}
          icon={CalendarClock}
          sub={`${fmtNum(calendar.total_scheduled)} jobs · ${fmtNum(util.total_maintenance_hours)}h booked`}
        />
        <StatCard
          title="Parts Fill Rate"
          value={fmtPct(partsKpis.fill_rate_pct)}
          icon={Wrench}
          sub={`${fmtNum(parts.inventory_summary?.total_stockout_items)} stockouts · ${fmtCompactUsd(parts.inventory_summary?.total_inventory_value)}`}
          subClass={
            (partsKpis.fill_rate_pct ?? 100) < 95 ? 'text-amber-400' : 'text-slate-400'
          }
        />
      </div>

      <Card
        title="Equipment Fleet"
        action={
          <span className="text-[11px] text-slate-500">
            select an asset for prediction &amp; sensors
          </span>
        }
      >
        <DataTable
          columns={equipmentColumns}
          rows={equipment}
          rowKey={(row, i) => row.equipment_id ?? String(i)}
          empty="No equipment"
          maxHeight="max-h-96"
        />
      </Card>

      <div className="grid grid-cols-1 @4xl:grid-cols-2 gap-3 @lg:gap-4">
        <Card title="Active Alerts">
          <DataTable
            columns={alertColumns}
            rows={alerts.alerts ?? []}
            rowKey={(row, i) => row.alert_id ?? String(i)}
            empty="No active alerts"
          />
        </Card>

        <Card title="Maintenance Load by Week (hours)">
          <div className="p-4 @lg:p-5">
            {weekly.length === 0 ? (
              <p className="py-6 text-center text-sm text-slate-500">
                Nothing scheduled
              </p>
            ) : (
              <RankedBars
                data={weekly}
                categoryKey="week"
                valueKey="hours"
                color={SERIES}
                labelWidth={50}
                barSize={18}
                valueFormatter={(v) => `${v}h`}
              />
            )}
          </div>
        </Card>
      </div>

      <Card title="Maintenance Schedule (next 30 days)">
        <DataTable
          columns={scheduleColumns}
          rows={calendar.schedule ?? []}
          rowKey={(row, i) => row.schedule_id ?? String(i)}
          empty="Nothing scheduled"
          maxHeight="max-h-80"
        />
      </Card>
    </section>
  )
}

/* --------------------------- selected-asset detail ------------------------- */

function AssetSection({ equipmentId }: { equipmentId: string }) {
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
        title={`Asset Detail — ${equipmentId}`}
        accentClass={ACCENT}
        action={
          <AskAgentButton
            hoverClass={HOVER}
            prompt={`Analyze ${equipmentId}: check its failure prediction and vibration data against our ISO 10816 standard, then schedule maintenance and reserve the spare parts.`}
          />
        }
      />

      <div className="grid grid-cols-1 @4xl:grid-cols-2 gap-3 @lg:gap-4">
        <Card title="Failure Prediction">
          <div className="p-4 @lg:p-5">
            {detail.loading ? (
              <LoadingPane label="Loading prediction…" />
            ) : detail.error || !prediction ? (
              <ErrorPane
                message={detail.error ?? detail.data?.error ?? 'No prediction'}
                onRetry={detail.reload}
              />
            ) : (
              <>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-xs text-slate-400">Remaining useful life</div>
                    <div className="flex items-baseline gap-2">
                      <span
                        className={`text-3xl font-bold tabular-nums ${
                          rul < 14 ? 'text-red-400' : rul < 45 ? 'text-amber-400' : 'text-green-400'
                        }`}
                      >
                        {rul}
                      </span>
                      <span className="text-sm text-slate-400">days</span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5 tabular-nums">
                      CI {primary.confidence_interval?.lower_days ?? '—'}–
                      {primary.confidence_interval?.upper_days ?? '—'}d · est.{' '}
                      {primary.estimated_failure_date ?? '—'}
                    </div>
                  </div>
                  <SeverityPill severity={prediction.risk_level} />
                </div>

                <dl className="mt-4 space-y-2 text-sm">
                  <div className="flex justify-between gap-3">
                    <dt className="text-slate-400">Failure mode</dt>
                    <dd className="text-white text-right">
                      {(primary.failure_mode ?? '—').replace(/_/g, ' ')}
                      <span className="block text-[11px] text-slate-500">
                        {primary.affected_component ?? ''}
                      </span>
                    </dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-slate-400">Failure probability</dt>
                    <dd className="text-white tabular-nums">{fmtPct(prob)}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-slate-400">Degradation</dt>
                    <dd className="text-white tabular-nums text-right">
                      {fmtPct(degradation.current_degradation_pct)}
                      <span className="block text-[11px] text-slate-500">
                        {degradation.degradation_rate_per_day ?? '—'}%/day ·{' '}
                        {(degradation.acceleration ?? '').toLowerCase()}
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
                  {prediction.prediction_model} · accuracy{' '}
                  {fmtPct((prediction.model_accuracy ?? 0) * 100, 0)}
                </p>
              </>
            )}
          </div>
        </Card>

        <Card
          title={`Sensor — last 24h (${sensor.data?.unit ?? ''})`}
          action={
            <select
              value={sensorType}
              onChange={(event) => setSensorType(event.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200"
              aria-label="Sensor type"
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
              <LoadingPane label="Loading sensor data…" />
            ) : sensor.error || !sensor.data || sensor.data.error ? (
              <ErrorPane
                message={sensor.error ?? sensor.data?.error ?? 'No sensor data'}
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
                      name: sensor.data.sensor_type ?? 'value',
                    },
                  ]}
                  refLines={[
                    // Oil pressure fails LOW, so an unqualified "critical" label
                    // on a line the series sits above reads as if the asset were
                    // in breach when it is fine.
                    ...(thresholds.warning != null
                      ? [{ y: thresholds.warning, label: `warning ${breachSign}` }]
                      : []),
                    ...(thresholds.critical != null
                      ? [{ y: thresholds.critical, label: `critical ${breachSign}` }]
                      : []),
                  ]}
                  height={190}
                  unit={sensor.data.unit}
                />
                <div className="flex flex-wrap gap-x-5 gap-y-1 mt-3 text-[11px] text-slate-500 tabular-nums">
                  <span>mean {sensor.data.statistics?.mean ?? '—'}</span>
                  <span>
                    range {sensor.data.statistics?.min ?? '—'}–
                    {sensor.data.statistics?.max ?? '—'}
                  </span>
                  <span>σ {sensor.data.statistics?.std_dev ?? '—'}</span>
                  <span
                    className={
                      sensor.data.statistics?.trend === 'INCREASING'
                        ? 'text-amber-400'
                        : ''
                    }
                  >
                    trend {(sensor.data.statistics?.trend ?? '—').toLowerCase()}
                  </span>
                  {thresholds.critical != null ? (
                    // A healthy asset's series sits far from its limits, so the
                    // reference lines fall outside the auto-scaled domain and
                    // recharts clips them — the chart would then show no limits
                    // at all. Stating them here keeps them legible either way.
                    <span className={offChart ? '' : 'text-slate-600'}>
                      limit {breachSign} {thresholds.critical}
                      {sensor.data.unit ? ` ${sensor.data.unit}` : ''}
                      {offChart ? ' (off chart)' : ''}
                    </span>
                  ) : null}
                </div>
                {(thresholds.breaches_critical ?? 0) > 0 ? (
                  <p className="mt-2 rounded-lg border border-red-800/50 bg-red-950/30 px-3 py-2 text-xs text-red-200">
                    {thresholds.breaches_critical} critical threshold breach(es) in window
                  </p>
                ) : (thresholds.breaches_warning ?? 0) > 0 ? (
                  <p className="mt-2 rounded-lg border border-amber-800/50 bg-amber-950/30 px-3 py-2 text-xs text-amber-100">
                    {thresholds.breaches_warning} warning threshold breach(es) in window
                  </p>
                ) : null}
              </>
            )}
          </div>
        </Card>
      </div>

      <Card title="Reliability (last 12 months)">
        <div className="p-4 @lg:p-5">
          {detail.loading ? (
            <LoadingPane label="Loading reliability…" />
          ) : !reliability ? (
            <p className="py-6 text-center text-sm text-slate-500">
              No reliability metrics
            </p>
          ) : (
            <div className="grid grid-cols-2 @2xl:grid-cols-4 gap-3 @lg:gap-4">
              <StatCard
                title="OEE"
                value={fmtPct(oee.oee_pct)}
                icon={Gauge}
                sub={`${oee.oee_class ?? ''} · industry ${fmtPct(benchmarks.industry_avg_oee, 0)}`}
                subClass={
                  (benchmarks.vs_industry_oee ?? 0) >= 0
                    ? 'text-green-400'
                    : 'text-amber-400'
                }
              />
              <StatCard
                title="MTBF"
                value={`${fmtNum(metrics.mtbf_hours)}h`}
                icon={Activity}
                sub={`${metrics.mtbf_days ?? '—'} days between failures`}
              />
              <StatCard
                title="MTTR"
                value={`${metrics.mttr_hours ?? '—'}h`}
                icon={Wrench}
                sub={`${fmtNum(failures.total_failures_12m)} failures / 12mo`}
              />
              <StatCard
                title="Unplanned Downtime"
                value={fmtPct(failures.unplanned_downtime_pct)}
                icon={AlertOctagon}
                // The breakdown hours ARE the unplanned share, so labelling them
                // "total" contradicted the percentage above them; the total is
                // breakdown + planned.
                sub={`${fmtNum(failures.total_downtime_hours)}h breakdown of ${fmtNum(
                  (failures.total_downtime_hours ?? 0) +
                    (failures.planned_downtime_hours ?? 0),
                )}h`}
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
                {fmtNum(failures.total_failures_12m)} failures by mode
              </p>
              <ul className="space-y-1.5">
                {(failures.top_failure_modes ?? []).map((mode) => (
                  <li
                    key={mode.mode}
                    className="flex items-baseline justify-between gap-3 text-xs"
                  >
                    <span className="text-slate-300">{mode.mode}</span>
                    <span className="tabular-nums text-slate-500">
                      {mode.count}× · {mode.avg_repair_hours}h avg repair
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
