import { useState } from 'react'
import {
  Boxes,
  PackageX,
  Percent,
  TrendingUp,
  Truck,
  Warehouse,
} from 'lucide-react'
import { useApi } from '../../lib/api'
import { Card, ErrorPane, LoadingPane, SimulatedBadge, StatCard } from '../finance/widgets'
import {
  AskAgentButton,
  DataTable,
  ForecastBand,
  LineTrend,
  MeterBar,
  SectionHeader,
  SeverityPill,
  StatusPill,
  deltaClass,
  fmtCompactUsd,
  fmtNum,
  fmtPct,
  fmtSignedPct,
  fmtUsd0,
  type Column,
} from '../common/widgets'
import type {
  DemandResponse,
  ForecastResponse,
  OverviewResponse,
  StockoutItem,
  StockoutReport,
} from './types'

const ACCENT = 'text-emerald-400'
const SERIES = '#34d399' // emerald-400
const SERIES_2 = '#38bdf8' // sky-400
const HOVER = 'hover:text-emerald-300'

// Real catalog SKUs from toolkit.retail_basis.CATALOG, not `SKU-1001`-style
// invention. The basis falls back to a synthetic "Product 1001 / Electronics /
// class B" for any unknown id, so the old picker looked fine while the stockout
// report beside it named SKU-ELEC-1001 "Wireless Earbuds" — the forecast card
// was describing a product that exists nowhere else in the app. One per
// category, and each is A-class, so the forecast has real velocity to show.
const SKU_CHOICES = [
  { sku: 'SKU-ELEC-1001', label: 'SKU-ELEC-1001 · Wireless Earbuds' },
  { sku: 'SKU-APRL-2001', label: 'SKU-APRL-2001 · Winter Jacket' },
  { sku: 'SKU-GROC-3001', label: 'SKU-GROC-3001 · Organic Coffee' },
  { sku: 'SKU-HOME-4001', label: 'SKU-HOME-4001 · Air Purifier' },
  { sku: 'SKU-SPRT-5001', label: 'SKU-SPRT-5001 · Running Shoes' },
] as const

export default function RetailDashboard() {
  const [sku, setSku] = useState<string>(SKU_CHOICES[0].sku)

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 @container">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">Retail Inventory</h2>
          <SimulatedBadge />
        </div>

        <NetworkSection />
        <StockoutSection />
        <DemandSection sku={sku} onSkuChange={setSku} />
      </div>
    </div>
  )
}

/* ------------------------------ network health ---------------------------- */

function NetworkSection() {
  const { data, loading, error, reload } = useApi<OverviewResponse>(
    '/api/retail/overview',
  )

  if (loading) return <LoadingPane label="Loading network health…" />
  if (error || !data || data.error) {
    return (
      <Card title="Network Health">
        <ErrorPane message={error ?? data?.error ?? 'No overview data'} onRetry={reload} />
      </Card>
    )
  }

  const overall = data.inventory?.overall ?? {}
  const categories = data.inventory?.summary ?? []
  const alerts = data.inventory?.alerts ?? []
  const abc = data.abc?.classification ?? {}
  const margins = data.margins?.overall ?? {}
  const risk = data.supplier_risk ?? {}

  const inStock = overall.avg_in_stock_rate ?? 0

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title="Network Health"
        accentClass={ACCENT}
        action={
          <AskAgentButton
            hoverClass={HOVER}
            prompt="Review our inventory position across all categories, then recommend the three highest-value replenishment or markdown actions."
          />
        }
      />

      <div className="grid grid-cols-2 @xl:grid-cols-4 gap-3 @lg:gap-4">
        <StatCard
          title="Total SKUs"
          value={fmtNum(overall.total_skus)}
          icon={Boxes}
          /* Excess is the share of the on-hand value above target — the number a
             merchandiser acts on. Only the gross total was shown, so $3.4M of
             trapped capital inside $14.5M on hand was invisible on this screen. */
          sub={
            overall.total_excess_value
              ? `${fmtCompactUsd(overall.total_inventory_value)} on hand · ${fmtCompactUsd(
                  overall.total_excess_value,
                )} excess`
              : `${fmtCompactUsd(overall.total_inventory_value)} on hand`
          }
        />
        <StatCard
          title="In-Stock Rate"
          value={fmtPct(inStock)}
          icon={Warehouse}
          sub="target 95%"
          subClass={inStock < 95 ? 'text-amber-400' : 'text-green-400'}
        />
        <StatCard
          title="Blended Margin"
          value={fmtPct(margins.blended_gross_margin)}
          icon={Percent}
          sub={`${fmtCompactUsd(margins.margin_improvement_opportunity)} opportunity`}
        />
        <StatCard
          title="Supply Chain Risk"
          value={risk.overall_supply_chain_risk ?? '—'}
          icon={Truck}
          /* The rating is a judgement over the whole roster, so the subtitle
             names how many suppliers were assessed. "4 tracked risks" described
             the length of the findings list, which reads as a supplier count. */
          sub={
            risk.suppliers_assessed
              ? `${fmtNum(risk.suppliers_assessed)} suppliers assessed`
              : `${(risk.top_risks ?? []).length} tracked risks`
          }
          subClass={
            (risk.overall_supply_chain_risk ?? '').toUpperCase() === 'LOW'
              ? 'text-green-400'
              : 'text-amber-400'
          }
        />
      </div>

      {alerts.length > 0 && (
        <div className="space-y-2">
          {alerts.map((alert, i) => (
            <div
              key={`${alert.type ?? 'alert'}-${i}`}
              className="flex items-start gap-3 rounded-xl border border-amber-800/50 bg-amber-950/30 px-4 py-3"
            >
              <SeverityPill severity={alert.severity} />
              <span className="text-sm text-amber-100">{alert.message ?? '—'}</span>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 @4xl:grid-cols-[3fr_2fr] gap-3 @lg:gap-4">
        <Card title="Inventory by Category">
          <DataTable
            columns={
              [
                {
                  header: 'Category',
                  className: 'text-white',
                  render: (row) => row.category ?? '—',
                },
                { header: 'SKUs', numeric: true, render: (row) => fmtNum(row.total_skus) },
                {
                  header: 'In stock',
                  numeric: true,
                  render: (row) => (
                    <span
                      className={
                        (row.in_stock_pct ?? 0) < 95 ? 'text-amber-400' : 'text-green-400'
                      }
                    >
                      {fmtPct(row.in_stock_pct)}
                    </span>
                  ),
                },
                {
                  header: 'Stockouts',
                  numeric: true,
                  render: (row) => fmtNum(row.stockout_skus),
                },
                {
                  header: 'Turns',
                  numeric: true,
                  render: (row) => row.inventory_turnover?.toFixed(1) ?? '—',
                },
                {
                  header: 'Value',
                  numeric: true,
                  className: 'text-white',
                  render: (row) => fmtCompactUsd(row.total_value),
                },
              ] as Array<Column<(typeof categories)[number]>>
            }
            rows={categories}
            rowKey={(row, i) => row.category ?? String(i)}
            empty="No category data"
          />
        </Card>

        <Card title="ABC Classification — fill rate vs target">
          {Object.keys(abc).length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-500">No ABC analysis</p>
          ) : (
            <ul className="p-4 @lg:p-5 space-y-4">
              {Object.entries(abc).map(([cls, entry]) => {
                const current = entry.current_fill_rate ?? 0
                const target = entry.target_fill_rate ?? 0
                const onTarget = current >= target
                return (
                  <li key={cls}>
                    <div className="flex items-baseline justify-between gap-2 mb-1.5">
                      <span className="text-sm font-semibold text-white">
                        Class {cls}
                        <span className="ml-2 font-normal text-xs text-slate-400 tabular-nums">
                          {fmtNum(entry.sku_count)} SKUs · {fmtPct(entry.revenue_pct)} of
                          revenue
                        </span>
                      </span>
                      <StatusPill
                        tone={onTarget ? 'green' : 'amber'}
                        label={onTarget ? 'On target' : 'Below target'}
                      />
                    </div>
                    <MeterBar
                      pct={current}
                      fillClass={onTarget ? 'bg-green-500' : 'bg-amber-500'}
                      ticks={[{ at: target, title: `target ${target}%` }]}
                    />
                    <div className="flex justify-between text-[11px] text-slate-500 mt-1 tabular-nums">
                      <span>fill {fmtPct(current)}</span>
                      <span>target {fmtPct(target)}</span>
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </Card>
      </div>
    </section>
  )
}

/* -------------------------------- stockouts ------------------------------- */

function StockoutSection() {
  const { data, loading, error, reload } = useApi<StockoutReport>(
    '/api/retail/stockouts',
  )

  const columns: Array<Column<StockoutItem>> = [
    {
      header: 'SKU',
      render: (row) => (
        <span className="font-mono text-xs text-white">{row.sku ?? '—'}</span>
      ),
    },
    { header: 'Product', render: (row) => row.product_name ?? '—' },
    {
      header: 'Class',
      render: (row) => (
        <StatusPill
          tone={row.abc_class === 'A' ? 'red' : row.abc_class === 'B' ? 'amber' : 'slate'}
          label={row.abc_class ?? '—'}
        />
      ),
    },
    {
      header: 'Days out',
      numeric: true,
      render: (row) => (
        <span className={(row.days_out_of_stock ?? 0) > 7 ? 'text-red-400' : ''}>
          {fmtNum(row.days_out_of_stock)}
        </span>
      ),
    },
    {
      header: 'Reorder',
      render: (row) => (
        <StatusPill
          tone={row.reorder_status === 'ON_ORDER' ? 'sky' : 'amber'}
          label={(row.reorder_status ?? '—').replace(/_/g, ' ')}
        />
      ),
    },
    {
      header: 'ETA',
      render: (row) => (
        <span className="tabular-nums text-slate-400">{row.eta ?? '—'}</span>
      ),
    },
    {
      header: 'Lost revenue',
      numeric: true,
      className: 'text-white',
      render: (row) => fmtUsd0(row.estimated_total_loss),
    },
  ]

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title="Stockouts"
        accentClass={ACCENT}
        action={
          <AskAgentButton
            hoverClass={HOVER}
            prompt="For our A-class stockouts, check current inventory and place expedited reorders where it is justified by the revenue impact."
          />
        }
      />

      {loading ? (
        <LoadingPane label="Loading stockouts…" />
      ) : error || !data || data.error ? (
        <Card title="Stockouts">
          <ErrorPane
            message={error ?? data?.error ?? 'No stockout data'}
            onRetry={reload}
          />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-3 @lg:gap-4">
            {/* The table below lists the tracked catalog SKUs that are out, not
                the whole network. Labelled "Active Stockouts" against a count of
                7, it sat beside a category breakdown totalling 314 — the same
                number under two names. Both are now stated, with the tile that
                names the table showing the table's own count. */}
            <StatCard
              title="Tracked Stockouts"
              value={fmtNum(data.total_stockouts)}
              icon={PackageX}
              sub={
                data.network_stockouts
                  ? `of ${fmtNum(data.network_stockouts)} network-wide`
                  : `${fmtNum(data.a_class_stockouts)} A-class`
              }
              subClass="text-slate-400"
            />
            <StatCard
              title="Revenue at Risk"
              value={fmtCompactUsd(data.total_revenue_impact)}
              icon={TrendingUp}
              sub="cumulative lost sales, tracked SKUs"
            />
            <StatCard
              title="A-Class Share"
              value={fmtPct(
                data.total_stockouts
                  ? ((data.a_class_stockouts ?? 0) / data.total_stockouts) * 100
                  : 0,
                0,
              )}
              icon={Boxes}
              sub={`${fmtNum(data.a_class_stockouts)} of ${fmtNum(data.total_stockouts)} tracked`}
              subClass={
                (data.a_class_stockouts ?? 0) > 0 ? 'text-red-400' : 'text-slate-400'
              }
            />
          </div>

          <Card title="Out-of-Stock Items">
            {data.scope && (
              <p className="text-xs text-slate-400 mb-3">{data.scope}</p>
            )}
            <DataTable
              columns={columns}
              rows={data.items ?? []}
              rowKey={(row, i) => row.sku ?? String(i)}
              empty="No stockouts — every SKU is in stock"
            />
          </Card>

          {data.recommendation && (
            <p className="text-xs text-slate-400 px-1">{data.recommendation}</p>
          )}
        </>
      )}
    </section>
  )
}

/* ---------------------------- demand + forecast --------------------------- */

function DemandSection({
  sku,
  onSkuChange,
}: {
  sku: string
  onSkuChange: (value: string) => void
}) {
  // quarter, not month: the backend derives weeks from the period, so "month"
  // yields a 4-point line — too few points to read as a trend.
  const demand = useApi<DemandResponse>(
    '/api/retail/demand?category=all&period=quarter',
  )
  const forecast = useApi<ForecastResponse>(`/api/retail/forecast?sku=${sku}&days=30`)

  const weekly = (demand.data?.weekly_data ?? []).map((w) => ({
    week: (w.week ?? '').replace(/^\d{4}-/, ''),
    units: w.units_sold ?? 0,
    revenue: w.revenue ?? 0,
  }))

  const points = (forecast.data?.forecasts ?? []).map((p) => ({
    date: (p.date ?? '').slice(5),
    predicted: p.predicted_units ?? 0,
    low: p.lower_bound ?? 0,
    // stacked band: the upper area sits on top of the lower bound
    band: Math.max((p.upper_bound ?? 0) - (p.lower_bound ?? 0), 0),
  }))

  const trends = demand.data?.trends ?? {}
  const accuracy = forecast.data?.accuracy_metrics ?? {}

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title="Demand & Forecast"
        accentClass={ACCENT}
        action={
          <AskAgentButton
            hoverClass={HOVER}
            prompt={`Forecast demand for ${sku} over the next 30 days and tell me whether current stock covers it — if not, auto-reorder.`}
          />
        }
      />

      <div className="grid grid-cols-1 @4xl:grid-cols-2 gap-3 @lg:gap-4">
        <Card
          title="Weekly Demand Trend — 12w (all categories)"
          action={
            trends.units_growth_pct != null ? (
              <span
                className={`text-xs tabular-nums ${deltaClass(trends.units_growth_pct)}`}
              >
                units {fmtSignedPct(trends.units_growth_pct)}
              </span>
            ) : undefined
          }
        >
          <div className="p-4 @lg:p-5">
            {demand.loading ? (
              <LoadingPane label="Loading demand…" />
            ) : demand.error || !demand.data || demand.data.error ? (
              <ErrorPane
                message={demand.error ?? demand.data?.error ?? 'No demand data'}
                onRetry={demand.reload}
              />
            ) : (
              <>
                <LineTrend
                  data={weekly}
                  xKey="week"
                  series={[
                    { key: 'units', color: SERIES, name: 'Units sold' },
                    // revenue runs ~100x units — its own axis, or it flatlines
                    {
                      key: 'revenue',
                      color: SERIES_2,
                      name: 'Revenue (USD)',
                      axis: 'right',
                      formatter: fmtCompactUsd,
                    },
                  ]}
                  yFormatter={fmtNum}
                />
                <div className="flex flex-wrap gap-x-5 gap-y-1 mt-3 text-[11px] text-slate-500 tabular-nums">
                  <span>
                    revenue{' '}
                    <span className={deltaClass(trends.revenue_growth_pct ?? 0)}>
                      {fmtSignedPct(trends.revenue_growth_pct)}
                    </span>
                  </span>
                  <span>
                    AOV{' '}
                    <span className={deltaClass(trends.aov_change_pct ?? 0)}>
                      {fmtSignedPct(trends.aov_change_pct)}
                    </span>
                  </span>
                  <span>seasonality {demand.data.seasonality_index ?? '—'}×</span>
                </div>
              </>
            )}
          </div>
        </Card>

        <Card
          title="SKU Demand Forecast"
          action={
            <select
              value={sku}
              onChange={(event) => onSkuChange(event.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200"
              aria-label="Forecast SKU"
            >
              {SKU_CHOICES.map((choice) => (
                <option key={choice.sku} value={choice.sku}>
                  {choice.label}
                </option>
              ))}
            </select>
          }
        >
          <div className="p-4 @lg:p-5">
            {forecast.loading ? (
              <LoadingPane label="Loading forecast…" />
            ) : forecast.error || !forecast.data || forecast.data.error ? (
              <ErrorPane
                message={forecast.error ?? forecast.data?.error ?? 'No forecast'}
                onRetry={forecast.reload}
              />
            ) : (
              <>
                <div className="flex flex-wrap items-baseline gap-x-5 gap-y-1 mb-3">
                  <span className="text-2xl font-bold text-white tabular-nums">
                    {fmtNum(forecast.data.total_predicted_demand)}
                  </span>
                  <span className="text-xs text-slate-400">
                    units over {forecast.data.forecast_period_days}d · avg{' '}
                    {forecast.data.avg_daily_demand}/day · peak{' '}
                    {forecast.data.peak_day}
                  </span>
                </div>
                <ForecastBand
                  data={points}
                  xKey="date"
                  lowKey="low"
                  highKey="band"
                  lineKey="predicted"
                  color={SERIES}
                />
                <div className="flex flex-wrap gap-x-5 gap-y-1 mt-2 text-[11px] text-slate-500 tabular-nums">
                  <span>MAPE {fmtPct(accuracy.mape)}</span>
                  <span>RMSE {accuracy.rmse ?? '—'}</span>
                  <span>bias {fmtSignedPct(accuracy.forecast_bias)}</span>
                </div>
                <p className="mt-2 text-[11px] text-slate-500">
                  {forecast.data.model}
                </p>
              </>
            )}
          </div>
        </Card>
      </div>
    </section>
  )
}
