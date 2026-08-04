import { useState } from 'react'
import {
  Building2,
  CalendarDays,
  DollarSign,
  Home,
  LineChart as LineChartIcon,
  Scale,
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
  Comparable,
  ComparablesResponse,
  Listing,
  ListingsResponse,
  MarketResponse,
} from './types'
import { MARKETS } from './types'

const ACCENT = 'text-cyan-400'
const SERIES = '#22d3ee' // cyan-400
// not sky-400 here: adjacent to cyan on the wheel, so the two price-history
// lines were indistinguishable. violet-400 reads apart at chart line weight.
const SERIES_2 = '#a78bfa' // violet-400
const HOVER = 'hover:text-cyan-300'

/** A balanced market sits near six months of supply; below that favours sellers. */
const BALANCED_MONTHS_SUPPLY = 6

const fmtK = (n: number) => `${Math.round(n / 1000)}k`

export default function RealEstateDashboard() {
  const [zipcode, setZipcode] = useState<string>(MARKETS[0].zipcode)
  const [subject, setSubject] = useState<string | null>(null)

  // switching markets invalidates the comp subject picked in the old market
  const selectMarket = (next: string) => {
    setZipcode(next)
    setSubject(null)
  }

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 @container">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">
            Real Estate Valuation
          </h2>
          <div className="flex items-center gap-3">
            <select
              value={zipcode}
              onChange={(event) => selectMarket(event.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200"
              aria-label="Market"
            >
              {MARKETS.map((market) => (
                <option key={market.zipcode} value={market.zipcode}>
                  {market.label}
                </option>
              ))}
            </select>
            <SimulatedBadge />
          </div>
        </div>

        <MarketSection zipcode={zipcode} />
        <ListingsSection
          zipcode={zipcode}
          subject={subject}
          onSelectSubject={setSubject}
        />
        {subject && <ComparablesSection address={subject} />}
      </div>
    </div>
  )
}

/* ------------------------- market pulse + trend + forecast ----------------- */

function MarketSection({ zipcode }: { zipcode: string }) {
  const { data, loading, error, reload } = useApi<MarketResponse>(
    `/api/realestate/market?zipcode=${zipcode}`,
  )

  if (loading) return <LoadingPane label="Loading market conditions…" />
  if (error || !data || data.error) {
    return (
      <Card title="Market Pulse">
        <ErrorPane message={error ?? data?.error ?? 'No market data'} onRetry={reload} />
      </Card>
    )
  }

  const snapshot = data.conditions?.market_snapshot ?? {}
  const priceTrends = data.conditions?.price_trends ?? {}
  const indicators = data.conditions?.market_indicators ?? {}
  const propertyTypes = data.conditions?.property_types ?? {}

  const history = (data.trends?.trends ?? []).map((point) => ({
    month: (point.date ?? '').replace(/^\d{2}(\d{2})-/, "$1-"),
    price: point.median_sale_price ?? 0,
    sales: point.closed_sales ?? 0,
  }))
  const trendSummary = data.trends?.summary ?? {}

  const forecast = (data.forecast?.forecast ?? []).map((point) => ({
    month: (point.date ?? '').replace(/^\d{2}(\d{2})-/, "$1-"),
    projected: point.forecasted_median_price ?? 0,
    low: point.confidence_low ?? 0,
    // stacked band: the upper area sits on top of the low bound
    band: Math.max((point.confidence_high ?? 0) - (point.confidence_low ?? 0), 0),
  }))
  const forecastSummary = data.forecast?.summary ?? {}

  const yoy = priceTrends.year_over_year_pct ?? 0
  const supply = snapshot.months_of_supply ?? 0
  // months of supply as a share of a balanced market, for the meter
  const supplyPct = Math.min((supply / BALANCED_MONTHS_SUPPLY) * 100, 100)

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title="Market Pulse"
        accentClass={ACCENT}
        action={
          <AskAgentButton
            hoverClass={HOVER}
            prompt={`Summarize market conditions in ${zipcode} and tell me whether this is a good time to list or to buy, with the numbers behind it.`}
          />
        }
      />

      <div className="grid grid-cols-2 @xl:grid-cols-4 gap-3 @lg:gap-4">
        <StatCard
          title="Median Sale Price"
          value={fmtCompactUsd(snapshot.median_sale_price)}
          icon={DollarSign}
          sub={`YoY ${fmtSignedPct(yoy)}`}
          subClass={deltaClass(yoy)}
        />
        <StatCard
          title="Price / Sq Ft"
          value={
            snapshot.median_price_per_sqft != null
              ? `$${snapshot.median_price_per_sqft.toFixed(0)}`
              : '—'
          }
          icon={Home}
          /* The size this rate and the median price imply, so a reader can see
             the two tiles describe the same home. Drawn independently, $602/sqft
             beside a $440K median implied a 730 sqft median home and nothing on
             screen made that visible. */
          sub={
            snapshot.implied_median_sqft
              ? `${fmtNum(snapshot.implied_median_sqft)} sq ft median home`
              : `trend ${fmtSignedPct(priceTrends.price_per_sqft_trend)}`
          }
          subClass="text-slate-400"
        />
        <StatCard
          title="Median Days on Market"
          value={fmtNum(snapshot.median_days_on_market)}
          icon={CalendarDays}
          sub={`${fmtNum(snapshot.average_days_on_market)} day average`}
        />
        <StatCard
          title="Active Listings"
          value={fmtNum(snapshot.active_listings)}
          icon={Building2}
          sub={`${fmtNum(snapshot.pending_sales)} pending · ${fmtNum(
            snapshot.closed_sales_30d,
          )} closed 30d`}
        />
      </div>

      <div className="grid grid-cols-1 @4xl:grid-cols-[2fr_3fr] gap-3 @lg:gap-4">
        <Card
          title="Supply & Negotiating Position"
          action={
            indicators.market_type ? (
              <StatusPill
                tone={
                  /seller/i.test(indicators.market_type)
                    ? 'amber'
                    : /buyer/i.test(indicators.market_type)
                      ? 'sky'
                      : 'green'
                }
                label={indicators.market_type}
              />
            ) : undefined
          }
        >
          <div className="p-4 @lg:p-5 space-y-4">
            <div>
              <div className="flex items-baseline justify-between gap-2 mb-1.5">
                <span className="text-sm text-slate-300">Months of supply</span>
                <span className="text-sm font-semibold text-white tabular-nums">
                  {supply.toFixed(1)} mo
                </span>
              </div>
              <MeterBar
                pct={supplyPct}
                fillClass={supply < 3 ? 'bg-amber-500' : 'bg-green-500'}
                ticks={[{ at: 50, title: 'balanced market ≈ 6 months' }]}
              />
              <p className="mt-1 text-[11px] text-slate-500">
                Tick marks a balanced market at {BALANCED_MONTHS_SUPPLY} months; less
                supply means sellers hold the leverage.
              </p>
            </div>

            <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 text-xs">
              <Metric
                label="Sale-to-list ratio"
                value={
                  indicators.sale_to_list_ratio != null
                    ? indicators.sale_to_list_ratio.toFixed(3)
                    : '—'
                }
              />
              <Metric
                label="Sold over asking"
                value={fmtPct(indicators.pct_sold_over_asking)}
              />
              <Metric
                label="With price cut"
                value={fmtPct(indicators.pct_with_price_reduction)}
              />
              <Metric
                label="Avg price cut"
                value={fmtPct(indicators.avg_price_reduction_pct)}
              />
              <Metric
                label="Absorption rate"
                value={fmtPct(indicators.absorption_rate)}
              />
              <Metric
                label="New listings 30d"
                value={fmtNum(snapshot.new_listings_30d)}
              />
            </dl>

            {Object.keys(propertyTypes).length > 0 && (
              <div>
                <p className="text-xs text-slate-500 mb-2">Median price by type</p>
                <ul className="space-y-1.5">
                  {Object.entries(propertyTypes).map(([type, entry]) => (
                    <li
                      key={type}
                      className="flex items-baseline justify-between gap-2 text-xs"
                    >
                      <span className="text-slate-300 capitalize">
                        {type.replace(/_/g, ' ')}
                        <span className="ml-2 text-slate-500 tabular-nums">
                          {fmtPct(entry.pct_of_sales)} of sales
                        </span>
                      </span>
                      <span className="text-white tabular-nums">
                        {fmtCompactUsd(entry.median_price)}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Card>

        <Card
          title={`Price History — ${data.trends?.period ?? '1y'}`}
          action={
            trendSummary.total_price_change_pct != null ? (
              <span
                className={`text-xs tabular-nums ${deltaClass(
                  trendSummary.total_price_change_pct,
                )}`}
              >
                {fmtSignedPct(trendSummary.total_price_change_pct)} over period
              </span>
            ) : undefined
          }
        >
          <div className="p-4 @lg:p-5">
            <LineTrend
              data={history}
              xKey="month"
              series={[
                { key: 'price', color: SERIES, name: 'Median sale price (USD)' },
                // sales volume is ~4 orders of magnitude below price — own axis
                {
                  key: 'sales',
                  color: SERIES_2,
                  name: 'Closed sales',
                  axis: 'right',
                  formatter: fmtNum,
                },
              ]}
              yFormatter={fmtK}
            />
            <div className="flex flex-wrap gap-x-5 gap-y-1 mt-3 text-[11px] text-slate-500 tabular-nums">
              <span>peak {fmtCompactUsd(trendSummary.peak_price)}</span>
              <span>trough {fmtCompactUsd(trendSummary.trough_price)}</span>
              <span>avg volume {fmtNum(trendSummary.avg_monthly_volume)}/mo</span>
              <span>volume {trendSummary.volume_trend ?? '—'}</span>
            </div>
          </div>
        </Card>
      </div>

      <Card
        title={`${data.forecast?.forecast_horizon_months ?? 12}-Month Price Forecast`}
        action={
          forecastSummary.forecast_confidence ? (
            <StatusPill
              tone={
                forecastSummary.forecast_confidence === 'High'
                  ? 'green'
                  : forecastSummary.forecast_confidence === 'Low'
                    ? 'amber'
                    : 'slate'
              }
              label={`${forecastSummary.forecast_confidence} confidence`}
            />
          ) : undefined
        }
      >
        <div className="p-4 @lg:p-5">
          <div className="flex flex-wrap items-baseline gap-x-5 gap-y-1 mb-3">
            <span className="text-2xl font-bold text-white tabular-nums">
              {fmtCompactUsd(forecastSummary.projected_end_price)}
            </span>
            <span className="text-xs text-slate-400">
              projected from {fmtCompactUsd(data.forecast?.current_median_price)} ·{' '}
              <span className={deltaClass(forecastSummary.total_price_change_pct ?? 0)}>
                {fmtSignedPct(forecastSummary.total_price_change_pct)}
              </span>{' '}
              · {fmtSignedPct(forecastSummary.annualized_growth_rate)} annualized
            </span>
          </div>

          <ForecastBand
            data={forecast}
            xKey="month"
            lowKey="low"
            highKey="band"
            lineKey="projected"
            color={SERIES}
            yFormatter={fmtK}
          />

          <div className="grid grid-cols-1 @2xl:grid-cols-2 gap-x-6 gap-y-3 mt-4">
            <DriverList
              title="Positive drivers"
              items={data.forecast?.positive_drivers ?? []}
              markerClass="bg-green-500"
            />
            <DriverList
              title="Risk factors"
              items={data.forecast?.risk_factors ?? []}
              markerClass="bg-amber-500"
            />
          </div>

          {data.forecast?.disclaimer && (
            <p className="mt-3 text-[11px] text-slate-500">
              {data.forecast.disclaimer}
            </p>
          )}
        </div>
      </Card>
    </section>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <dt className="text-slate-400">{label}</dt>
      <dd className="text-white tabular-nums">{value}</dd>
    </div>
  )
}

function DriverList({
  title,
  items,
  markerClass,
}: {
  title: string
  items: string[]
  markerClass: string
}) {
  if (items.length === 0) return null
  return (
    <div>
      <p className="text-xs text-slate-500 mb-1.5">{title}</p>
      <ul className="space-y-1">
        {items.map((item) => (
          <li key={item} className="flex items-start gap-2 text-xs text-slate-300">
            <span
              className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${markerClass}`}
            />
            {item}
          </li>
        ))}
      </ul>
    </div>
  )
}

/* -------------------------------- listings -------------------------------- */

function ListingsSection({
  zipcode,
  subject,
  onSelectSubject,
}: {
  zipcode: string
  subject: string | null
  onSelectSubject: (address: string) => void
}) {
  const [bedsMin, setBedsMin] = useState(3)
  const { data, loading, error, reload } = useApi<ListingsResponse>(
    `/api/realestate/listings?zipcode=${zipcode}&bedsMin=${bedsMin}`,
  )

  const columns: Array<Column<Listing>> = [
    {
      header: 'Address',
      className: 'text-white whitespace-nowrap',
      render: (row) => (
        <button
          type="button"
          onClick={() => row.address && onSelectSubject(row.address)}
          className={`text-left hover:underline ${
            subject === row.address ? 'text-cyan-300' : 'text-white'
          }`}
          title="Run comparables for this property"
        >
          {/* the trailing zipcode duplicates the market selector — drop it */}
          {(row.address ?? '—').replace(/,\s*\d{5}$/, '')}
        </button>
      ),
    },
    {
      header: 'List price',
      numeric: true,
      className: 'text-white',
      render: (row) => (
        <span>
          {fmtUsd0(row.list_price)}
          {row.price_reduced && (
            <span className="ml-1.5 text-[11px] text-amber-400">↓</span>
          )}
        </span>
      ),
    },
    {
      header: '$/sqft',
      numeric: true,
      render: (row) =>
        row.price_per_sqft != null ? `$${row.price_per_sqft.toFixed(0)}` : '—',
    },
    {
      header: 'Bd / Ba',
      numeric: true,
      render: (row) => `${row.bedrooms ?? '—'} / ${row.bathrooms ?? '—'}`,
    },
    { header: 'Sq ft', numeric: true, render: (row) => fmtNum(row.sqft) },
    { header: 'Built', numeric: true, render: (row) => row.year_built ?? '—' },
    {
      header: 'Status',
      render: (row) => (
        <StatusPill
          tone={
            row.status === 'Pending'
              ? 'amber'
              : row.status === 'Coming Soon'
                ? 'violet'
                : 'green'
          }
          label={row.status ?? '—'}
        />
      ),
    },
    {
      header: 'DOM',
      numeric: true,
      render: (row) => (
        <span className={(row.days_on_market ?? 0) > 60 ? 'text-amber-400' : ''}>
          {fmtNum(row.days_on_market)}
        </span>
      ),
    },
  ]

  const summary = data?.summary ?? {}

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title="Active Listings"
        accentClass={ACCENT}
        action={
          <div className="flex items-center gap-2">
            <select
              value={bedsMin}
              onChange={(event) => setBedsMin(Number(event.target.value))}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200"
              aria-label="Minimum bedrooms"
            >
              {[1, 2, 3, 4].map((beds) => (
                <option key={beds} value={beds}>
                  {beds}+ beds
                </option>
              ))}
            </select>
            <AskAgentButton
              hoverClass={HOVER}
              prompt={`Find the best-value ${bedsMin}+ bedroom listings in ${zipcode} right now and explain what makes each one underpriced.`}
            />
          </div>
        }
      />

      {loading ? (
        <LoadingPane label="Loading listings…" />
      ) : error || !data || data.error ? (
        <Card title="Active Listings">
          <ErrorPane
            message={error ?? data?.error ?? 'No listing data'}
            onRetry={reload}
          />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 @xl:grid-cols-4 gap-3 @lg:gap-4">
            <StatCard
              title="Matching Listings"
              value={fmtNum(data.total_results)}
              icon={Building2}
              /* Against the market's whole active inventory, so "323 matching"
                 is legible as a filtered subset rather than a total that
                 contradicts the 420 on the Market Pulse tile above. */
              sub={
                data.market_active_listings
                  ? `of ${fmtNum(data.market_active_listings)} active in market`
                  : `showing ${(data.listings ?? []).length} of page ${data.page ?? 1}`
              }
            />
            <StatCard
              title="Median Asking"
              value={fmtCompactUsd(summary.median_price)}
              icon={DollarSign}
              sub={`${fmtCompactUsd(summary.min_price)} – ${fmtCompactUsd(
                summary.max_price,
              )}`}
            />
            <StatCard
              title="Avg $/Sq Ft"
              value={
                summary.avg_price_per_sqft != null
                  ? `$${summary.avg_price_per_sqft.toFixed(0)}`
                  : '—'
              }
              icon={Home}
              /* Beside the market rate, because these listings are drawn from
                 that market: the table averaged $312/sqft under a $421/sqft
                 market tile and nothing on screen connected the two. */
              sub={
                data.market_median_price_per_sqft
                  ? `market $${data.market_median_price_per_sqft.toFixed(0)}/sq ft`
                  : `${fmtNum(summary.avg_days_on_market)} day avg on market`
              }
              subClass="text-slate-400"
            />
            <StatCard
              title="With Price Cut"
              value={fmtPct(summary.pct_with_price_reduction, 0)}
              icon={LineChartIcon}
              sub="of listings shown"
              subClass={
                (summary.pct_with_price_reduction ?? 0) > 40
                  ? 'text-amber-400'
                  : 'text-slate-400'
              }
            />
          </div>

          <Card title="Listings — select an address to pull comparables">
            <DataTable
              columns={columns}
              rows={data.listings ?? []}
              rowKey={(row, i) => row.listing_id ?? String(i)}
              empty="No listings match these criteria"
            />
          </Card>
        </>
      )}
    </section>
  )
}

/* ------------------------------- comparables ------------------------------ */

function ComparablesSection({ address }: { address: string }) {
  const [radius, setRadius] = useState(1)
  const { data, loading, error, reload } = useApi<ComparablesResponse>(
    `/api/realestate/comparables?address=${encodeURIComponent(address)}&radius=${radius}`,
  )

  const columns: Array<Column<Comparable>> = [
    {
      header: 'Comp address',
      className: 'text-white whitespace-nowrap',
      render: (row) => row.address ?? '—',
    },
    {
      header: 'Sale price',
      numeric: true,
      render: (row) => fmtUsd0(row.sale_price),
    },
    {
      header: 'Adjusted',
      numeric: true,
      className: 'text-white',
      render: (row) => fmtUsd0(row.adjusted_price),
    },
    {
      header: 'Net adj.',
      numeric: true,
      render: (row) => {
        const total = row.adjustments?.total ?? 0
        return (
          <span className={total === 0 ? 'text-slate-500' : deltaClass(total)}>
            {total >= 0 ? '+' : '−'}
            {fmtUsd0(Math.abs(total))}
          </span>
        )
      },
    },
    { header: 'Sq ft', numeric: true, render: (row) => fmtNum(row.sqft) },
    {
      header: 'Bd / Ba',
      numeric: true,
      render: (row) => `${row.beds ?? '—'} / ${row.baths ?? '—'}`,
    },
    {
      header: '$/sqft',
      numeric: true,
      render: (row) =>
        row.price_per_sqft != null ? `$${row.price_per_sqft.toFixed(0)}` : '—',
    },
    {
      header: 'Distance',
      numeric: true,
      render: (row) =>
        row.distance_miles != null ? `${row.distance_miles.toFixed(2)} mi` : '—',
    },
    { header: 'Sold', render: (row) => row.sale_date ?? '—' },
    {
      header: 'Similarity',
      numeric: true,
      render: (row) => (
        <StatusPill
          tone={(row.similarity_score ?? 0) >= 90 ? 'green' : 'slate'}
          label={fmtPct(row.similarity_score, 0)}
        />
      ),
    },
  ]

  const summary = data?.summary ?? {}
  const subject = data?.subject_property ?? {}

  return (
    <section className="space-y-4 @container">
      <SectionHeader
        title="Comparables"
        accentClass={ACCENT}
        action={
          <div className="flex items-center gap-2">
            <select
              value={radius}
              onChange={(event) => setRadius(Number(event.target.value))}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200"
              aria-label="Search radius in miles"
            >
              {[0.5, 1, 2, 5].map((miles) => (
                <option key={miles} value={miles}>
                  {miles} mi radius
                </option>
              ))}
            </select>
            <AskAgentButton
              hoverClass={HOVER}
              prompt={`Produce a valuation for ${address} from the comparable sales within ${radius} mile${
                radius === 1 ? '' : 's'
              }, and state the adjustments you applied.`}
            />
          </div>
        }
      />

      {loading ? (
        <LoadingPane label="Loading comparables…" />
      ) : error || !data || data.error ? (
        <Card title="Comparables">
          <ErrorPane
            message={error ?? data?.error ?? 'No comparable sales'}
            onRetry={reload}
          />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 @xl:grid-cols-4 gap-3 @lg:gap-4">
            <StatCard
              title="Indicated Value"
              value={fmtCompactUsd(summary.median_adjusted_price)}
              icon={Scale}
              /* Against the subject's own basis value, so the two are readable
                 as agreeing or not. The comps used to be priced independently of
                 the listing, and this tile could read half the asking price on
                 the row the user had just clicked. */
              sub={
                subject.indicated_value
                  ? `subject basis ${fmtCompactUsd(subject.indicated_value)}`
                  : 'median adjusted comp price'
              }
              subClass="text-slate-400"
            />
            <StatCard
              title="Median Comp Sale"
              value={fmtCompactUsd(summary.median_sale_price)}
              icon={DollarSign}
              sub="before adjustments"
            />
            <StatCard
              title="Median $/Sq Ft"
              value={
                summary.median_price_per_sqft != null
                  ? `$${summary.median_price_per_sqft.toFixed(0)}`
                  : '—'
              }
              icon={Home}
              sub={`${fmtNum(data.total_found)} comps within ${
                data.search_radius_miles ?? radius
              } mi`}
            />
            <StatCard
              title="Avg Days on Market"
              value={fmtNum(summary.avg_days_on_market)}
              icon={CalendarDays}
              sub="for these comps"
            />
          </div>

          <Card title={`Comparable sales — subject ${data.subject_address ?? address}`}>
            {/* The subject the whole adjustment column is measured against. The
                table showed adjustments of +/-$90K with the property they were
                relative to nowhere on screen, so a reader had no way to tell a
                reasonable adjustment from an absurd one. */}
            {subject.sqft != null && (
              <p className="text-xs text-slate-400 mb-3 tabular-nums">
                {fmtNum(subject.sqft)} sq ft · {subject.beds ?? '—'} bd ·{' '}
                {subject.baths ?? '—'} ba · built {subject.year_built ?? '—'}
                {subject.price_per_sqft != null &&
                  ` · $${subject.price_per_sqft.toFixed(0)}/sq ft`}
              </p>
            )}
            <DataTable
              columns={columns}
              rows={data.comparables ?? []}
              rowKey={(row, i) => row.address ?? String(i)}
              empty="No comparable sales in this radius"
            />
          </Card>

          <p className="text-xs text-slate-400 px-1">
            Adjusted prices normalise each comp to the subject property for size,
            bedrooms, bathrooms and time of sale. The indicated value is the median of
            those adjusted prices — the agent can walk through any single adjustment.
          </p>
        </>
      )}
    </section>
  )
}
