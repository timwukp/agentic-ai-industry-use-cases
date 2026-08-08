import { ArrowDownRight, ArrowUpRight, Landmark, Percent } from 'lucide-react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { useLocale } from '../../i18n/LocaleContext'
import { useApi } from '../../lib/api'
import type { FredEntry, MarketLiveResponse } from './types'
import { Card, ErrorPane, LiveBadge, LoadingPane, fmtSigned, pnlClass } from './widgets'

/** Maturity axis order for the yield-curve chart. */
const CURVE_ORDER = [
  'DGS1MO',
  'DGS3MO',
  'DGS6MO',
  'DGS1',
  'DGS2',
  'DGS5',
  'DGS10',
  'DGS30',
]
const CURVE_LABELS: Record<string, string> = {
  DGS1MO: '1M',
  DGS3MO: '3M',
  DGS6MO: '6M',
  DGS1: '1Y',
  DGS2: '2Y',
  DGS5: '5Y',
  DGS10: '10Y',
  DGS30: '30Y',
}

export default function MarketLiveSection() {
  const { t } = useLocale()
  const { data, loading, error, reload } = useApi<MarketLiveResponse>(
    '/api/finance/market/live',
  )

  if (loading) return <LoadingPane label={t('finance.loadingLiveMarket')} />
  if (error || !data) {
    return (
      <Card title={t('finance.liveMarket')}>
        <ErrorPane message={error ?? t('finance.noLiveData')} onRetry={reload} />
      </Card>
    )
  }

  const treasury = data.treasury
  const curvePoints = treasury.curve
    ? CURVE_ORDER.filter((k) => treasury.curve[k]).map((k) => ({
        maturity: CURVE_LABELS[k] ?? k,
        yield: treasury.curve[k].value,
      }))
    : []
  const quotes = data.quotes.filter((q) => !q.error)

  return (
    <div className="space-y-4 @container" data-section="market-live">
      {/* Indices */}
      <div className="grid grid-cols-1 @3xl:grid-cols-2 gap-3 @lg:gap-4">
        {data.indices
          .filter((ix) => !ix.error)
          .map((ix) => (
            <div
              key={ix.index}
              className="bg-slate-900 rounded-xl p-4 border border-slate-800"
              data-kpi={`live-index-${ix.index}`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                <span className="text-xs @lg:text-sm text-slate-400">{ix.name}</span>
                <LiveBadge
                  provider={ix.provider}
                  fetchedAt={ix.fetched_at}
                  delay={ix.delay}
                  stale={ix.stale}
                />
              </div>
              <div
                className="text-lg @lg:text-xl font-bold text-white tabular-nums"
                data-kpi-value
              >
                {ix.level.toLocaleString('en-US', { minimumFractionDigits: 2 })}
              </div>
              <div
                className={`flex items-center gap-1 text-xs @lg:text-sm mt-1 ${pnlClass(ix.change_pct)}`}
              >
                {ix.change_pct >= 0 ? (
                  <ArrowUpRight className="w-3.5 h-3.5" />
                ) : (
                  <ArrowDownRight className="w-3.5 h-3.5" />
                )}
                {fmtSigned(ix.change_pct, '%')}
              </div>
            </div>
          ))}
      </div>

      {/* Yield curve + policy rates */}
      <div className="grid grid-cols-1 @3xl:grid-cols-2 gap-3 @lg:gap-4">
        <Card
          title={t('finance.yieldCurve')}
          action={
            !treasury.error && (
              <LiveBadge
                provider={treasury.provider}
                fetchedAt={treasury.fetched_at}
                delay={treasury.delay}
                stale={treasury.stale}
              />
            )
          }
        >
          {treasury.error ? (
            <ErrorPane message={treasury.error} />
          ) : (
            <div className="p-4 @lg:p-5">
              {treasury.curve_inverted !== undefined && (
                <div
                  className={`mb-3 text-xs @lg:text-sm ${
                    treasury.curve_inverted ? 'text-amber-300' : 'text-slate-400'
                  }`}
                >
                  {t('finance.spread10y2y')}:{' '}
                  <span className="font-medium tabular-nums">
                    {fmtSigned(treasury.spread_10y_2y ?? 0, ' pp')}
                  </span>
                  {treasury.curve_inverted && ` — ${t('finance.inverted')}`}
                </div>
              )}
              <ResponsiveContainer width="100%" height={220}>
                <LineChart
                  data={curvePoints}
                  margin={{ left: 0, right: 16, top: 8, bottom: 4 }}
                >
                  <CartesianGrid stroke="#1e293b" vertical={false} />
                  <XAxis
                    dataKey="maturity"
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                    domain={['auto', 'auto']}
                    tickFormatter={(v: number) => `${v}%`}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#1e293b',
                      border: '1px solid #334155',
                      borderRadius: '8px',
                      color: '#e2e8f0',
                    }}
                    labelStyle={{ color: '#94a3b8' }}
                    formatter={(value: number) => [
                      `${value.toFixed(2)}%`,
                      t('finance.yieldLabel'),
                    ]}
                  />
                  <Line
                    type="monotone"
                    dataKey="yield"
                    stroke="#22c55e"
                    strokeWidth={2}
                    dot={{ r: 3, fill: '#22c55e' }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card
          title={t('finance.policyRates')}
          action={
            !data.rates.error && (
              <LiveBadge
                provider={data.rates.provider}
                fetchedAt={data.rates.fetched_at}
                delay={data.rates.delay}
                stale={data.rates.stale}
              />
            )
          }
        >
          {data.rates.error ? (
            <ErrorPane message={data.rates.error} />
          ) : (
            <div className="p-5 space-y-3.5">
              {Object.values(data.rates.rates ?? {}).map((entry: FredEntry) => (
                <div key={entry.series} className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm text-slate-400">
                    {entry.series.startsWith('DFEDTAR') ? (
                      <Landmark className="w-3.5 h-3.5" />
                    ) : (
                      <Percent className="w-3.5 h-3.5" />
                    )}
                    {entry.label}
                  </span>
                  <span className="text-white font-medium tabular-nums">
                    {entry.value.toFixed(2)}%
                    <span className="ml-2 text-[11px] text-slate-500">
                      {entry.as_of_date}
                    </span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Tracked quotes */}
      <Card title={t('finance.trackedSymbols')}>
        {quotes.length === 0 ? (
          <ErrorPane message={t('finance.noLiveData')} onRetry={reload} />
        ) : (
          <div className="p-4 @lg:p-5">
            <div className="mb-3">
              <LiveBadge
                provider={quotes[0].provider}
                fetchedAt={quotes[0].fetched_at}
                delay={quotes[0].delay}
                stale={quotes.some((q) => q.stale)}
              />
            </div>
            <div className="grid grid-cols-2 @lg:grid-cols-3 @3xl:grid-cols-5 gap-2 @lg:gap-3">
              {quotes.map((q) => (
                <div
                  key={q.symbol}
                  className="bg-slate-950 rounded-lg px-3 py-2.5 border border-slate-800"
                  data-kpi={`live-quote-${q.symbol}`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-300">{q.symbol}</span>
                    <span className={`text-[11px] ${pnlClass(q.change_pct)}`}>
                      {fmtSigned(q.change_pct, '%')}
                    </span>
                  </div>
                  <div className="text-sm font-bold text-white tabular-nums mt-0.5" data-kpi-value>
                    {q.price.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>
    </div>
  )
}
