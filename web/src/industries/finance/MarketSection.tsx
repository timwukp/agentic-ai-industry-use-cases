import { Activity, ArrowDownRight, ArrowUpRight, Gauge } from 'lucide-react'
import {
  Bar,
  BarChart,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { useLocale } from '../../i18n/LocaleContext'
import { useApi } from '../../lib/api'
import type { MarketOverviewResponse } from './types'
import { Card, ErrorPane, LoadingPane, fmtSigned, pnlClass } from './widgets'

const INDEX_LABELS: Record<string, string> = {
  SP500: 'S&P 500',
  NASDAQ: 'NASDAQ',
  DOW: 'DOW',
  RUSSELL2000: 'Russell 2000',
}

const TREASURY_LABELS: Record<string, string> = {
  '2Y': '2-Year',
  '10Y': '10-Year',
  '30Y': '30-Year',
}

export default function MarketSection() {
  const { t } = useLocale()
  const { data, loading, error, reload } = useApi<MarketOverviewResponse>(
    '/api/finance/market/overview',
  )

  if (loading) return <LoadingPane label={t('finance.loadingMarket')} />
  if (error || !data) {
    return (
      <Card title={t('finance.marketOverview')}>
        <ErrorPane message={error ?? t('finance.noMarketData')} onRetry={reload} />
      </Card>
    )
  }

  const vix = data.volatility.VIX
  const vixElevated = data.volatility.VIX_status === 'elevated'
  const fearGreed = data.sentiment.fear_greed_index

  return (
    <div className="space-y-4 @container">
      {/* Indices */}
      <div className="grid grid-cols-2 @3xl:grid-cols-4 gap-3 @lg:gap-4">
        {Object.entries(data.indices).map(([key, quote]) => (
          <div key={key} className="bg-slate-900 rounded-xl p-4 border border-slate-800">
            <div className="text-xs @lg:text-sm text-slate-400 mb-1">
              {INDEX_LABELS[key] ?? key}
            </div>
            <div className="text-lg @lg:text-xl font-bold text-white tabular-nums">
              {quote.value.toLocaleString('en-US', { minimumFractionDigits: 2 })}
            </div>
            <div
              className={`flex items-center gap-1 text-xs @lg:text-sm mt-1 ${pnlClass(quote.change_pct)}`}
            >
              {quote.change_pct >= 0 ? (
                <ArrowUpRight className="w-3.5 h-3.5" />
              ) : (
                <ArrowDownRight className="w-3.5 h-3.5" />
              )}
              {fmtSigned(quote.change_pct, '%')}
            </div>
          </div>
        ))}
      </div>

      {/* Sector performance chart */}
      <Card title={t('finance.sectorPerformanceDaily')}>
        <div className="p-4 @lg:p-5">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={data.sectors}
              layout="vertical"
              margin={{ left: 8, right: 16, top: 4, bottom: 4 }}
            >
              <XAxis
                type="number"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                tickFormatter={(v: number) => `${v}%`}
              />
              <YAxis
                type="category"
                dataKey="name"
                stroke="#64748b"
                fontSize={11}
                width={130}
                tickLine={false}
                axisLine={false}
              />
              <ReferenceLine x={0} stroke="#334155" />
              <Tooltip
                cursor={{ fill: 'rgba(148, 163, 184, 0.06)' }}
                contentStyle={{
                  background: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  color: '#e2e8f0',
                }}
                labelStyle={{ color: '#94a3b8' }}
                formatter={(value: number) => [fmtSigned(value, '%'), t('finance.dailyChange')]}
              />
              <Bar dataKey="daily_change_pct" barSize={14} radius={[0, 4, 4, 0]}>
                {data.sectors.map((sector) => (
                  <Cell
                    key={sector.name}
                    fill={sector.daily_change_pct >= 0 ? '#22c55e' : '#ef4444'}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      {/* VIX + Treasury + Fear/Greed */}
      <div className="grid grid-cols-1 @3xl:grid-cols-3 gap-3 @lg:gap-4">
        <Card>
          <div className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-slate-400" />
                <span className="text-sm text-slate-400">{t('finance.volatilityVix')}</span>
              </div>
              <span
                className={`px-2 py-0.5 rounded-full text-[11px] border ${
                  vixElevated
                    ? 'bg-amber-950/50 border-amber-800/50 text-amber-300'
                    : 'bg-green-950/50 border-green-800/50 text-green-300'
                }`}
              >
                {vixElevated ? t('finance.elevated') : t('finance.normal')}
              </span>
            </div>
            <div
              className={`text-3xl font-bold tabular-nums ${vixElevated ? 'text-amber-400' : 'text-white'}`}
            >
              {vix.toFixed(1)}
            </div>
            <div className="mt-4 h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-green-500 via-yellow-500 to-red-500 rounded-full"
                style={{ width: `${Math.min((vix / 50) * 100, 100)}%` }}
              />
            </div>
            <div className="flex justify-between text-[11px] text-slate-500 mt-1">
              <span>{t('finance.meterLow')}</span>
              <span>{t('finance.meterNormal')}</span>
              <span>{t('finance.meterElevated')}</span>
              <span>{t('finance.meterHigh')}</span>
            </div>
          </div>
        </Card>

        <Card title={t('finance.treasuryYields')}>
          <div className="p-5 space-y-3.5">
            {Object.entries(data.treasury).map(([maturity, yieldPct]) => (
              <div key={maturity} className="flex items-center justify-between">
                <span className="text-sm text-slate-400">
                  {TREASURY_LABELS[maturity] ?? maturity}
                </span>
                <span className="text-white font-medium tabular-nums">
                  {yieldPct.toFixed(2)}%
                </span>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <div className="p-5">
            <div className="flex items-center gap-2 mb-3">
              <Gauge className="w-4 h-4 text-slate-400" />
              <span className="text-sm text-slate-400">{t('finance.fearGreed')}</span>
            </div>
            <div className="flex items-baseline gap-3">
              <span className="text-3xl font-bold text-white tabular-nums">{fearGreed}</span>
              <span
                className={`text-sm font-medium ${
                  fearGreed < 40
                    ? 'text-red-400'
                    : fearGreed < 60
                      ? 'text-slate-300'
                      : 'text-green-400'
                }`}
              >
                {data.sentiment.label}
              </span>
            </div>
            <div className="mt-4 h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-red-500 via-yellow-500 to-green-500 rounded-full"
                style={{ width: `${fearGreed}%` }}
              />
            </div>
            <div className="flex justify-between text-[11px] text-slate-500 mt-1">
              <span>{t('finance.meterFear')}</span>
              <span>{t('finance.meterNeutral')}</span>
              <span>{t('finance.meterGreed')}</span>
            </div>
          </div>
        </Card>
      </div>
    </div>
  )
}
