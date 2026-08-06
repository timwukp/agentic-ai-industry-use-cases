import {
  ArrowDownRight,
  ArrowUpRight,
  BarChart3,
  DollarSign,
  Percent,
  TrendingUp,
} from 'lucide-react'
import { useLocale } from '../../i18n/LocaleContext'
import { useApi } from '../../lib/api'
import type { PortfolioResponse } from './types'
import {
  Card,
  ErrorPane,
  LoadingPane,
  StatCard,
  fmtSigned,
  fmtUsd,
  fmtUsdCompact,
  pnlClass,
} from './widgets'

export default function PortfolioSection() {
  const { t } = useLocale()
  const { data, loading, error, reload } = useApi<PortfolioResponse>(
    '/api/finance/portfolio',
  )

  if (loading) return <LoadingPane label={t('finance.loadingPortfolio')} />
  if (error || !data || data.error) {
    return (
      <Card title={t('finance.portfolio')}>
        <ErrorPane
          message={error ?? data?.error ?? t('finance.noPortfolioData')}
          onRetry={reload}
        />
      </Card>
    )
  }

  const { summary, positions } = data
  const pnlPositive = summary.total_unrealized_pnl >= 0

  return (
    <div className="space-y-4 @container">
      {/* Summary stat cards */}
      <div className="grid grid-cols-2 @3xl:grid-cols-4 gap-3 @lg:gap-4">
        <StatCard
          kpiKey="Portfolio Value"
          title={t('finance.portfolioValue')}
          value={fmtUsdCompact(summary.total_market_value)}
          icon={DollarSign}
          sub={t('finance.costBasis', { value: fmtUsdCompact(summary.total_cost_basis) })}
        />
        <StatCard
          kpiKey="Unrealized P&L"
          title={t('finance.unrealizedPnl')}
          value={fmtSigned(summary.total_unrealized_pnl)}
          icon={TrendingUp}
          sub={pnlPositive ? t('finance.inProfit') : t('finance.inLoss')}
          subClass={pnlClass(summary.total_unrealized_pnl)}
        />
        <StatCard
          kpiKey="Total Return"
          title={t('finance.totalReturn')}
          value={fmtSigned(summary.total_return_pct, '%')}
          icon={Percent}
          sub={t('finance.sinceInception')}
          subClass={pnlClass(summary.total_return_pct)}
        />
        <StatCard
          kpiKey="Positions"
          title={t('finance.positions')}
          value={String(summary.num_positions)}
          icon={BarChart3}
          sub={t('finance.activeHoldings')}
        />
      </div>

      {/* Positions table */}
      <Card title={t('finance.positions')}>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px]">
            <thead>
              <tr className="text-xs text-slate-500 border-b border-slate-800">
                <th className="px-5 py-3 text-left font-medium">{t('finance.colSymbol')}</th>
                <th className="px-5 py-3 text-right font-medium">{t('finance.colQty')}</th>
                <th className="px-5 py-3 text-right font-medium">{t('finance.colAvgCost')}</th>
                <th className="px-5 py-3 text-right font-medium">{t('finance.colPrice')}</th>
                <th className="px-5 py-3 text-right font-medium">{t('finance.colMarketValue')}</th>
                <th className="px-5 py-3 text-right font-medium">{t('finance.colPnl')}</th>
                <th className="px-5 py-3 text-right font-medium">{t('finance.colReturn')}</th>
              </tr>
            </thead>
            <tbody>
              {positions.map((pos) => (
                <tr
                  key={pos.symbol}
                  className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/30"
                >
                  <td className="px-5 py-3 font-medium text-white">{pos.symbol}</td>
                  <td className="px-5 py-3 text-right text-slate-300 tabular-nums">
                    {pos.quantity.toLocaleString()}
                  </td>
                  <td className="px-5 py-3 text-right text-slate-300 tabular-nums">
                    {fmtUsd(pos.avg_cost)}
                  </td>
                  <td className="px-5 py-3 text-right text-white font-medium tabular-nums">
                    {fmtUsd(pos.current_price)}
                  </td>
                  <td className="px-5 py-3 text-right text-white tabular-nums">
                    {fmtUsd(pos.market_value)}
                  </td>
                  <td
                    className={`px-5 py-3 text-right font-medium tabular-nums ${pnlClass(pos.unrealized_pnl)}`}
                  >
                    {fmtSigned(pos.unrealized_pnl)}
                  </td>
                  <td className="px-5 py-3 text-right">
                    <span
                      className={`inline-flex items-center gap-1 text-sm tabular-nums ${pnlClass(pos.unrealized_pnl_pct)}`}
                    >
                      {pos.unrealized_pnl_pct >= 0 ? (
                        <ArrowUpRight className="w-3 h-3" />
                      ) : (
                        <ArrowDownRight className="w-3 h-3" />
                      )}
                      {fmtSigned(pos.unrealized_pnl_pct, '%')}
                    </span>
                  </td>
                </tr>
              ))}
              {positions.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-5 py-8 text-center text-sm text-slate-500">
                    {t('finance.noOpenPositions')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
