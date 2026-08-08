import { useLocale } from '../../i18n/LocaleContext'
import MarketLiveSection from './MarketLiveSection'
import MarketSection from './MarketSection'
import OrdersSection from './OrdersSection'
import PortfolioSection from './PortfolioSection'
import { SimulatedBadge } from './widgets'

export default function FinanceDashboard() {
  const { t } = useLocale()
  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 @container">
        {/* Live market data: real providers, per-card LiveBadge provenance */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">
            {t('finance.liveMarket')}
          </h2>
        </div>
        <MarketLiveSection />

        {/* Simulated demo book: portfolio/orders price off MarketSim so the
            fills, P&L, and the simulated market section stay coherent */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">
            {t('finance.heading')}
          </h2>
          <SimulatedBadge />
        </div>
        <PortfolioSection />
        <MarketSection />
        <OrdersSection />
      </div>
    </div>
  )
}
