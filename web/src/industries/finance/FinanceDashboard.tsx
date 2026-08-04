import MarketSection from './MarketSection'
import OrdersSection from './OrdersSection'
import PortfolioSection from './PortfolioSection'
import { SimulatedBadge } from './widgets'

export default function FinanceDashboard() {
  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 lg:p-6 space-y-6 @container">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg lg:text-xl font-bold text-white">
            Finance &amp; Trading
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
