/** Response shapes of the finance dashboard REST API (tools/finance/dashboard_api). */

export interface Position {
  symbol: string
  quantity: number
  avg_cost: number
  current_price: number
  cost_basis: number
  market_value: number
  unrealized_pnl: number
  unrealized_pnl_pct: number
}

export interface PortfolioResponse {
  portfolio_id: string
  positions: Position[]
  summary: {
    total_cost_basis: number
    total_market_value: number
    total_unrealized_pnl: number
    total_return_pct: number
    num_positions: number
  }
  as_of: string
  source?: string
  error?: string
}

export interface IndexQuote {
  value: number
  change_pct: number
}

export interface SectorPerf {
  name: string
  daily_change_pct: number
  ytd_change_pct: number
  market_cap_trillions: number
}

export interface MarketOverviewResponse {
  indices: Record<string, IndexQuote>
  volatility: { VIX: number; VIX_status: string }
  treasury: Record<string, number>
  sentiment: { fear_greed_index: number; label: string }
  sectors: SectorPerf[]
  timestamp: string
  source?: string
}

/** Live-provenance envelope shared by every real-data payload. */
export interface LiveEnvelope {
  source: 'live'
  provider: string
  fetched_at: string
  delay: string
  stale?: boolean
  error?: string
}

export interface LiveIndex extends LiveEnvelope {
  index: string
  name: string
  level: number
  change: number
  change_pct: number
}

export interface LiveQuote extends LiveEnvelope {
  symbol: string
  price: number
  change: number
  change_pct: number
  high: number
  low: number
  open: number
  prev_close: number
}

export interface FredEntry {
  series: string
  label: string
  value: number
  as_of_date: string
}

export interface LiveTreasury extends LiveEnvelope {
  curve: Record<string, FredEntry>
  spread_10y_2y?: number
  curve_inverted?: boolean
}

export interface LiveRates extends LiveEnvelope {
  rates: Record<string, FredEntry>
}

export interface MarketLiveResponse {
  indices: LiveIndex[]
  treasury: LiveTreasury
  rates: LiveRates
  quotes: LiveQuote[]
  tracked: { symbols: string[] } & Partial<LiveEnvelope>
}

export interface Order {
  orderId: string
  portfolioId: string
  symbol: string
  side: 'BUY' | 'SELL'
  quantity: number
  orderType: string
  limitPrice?: number
  status: 'FILLED' | 'OPEN' | 'CANCELLED' | string
  fillPrice?: number
  commission?: number
  createdAt: string
}

export interface OrdersResponse {
  portfolio_id: string
  period_days: number
  total_orders: number
  orders: Order[]
  summary: {
    total_buy_value: number
    total_sell_value: number
    total_commissions: number
  }
  source?: string
}
