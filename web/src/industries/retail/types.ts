/** Response shapes for /api/retail/* — mirrors tools/retail handlers. */

export interface CategoryInventory {
  category?: string
  total_skus?: number
  in_stock_pct?: number
  stockout_skus?: number
  overstock_skus?: number
  total_value?: number
  avg_days_of_supply?: number
  inventory_turnover?: number
}

export interface InventoryAlert {
  type?: string
  severity?: string
  message?: string
}

export interface InventorySummary {
  filter?: string
  summary?: CategoryInventory[]
  overall?: {
    total_skus?: number
    total_inventory_value?: number
    avg_in_stock_rate?: number
    total_stockouts?: number
    total_overstock?: number
    /** on-hand value above target — the actionable share of total_inventory_value */
    total_excess_value?: number
  }
  alerts?: InventoryAlert[]
  source?: string
}

export interface AbcClass {
  description?: string
  sku_count?: number
  sku_pct?: number
  revenue_pct?: number
  inventory_value?: number
  avg_turnover?: number
  target_fill_rate?: number
  current_fill_rate?: number
}

export interface AbcAnalysis {
  analysis_date?: string
  classification?: Record<string, AbcClass>
  recommendations?: string[]
  source?: string
}

export interface CategoryMargin {
  category?: string
  gross_margin_pct?: number
  net_margin_pct?: number
  revenue?: number
  cogs?: number
  margin_trend?: number
  top_margin_sku?: string
  lowest_margin_sku?: string
  skus_below_target?: number
}

export interface MarginReport {
  report?: CategoryMargin[]
  overall?: {
    blended_gross_margin?: number
    total_revenue?: number
    margin_improvement_opportunity?: number
  }
  source?: string
}

export interface SupplierRisk {
  risk?: string
  severity?: string
  mitigation?: string
}

export interface SupplierRiskReport {
  report_date?: string
  overall_supply_chain_risk?: string
  /** how many suppliers the rating above is a judgement over */
  suppliers_assessed?: number
  /** Values are numbers, or lists of supplier ids / category names — the
   *  previous `Record<string, number>` inner type was wrong for `suppliers`,
   *  `categories` and `watch_list`, which the handler returns as arrays. */
  risk_factors?: Record<string, Record<string, number | string[]>>
  top_risks?: SupplierRisk[]
  recommendations?: string[]
  watch_list?: string[]
  next_review?: string
  source?: string
}

export interface OverviewResponse {
  inventory?: InventorySummary
  abc?: AbcAnalysis
  margins?: MarginReport
  supplier_risk?: SupplierRiskReport
  error?: string
}

export interface StockoutItem {
  sku?: string
  product_name?: string
  category?: string
  abc_class?: string
  days_out_of_stock?: number
  estimated_daily_revenue_loss?: number
  estimated_total_loss?: number
  reorder_status?: string
  eta?: string
}

export interface StockoutReport {
  /** tracked catalog SKUs out of stock — the count the items table lists */
  total_stockouts?: number
  /** all SKUs out of stock across the network, which the category breakdown sums to */
  network_stockouts?: number
  /** one sentence naming which of the two counts the table represents */
  scope?: string
  total_revenue_impact?: number
  a_class_stockouts?: number
  items?: StockoutItem[]
  recommendation?: string
  source?: string
  error?: string
}

export interface WeeklyDemand {
  week?: string
  units_sold?: number
  revenue?: number
  avg_order_value?: number
}

export interface DemandResponse {
  category?: string
  period?: string
  trends?: {
    units_growth_pct?: number
    revenue_growth_pct?: number
    aov_change_pct?: number
  }
  weekly_data?: WeeklyDemand[]
  top_growing_skus?: Array<{ sku?: string; growth_pct?: number }>
  declining_skus?: Array<{ sku?: string; decline_pct?: number }>
  seasonality_index?: number
  source?: string
  error?: string
}

export interface ForecastPoint {
  date?: string
  predicted_units?: number
  lower_bound?: number
  upper_bound?: number
  confidence?: number
}

export interface ForecastResponse {
  sku?: string
  forecast_period_days?: number
  model?: string
  total_predicted_demand?: number
  avg_daily_demand?: number
  peak_day?: string
  forecasts?: ForecastPoint[]
  accuracy_metrics?: { mape?: number; rmse?: number; forecast_bias?: number }
  factors?: Record<string, string>
  source?: string
  error?: string
}
