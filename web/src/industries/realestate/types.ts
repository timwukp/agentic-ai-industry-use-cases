/** Response shapes for /api/realestate/* — mirrors tools/realestate handlers. */

export interface MarketConditions {
  zipcode?: string
  market_snapshot?: {
    median_sale_price?: number
    median_price_per_sqft?: number
    average_days_on_market?: number
    median_days_on_market?: number
    active_listings?: number
    new_listings_30d?: number
    closed_sales_30d?: number
    pending_sales?: number
    months_of_supply?: number
    /** median_sale_price / median_price_per_sqft — stated so the two are visibly consistent */
    implied_median_sqft?: number
  }
  as_of?: string
  price_trends?: {
    year_over_year_pct?: number
    month_over_month_pct?: number
    median_price_12mo_ago?: number
    price_per_sqft_trend?: number
  }
  market_indicators?: {
    market_type?: string
    sale_to_list_ratio?: number
    pct_sold_over_asking?: number
    pct_with_price_reduction?: number
    avg_price_reduction_pct?: number
    absorption_rate?: number
  }
  property_types?: Record<string, { median_price?: number; pct_of_sales?: number }>
  source?: string
}

export interface TrendPoint {
  date?: string
  median_sale_price?: number
  median_price_per_sqft?: number
  closed_sales?: number
  new_listings?: number
  avg_days_on_market?: number
  sale_to_list_ratio?: number
  inventory?: number
}

export interface MarketTrends {
  zipcode?: string
  period?: string
  data_points?: number
  /** the same median the conditions tile shows — the last point of `trends` */
  current_median_price?: number
  market_type?: string
  trends?: TrendPoint[]
  summary?: {
    start_median_price?: number
    end_median_price?: number
    total_price_change_pct?: number
    annualized_change_pct?: number
    peak_price?: number
    trough_price?: number
    avg_monthly_volume?: number
    volume_trend?: string
  }
  source?: string
}

export interface ForecastPoint {
  month?: number
  date?: string
  forecasted_median_price?: number
  confidence_low?: number
  confidence_high?: number
  month_over_month_pct?: number
}

export interface MarketForecast {
  zipcode?: string
  forecast_horizon_months?: number
  current_median_price?: number
  /** trailing 12mo change the forecast continues, so the two agree in direction */
  trailing_yoy_pct?: number
  market_type?: string
  forecast?: ForecastPoint[]
  summary?: {
    projected_end_price?: number
    total_price_change_pct?: number
    annualized_growth_rate?: number
    forecast_confidence?: string
  }
  risk_factors?: string[]
  positive_drivers?: string[]
  disclaimer?: string
  source?: string
}

export interface MarketResponse {
  conditions?: MarketConditions
  trends?: MarketTrends
  forecast?: MarketForecast
  error?: string
}

export interface Listing {
  listing_id?: string
  address?: string
  list_price?: number
  original_price?: number
  price_reduced?: boolean
  bedrooms?: number
  bathrooms?: number
  sqft?: number
  lot_sqft?: number
  year_built?: number
  property_type?: string
  status?: string
  days_on_market?: number
  price_per_sqft?: number
  features?: string[]
  listing_date?: string
}

export interface ListingsResponse {
  search_criteria?: Record<string, unknown>
  zipcode?: string
  /** market context, so the table can be read against the market it is drawn from */
  market_active_listings?: number
  market_median_price?: number
  market_median_price_per_sqft?: number
  total_results?: number
  page?: number
  page_size?: number
  listings?: Listing[]
  summary?: {
    min_price?: number
    max_price?: number
    median_price?: number
    avg_price_per_sqft?: number
    avg_days_on_market?: number
    pct_with_price_reduction?: number
  }
  source?: string
  error?: string
}

export interface Comparable {
  address?: string
  sale_price?: number
  adjusted_price?: number
  sale_date?: string
  days_on_market?: number
  sqft?: number
  beds?: number
  baths?: number
  lot_sqft?: number
  year_built?: number
  price_per_sqft?: number
  distance_miles?: number
  property_type?: string
  adjustments?: Record<string, number>
  similarity_score?: number
}

export interface SubjectProperty {
  sqft?: number
  beds?: number
  baths?: number
  year_built?: number
  price_per_sqft?: number
  indicated_value?: number
}

export interface ComparablesResponse {
  subject_address?: string
  /** what the adjustments are measured against — an indicated value with no
   *  subject on screen gave no way to judge whether the comps bracketed it */
  subject_property?: SubjectProperty
  search_radius_miles?: number
  total_found?: number
  comparables?: Comparable[]
  summary?: {
    median_sale_price?: number
    median_price_per_sqft?: number
    median_adjusted_price?: number
    avg_days_on_market?: number
  }
  source?: string
  error?: string
}

export const MARKETS = [
  { zipcode: '78701', label: 'Austin — Downtown (78701)' },
  { zipcode: '78704', label: 'Austin — South Congress (78704)' },
  { zipcode: '78745', label: 'Austin — South (78745)' },
  { zipcode: '73301', label: 'Austin — North (73301)' },
] as const
