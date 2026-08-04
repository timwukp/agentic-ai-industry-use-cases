/** Response shapes for /api/insurance/* — mirrors tools/insurance handlers. */

export interface FraudMetrics {
  total_claims_screened?: number
  flagged_for_review?: number
  confirmed_fraud?: number
  false_positives?: number
  detection_rate_pct?: number
  false_positive_rate_pct?: number
  savings_from_detection?: number
}

export interface FraudType {
  type?: string
  count?: number
  pct?: number
}

export interface FraudDashboard {
  period?: string
  metrics?: FraudMetrics
  top_fraud_types?: FraudType[]
  trend?: string
  source?: string
  error?: string
}

export interface SettlementKpis {
  total_settlements?: number
  total_amount_paid?: number
  average_settlement?: number
  median_settlement?: number
  avg_processing_days?: number
  straight_through_rate_pct?: number
  customer_satisfaction?: number
}

export interface SettlementByType {
  count?: number
  avg_amount?: number
}

export interface SettlementTrend {
  settlements_vs_prior_month?: number
  avg_amount_vs_prior_month?: number
  processing_time_vs_prior_month?: number
}

export interface SettlementAnalytics {
  period?: string
  kpis?: SettlementKpis
  by_claim_type?: Record<string, SettlementByType>
  trend?: SettlementTrend
  source?: string
  error?: string
}

export interface OverviewResponse {
  fraud?: FraudDashboard
  settlement?: SettlementAnalytics
  error?: string
}

export interface ClaimRow {
  claim_id?: string
  status?: string
  claim_type?: string
  filed_date?: string
  amount?: number
  priority?: string
  fraud_risk?: number
}

export interface ClaimsResponse {
  filter?: string
  period_days?: number
  total_claims?: number
  /** Rows not yet CLOSED — what the "Open Claims" card counts. */
  open_claims?: number
  claims?: ClaimRow[]
  summary?: {
    total_amount?: number
    avg_amount?: number
    /** Sum over open claims only: a settled claim carries no reserve. */
    reserve_exposure?: number
    avg_open_amount?: number
    high_priority?: number
    flagged_fraud?: number
  }
  source?: string
  error?: string
}

export const CLAIM_STATUS_FILTERS = [
  'all',
  'open',
  'pending',
  'closed',
  'flagged',
] as const

export type ClaimStatusFilter = (typeof CLAIM_STATUS_FILTERS)[number]
