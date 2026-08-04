/** Response shapes for /api/manufacturing/* — mirrors tools/manufacturing. */

export interface EquipmentRow {
  equipment_id?: string
  name?: string
  department?: string
  status?: string
  health_score?: number
  criticality?: string
  last_maintenance?: string
  next_scheduled_maintenance?: string
}

export interface FleetResponse {
  facility_id?: string
  total_equipment?: number
  status_summary?: Record<string, number>
  avg_health_score?: number
  equipment?: EquipmentRow[]
  critical_equipment_below_threshold?: EquipmentRow[]
  source?: string
}

export interface EquipmentAlert {
  alert_id?: string
  equipment_id?: string
  type?: string
  severity?: string
  message?: string
  action?: string
  triggered_at?: string
  acknowledged?: boolean
}

export interface AlertsResponse {
  total_alerts?: number
  severity_counts?: { critical?: number; warning?: number; info?: number }
  unacknowledged?: number
  alerts?: EquipmentAlert[]
  recommendation?: string
  source?: string
}

export interface ScheduleEntry {
  schedule_id?: string
  equipment_id?: string
  date?: string
  start_time?: string
  duration_hours?: number
  type?: string
  priority?: string
  description?: string
  assigned_to?: string
  status?: string
}

export interface CalendarResponse {
  facility_id?: string
  period_days?: number
  total_scheduled?: number
  schedule?: ScheduleEntry[]
  weekly_capacity?: Record<string, { maintenance_hours?: number; events?: number }>
  resource_utilization?: {
    total_maintenance_hours?: number
    technician_hours_available?: number
    utilization_pct?: number
  }
  conflicts?: unknown[]
  source?: string
}

export interface PartsResponse {
  report_date?: string
  inventory_summary?: {
    total_part_numbers?: number
    total_inventory_value?: number
    total_stockout_items?: number
    total_excess_value?: number
    overall_service_level_pct?: number
    inventory_accuracy_pct?: number
  }
  critical_stockouts?: Array<{
    part_number?: string
    description?: string
    equipment_affected?: string
    days_out_of_stock?: number
  }>
  kpis?: {
    inventory_turnover_ratio?: number
    fill_rate_pct?: number
    dead_stock_pct?: number
    carrying_cost_pct?: number
    avg_days_to_fulfill?: number
  }
  recommendations?: string[]
  source?: string
}

export interface OverviewResponse {
  fleet?: FleetResponse
  alerts?: AlertsResponse
  calendar?: CalendarResponse
  parts?: PartsResponse
  error?: string
}

export interface PredictionResponse {
  equipment_id?: string
  prediction_model?: string
  model_accuracy?: number
  primary_prediction?: {
    failure_mode?: string
    affected_component?: string
    remaining_useful_life_days?: number
    estimated_failure_date?: string
    failure_probability?: number
    confidence_interval?: {
      lower_days?: number
      upper_days?: number
      confidence_level?: number
    }
  }
  secondary_prediction?: {
    failure_mode?: string
    affected_component?: string
    probability?: number
  }
  risk_level?: string
  degradation_trend?: {
    current_degradation_pct?: number
    degradation_rate_per_day?: number
    acceleration?: string
  }
  contributing_factors?: Array<{ factor?: string; impact?: string }>
  recommended_action?: string
  source?: string
}

export interface ReliabilityResponse {
  equipment_id?: string
  period?: string
  reliability_metrics?: {
    mtbf_hours?: number
    mtbf_days?: number
    mttr_hours?: number
    failure_rate_per_1000h?: number
  }
  oee_breakdown?: {
    oee_pct?: number
    availability_pct?: number
    performance_rate_pct?: number
    quality_rate_pct?: number
    oee_class?: string
  }
  failure_history?: {
    total_failures_12m?: number
    /** Breakdown repair hours — the sum of count x avg_repair_hours below. */
    total_downtime_hours?: number
    top_failure_modes?: Array<{
      mode?: string
      count?: number
      avg_repair_hours?: number
    }>
    /** Scheduled maintenance hours; the denominator of unplanned_downtime_pct. */
    planned_downtime_hours?: number
    unplanned_downtime_pct?: number
  }
  trends?: Record<string, string | number>
  benchmarks?: {
    industry_avg_oee?: number
    industry_avg_mtbf_hours?: number
    vs_industry_oee?: number
    vs_industry_mtbf?: number
  }
  source?: string
}

export interface EquipmentDetailResponse {
  prediction?: PredictionResponse
  reliability?: ReliabilityResponse
  error?: string
}

export interface SensorResponse {
  equipment_id?: string
  sensor_type?: string
  unit?: string
  period_hours?: number
  data_points?: number
  readings?: Array<{ timestamp?: string; value?: number }>
  statistics?: {
    mean?: number
    min?: number
    max?: number
    std_dev?: number
    trend?: string
    trend_rate_per_hour?: number
  }
  thresholds?: {
    warning?: number
    critical?: number
    /** Which side of the line is the fault: oil pressure fails LOW, the rest HIGH. */
    breach_direction?: 'ABOVE' | 'BELOW'
    breaches_warning?: number
    breaches_critical?: number
  }
  source?: string
  error?: string
}

export const SENSOR_TYPES = ['vibration', 'temperature', 'pressure'] as const
