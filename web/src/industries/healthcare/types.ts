/** Response shapes of the healthcare dashboard REST API (tools/healthcare/dashboard_api).
 *
 * The backend is a deterministic simulation (tools/healthcare/analytics and
 * tools/healthcare/scheduling handlers); many numeric-looking values arrive as
 * strings like "15.5%". All fields are typed defensively as optional.
 */

/* ---------------------------------- population --------------------------------- */

export interface ChronicDiseaseEntry {
  count?: number
  rate?: string // e.g. "15.5%"
}

export interface HedisMeasure {
  performance?: string // e.g. "81%"
  target?: string // e.g. "75%"
  national_avg?: string // e.g. "72%"
}

export interface PopulationResponse {
  practice_panel?: {
    total_active_patients?: number
    new_patients_30d?: number
    average_age?: number
    sex_distribution?: Record<string, string> // {"male": "46%", "female": "54%"}
  }
  chronic_disease_prevalence?: Record<string, ChronicDiseaseEntry>
  quality_measures_hedis?: Record<string, HedisMeasure>
  utilization_metrics?: {
    ed_visits_per_1000?: number
    hospital_admissions_per_1000?: number
    readmission_rate_30d?: string
    avg_encounters_per_patient_year?: number
    telehealth_utilization?: string
  }
  improvement_opportunities?: Array<{
    area?: string
    gap?: string
    impact?: string
  }>
  report_period?: string
  source?: string
  error?: string
}

/* ----------------------------------- patient ----------------------------------- */

export interface BpTrendPoint {
  month?: string
  systolic?: number
  diastolic?: number
}

export interface ValueTrendPoint {
  month?: string
  value?: number
}

export interface TrendMetric {
  data?: ValueTrendPoint[]
  current?: string | number
  target?: string
  status?: string // "AT TARGET" | "ABOVE TARGET"
  classification?: string
  change_12mo?: string
  trend_direction?: string
}

export interface PatientAnalytics {
  patient_id?: string
  analysis_period?: string
  trends?: {
    blood_pressure?: Omit<TrendMetric, 'data'> & { data?: BpTrendPoint[] }
    bmi?: TrendMetric
    hemoglobin_a1c?: TrendMetric
    weight?: TrendMetric
    ldl_cholesterol?: TrendMetric
  }
  clinical_insights?: string[]
  hipaa_notice?: string
  source?: string
  error?: string
}

export interface Comorbidity {
  condition?: string
  icd10?: string
}

export interface ReadmissionRisk {
  patient_id?: string
  risk_model?: string
  risk_score?: number // 5.0 – 55.0
  risk_level?: string // "LOW" | "MODERATE" | "HIGH"
  risk_color?: string // "GREEN" | "YELLOW" | "RED"
  probability_30day_readmission?: string
  clinical_profile?: {
    age?: number
    comorbidity_count?: number
    comorbidities?: Comorbidity[]
    prior_admissions_12mo?: number
    ed_visits_6mo?: number
  }
  social_determinants?: {
    lives_alone?: boolean
    transportation_barriers?: boolean
    food_insecurity?: boolean
    health_literacy?: string
    insurance_type?: string
  }
  contributing_factors?: string[]
  recommended_interventions?: Array<{
    intervention?: string
    priority?: string
  }>
  benchmark?: {
    national_avg_readmission_rate?: string
    cms_penalty_threshold?: string
  }
  disclaimer?: string
  source?: string
  error?: string
}

export interface PatientResponse {
  analytics?: PatientAnalytics
  readmission?: ReadmissionRisk
  error?: string
}

/* --------------------------------- availability -------------------------------- */

export interface AvailabilitySlot {
  time?: string // "08:30"
  duration_minutes?: number
  slot_type?: string // "in-person" | "telehealth"
}

export interface AvailabilityDay {
  date?: string // "2026-08-05"
  day_of_week?: string // "Wednesday"
  available_slots?: AvailabilitySlot[]
  total_open_slots?: number
}

export interface AvailabilityResponse {
  provider_id?: string
  provider?: {
    name?: string
    specialty?: string
    location?: string
  }
  date_range?: { start?: string; end?: string }
  availability?: AvailabilityDay[]
  summary?: {
    total_available_days?: number
    total_available_slots?: number
    earliest_available?: string
    message?: string
  }
  booking_note?: string
  source?: string
  error?: string
}

/* ---------------------------------- helpers ------------------------------------ */

/** Parses "81%" / "15.5%" (or a bare number) to a number; null when unparsable. */
export function parsePct(value: string | number | undefined | null): number | null {
  if (value == null) return null
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  const n = Number.parseFloat(value.replace('%', '').trim())
  return Number.isFinite(n) ? n : null
}

/** "diabetes_type_2" → "Diabetes Type 2" (fallback label for unknown keys). */
export function labelize(key: string): string {
  return key
    .split('_')
    .map((w) => (w.length ? w[0].toUpperCase() + w.slice(1) : w))
    .join(' ')
}
