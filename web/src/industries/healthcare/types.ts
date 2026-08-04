/** Response shapes of the healthcare dashboard REST API (tools/healthcare/*).
 *
 * The backend is a deterministic simulation (tools/healthcare records,
 * analytics, clinical, and scheduling handlers); many numeric-looking values
 * arrive as strings like "15.5%". All fields are typed defensively as optional.
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

export interface ImprovementOpportunity {
  area?: string
  gap?: string
  impact?: string // "HIGH" | "MEDIUM"
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
    readmission_rate_30d?: string // "12.4%"
    avg_encounters_per_patient_year?: number
    telehealth_utilization?: string // "28%"
  }
  improvement_opportunities?: ImprovementOpportunity[]
  report_period?: string
  source?: string
  error?: string
}

/* ------------------------------ patient summary -------------------------------- */

export interface PatientAllergy {
  allergen?: string
  reaction?: string
  severity?: string // "severe" | "moderate" | "mild"
  verified?: boolean
}

export interface PatientCondition {
  code?: string // ICD-10, e.g. "E11.9"
  description?: string
  onset?: string
  status?: string // "active" | "resolved"
}

export interface PatientSummary {
  patient_id?: string
  demographics?: {
    name?: string
    age?: number
    sex?: string
    date_of_birth?: string
    blood_type?: string
    primary_language?: string
    insurance?: string
    primary_care_provider?: string
  }
  active_conditions?: PatientCondition[]
  current_medications?: Array<{
    name?: string
    dosage?: string
    frequency?: string
    route?: string
    prescriber?: string
  }>
  allergies?: PatientAllergy[]
  recent_visits?: Array<{
    date?: string
    type?: string
    provider?: string
    chief_complaint?: string
    disposition?: string
  }>
  vitals_last_recorded?: {
    date?: string
    blood_pressure?: string // "128/82 mmHg"
    heart_rate?: string // "72 bpm"
    temperature?: string
    respiratory_rate?: string
    oxygen_saturation?: string // "98%"
    weight?: string // "185 lbs"
    height?: string
    bmi?: number
  }
  advance_directives?: boolean
  hipaa_notice?: string
  source?: string
  error?: string
}

/* ------------------------------ patient analytics ------------------------------ */

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

/* ------------------------------ readmission risk ------------------------------- */

export interface Comorbidity {
  condition?: string
  icd10?: string
}

export interface RecommendedIntervention {
  intervention?: string
  priority?: string // "HIGH" | "MEDIUM"
}

export interface ReadmissionRisk {
  patient_id?: string
  risk_model?: string
  risk_score?: number // 5.0 – 55.0
  risk_level?: string // "LOW" | "MODERATE" | "HIGH"
  risk_color?: string // "GREEN" | "YELLOW" | "RED"
  probability_30day_readmission?: string // "23.4%"
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
    health_literacy?: string // "adequate" | "limited"
    insurance_type?: string
  }
  contributing_factors?: string[]
  recommended_interventions?: RecommendedIntervention[]
  benchmark?: {
    national_avg_readmission_rate?: string // "15.6%"
    cms_penalty_threshold?: string // "15.4%"
  }
  disclaimer?: string
  source?: string
  error?: string
}

/* --------------------------------- care gaps ----------------------------------- */

export interface CareGap {
  measure?: string
  description?: string
  last_completed?: string | null
  due_date?: string
  status?: string // "OVERDUE" | "DUE SOON" | "NEVER COMPLETED"
  priority?: string // "HIGH" | "MEDIUM"
  quality_measure?: string
  applies_to?: string
}

export interface CareGapAnalysis {
  patient_id?: string
  patient_profile?: { age?: number; sex?: string }
  total_care_gaps?: number
  high_priority_gaps?: number
  care_gaps?: CareGap[]
  quality_impact?: {
    hedis_measures_affected?: number
    message?: string
  }
  recommended_actions?: string[]
  hipaa_notice?: string
  source?: string
  error?: string
}

/* -------------------------------- appointments --------------------------------- */

export interface UpcomingAppointment {
  appointment_id?: string
  date?: string
  time?: string
  day_of_week?: string
  appointment_type?: string
  provider?: { name?: string; specialty?: string }
  location?: string
  duration_minutes?: number
  status?: string // "Confirmed" | "Pending Confirmation"
  reminder_sent?: boolean
}

export interface AppointmentsResponse {
  patient_id?: string
  total_upcoming?: number
  appointments?: UpcomingAppointment[]
  next_appointment?: UpcomingAppointment | null
  reminders?: { pending_reminders?: number; message?: string }
  source?: string
  error?: string
}

/* ------------------------------- patient bundle -------------------------------- */

export interface PatientResponse {
  summary?: PatientSummary
  analytics?: PatientAnalytics
  readmission?: ReadmissionRisk
  care_gaps?: CareGapAnalysis
  appointments?: AppointmentsResponse
  error?: string
}

/* ------------------------------ labs & medications ----------------------------- */

export interface LabTest {
  test?: string
  value?: number
  unit?: string
  ref_range?: string
  flag?: string | null // "HIGH" | "LOW" | "BORDERLINE" | null
}

export interface LabPanel {
  panel_name?: string
  order_id?: string
  collection_date?: string
  result_date?: string
  ordering_provider?: string
  status?: string
  tests?: LabTest[]
}

export interface LabResults {
  patient_id?: string
  lookback_days?: number
  panels_returned?: number
  results?: LabPanel[]
  summary?: {
    total_tests?: number
    abnormal_count?: number
    critical_flags?: string[] | null
  }
  recommendation?: string
  hipaa_notice?: string
  source?: string
  error?: string
}

export interface MedicationEntry {
  name?: string
  generic?: boolean
  class?: string
  dosage?: string
  frequency?: string
  route?: string
  indication?: string
  prescriber?: string
  start_date?: string
  refills_remaining?: number
  last_filled?: string
  pharmacy?: string
  adherence_rate?: string // "92%"
  refill_alert?: string // "NEEDS RENEWAL - No refills remaining"
}

export interface MedicationAlert {
  type?: string // "REFILL_NEEDED" | "POLYPHARMACY"
  severity?: string
  message?: string
}

export interface MedicationList {
  patient_id?: string
  medication_count?: number
  medications?: MedicationEntry[]
  allergies_on_file?: PatientAllergy[]
  last_reconciliation?: string
  reconciled_by?: string
  alerts?: MedicationAlert[]
  hipaa_notice?: string
  source?: string
  error?: string
}

export interface LabsResponse {
  labs?: LabResults
  medications?: MedicationList
  error?: string
}

/* --------------------------------- risk scores --------------------------------- */

export interface RiskScoreResponse {
  patient_id?: string
  risk_model?: string // e.g. "ASCVD 10-Year Risk (Pooled Cohort Equations)"
  score?: number
  unit?: string // "% 10-year risk" | "points (0-10 scale)" | "points (0-125 scale)"
  interpretation?: string // "LOW RISK" | "MODERATE RISK" | "HIGH RISK" | …
  risk_category?: string
  input_parameters?: Record<string, unknown>
  risk_factors_present?: string[]
  recommendations?: string[]
  disclaimer?: string
  source?: string
  error?: string
  supported_risk_types?: string[]
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
