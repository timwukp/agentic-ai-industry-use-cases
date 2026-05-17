from strands import tool
import json
import random
from datetime import datetime, timedelta


@tool
def monitor_patient_metrics(patient_id: str) -> str:
    """Monitor key health metrics and identify deterioration trends.

    Tracks vital signs, lab values, and patient-reported outcomes over time
    to detect patterns that may indicate disease progression or treatment
    failure requiring intervention.

    Args:
        patient_id: The patient identifier to monitor metrics for.

    Returns:
        JSON string with current metrics, trend analysis, and alert status.
    """
    conditions = ["Type 2 Diabetes", "Hypertension", "Heart Failure", "COPD", "Chronic Kidney Disease"]
    primary_condition = random.choice(conditions)

    metrics_by_condition = {
        "Type 2 Diabetes": {
            "hba1c_pct": {"value": round(random.uniform(5.5, 11.0), 1), "target": 7.0, "unit": "%"},
            "fasting_glucose_mg_dl": {"value": random.randint(70, 250), "target": 130, "unit": "mg/dL"},
            "blood_pressure_systolic": {"value": random.randint(110, 170), "target": 130, "unit": "mmHg"},
            "weight_lbs": {"value": round(random.uniform(150, 280), 1), "target": None, "unit": "lbs"},
            "egfr_ml_min": {"value": random.randint(30, 120), "target": 60, "unit": "mL/min"},
        },
        "Hypertension": {
            "systolic_bp": {"value": random.randint(110, 180), "target": 130, "unit": "mmHg"},
            "diastolic_bp": {"value": random.randint(60, 110), "target": 80, "unit": "mmHg"},
            "heart_rate_bpm": {"value": random.randint(55, 100), "target": None, "unit": "bpm"},
            "sodium_meq_l": {"value": round(random.uniform(135, 148), 1), "target": None, "unit": "mEq/L"},
            "creatinine_mg_dl": {"value": round(random.uniform(0.7, 2.0), 2), "target": 1.2, "unit": "mg/dL"},
        },
        "Heart Failure": {
            "bnp_pg_ml": {"value": random.randint(50, 1500), "target": 100, "unit": "pg/mL"},
            "ejection_fraction_pct": {"value": random.randint(20, 60), "target": 50, "unit": "%"},
            "weight_lbs": {"value": round(random.uniform(140, 260), 1), "target": None, "unit": "lbs"},
            "systolic_bp": {"value": random.randint(90, 160), "target": 130, "unit": "mmHg"},
            "heart_rate_bpm": {"value": random.randint(55, 110), "target": None, "unit": "bpm"},
        },
        "COPD": {
            "fev1_pct_predicted": {"value": random.randint(30, 90), "target": 80, "unit": "%"},
            "oxygen_saturation_pct": {"value": round(random.uniform(88, 99), 1), "target": 92, "unit": "%"},
            "respiratory_rate": {"value": random.randint(12, 28), "target": 20, "unit": "breaths/min"},
            "peak_flow_l_min": {"value": random.randint(200, 600), "target": 400, "unit": "L/min"},
            "exacerbations_30d": {"value": random.randint(0, 4), "target": 0, "unit": "count"},
        },
        "Chronic Kidney Disease": {
            "egfr_ml_min": {"value": random.randint(15, 90), "target": 60, "unit": "mL/min"},
            "creatinine_mg_dl": {"value": round(random.uniform(1.0, 5.0), 2), "target": 1.2, "unit": "mg/dL"},
            "albumin_creatinine_ratio": {"value": random.randint(30, 500), "target": 30, "unit": "mg/g"},
            "potassium_meq_l": {"value": round(random.uniform(3.5, 6.0), 1), "target": None, "unit": "mEq/L"},
            "hemoglobin_g_dl": {"value": round(random.uniform(8.0, 15.0), 1), "target": 12.0, "unit": "g/dL"},
        },
    }

    current_metrics = metrics_by_condition[primary_condition]
    alerts = []
    for name, metric in current_metrics.items():
        if metric["target"] and metric["value"] > metric["target"] * 1.2:
            alerts.append({"metric": name, "status": "ABOVE_TARGET", "value": metric["value"]})

    overall_status = "STABLE" if len(alerts) == 0 else "MONITORING" if len(alerts) <= 1 else "DETERIORATING"

    return json.dumps({
        "patient_id": patient_id,
        "primary_condition": primary_condition,
        "overall_status": overall_status,
        "current_metrics": current_metrics,
        "alerts": alerts,
        "trend_analysis": {
            "direction": random.choice(["IMPROVING", "STABLE", "WORSENING"]),
            "trend_period_days": 30,
            "confidence": round(random.uniform(0.7, 0.95), 2),
        },
        "last_provider_visit": (datetime.utcnow() - timedelta(days=random.randint(7, 90))).strftime("%Y-%m-%d"),
        "next_scheduled_visit": (datetime.utcnow() + timedelta(days=random.randint(7, 60))).strftime("%Y-%m-%d"),
        "monitored_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def assess_adherence(patient_id: str) -> str:
    """Assess medication and treatment adherence for a patient.

    Evaluates prescription refill patterns, appointment attendance, and
    self-reported compliance to determine overall treatment adherence
    and identify barriers.

    Args:
        patient_id: The patient identifier to assess adherence for.

    Returns:
        JSON string with adherence scores, patterns, and barrier identification.
    """
    overall_adherence_pct = round(random.uniform(40, 98), 1)

    medications = []
    med_names = ["Metformin", "Lisinopril", "Atorvastatin", "Metoprolol", "Amlodipine"]
    for med in random.sample(med_names, random.randint(2, 4)):
        med_adherence = round(random.uniform(50, 100), 1)
        medications.append({
            "medication": med,
            "adherence_pct": med_adherence,
            "refill_gap_days": random.randint(0, 14),
            "doses_missed_30d": random.randint(0, 10),
            "status": "ADHERENT" if med_adherence >= 80 else "PARTIAL" if med_adherence >= 60 else "NON_ADHERENT",
        })

    barriers = random.sample([
        {"barrier": "Cost/affordability concerns", "severity": "HIGH"},
        {"barrier": "Side effect intolerance", "severity": "MEDIUM"},
        {"barrier": "Complex medication regimen", "severity": "MEDIUM"},
        {"barrier": "Forgetfulness", "severity": "LOW"},
        {"barrier": "Lack of perceived benefit", "severity": "MEDIUM"},
        {"barrier": "Transportation to pharmacy", "severity": "LOW"},
        {"barrier": "Health literacy challenges", "severity": "MEDIUM"},
    ], random.randint(1, 3))

    if overall_adherence_pct >= 80:
        adherence_category = "ADHERENT"
    elif overall_adherence_pct >= 60:
        adherence_category = "PARTIALLY_ADHERENT"
    else:
        adherence_category = "NON_ADHERENT"

    return json.dumps({
        "patient_id": patient_id,
        "overall_adherence_pct": overall_adherence_pct,
        "adherence_category": adherence_category,
        "medication_adherence": medications,
        "appointment_adherence": {
            "scheduled_visits_6m": random.randint(3, 8),
            "attended_visits_6m": random.randint(2, 8),
            "no_show_rate_pct": round(random.uniform(0, 30), 1),
            "cancellation_rate_pct": round(random.uniform(0, 20), 1),
        },
        "barriers_identified": barriers,
        "interventions_recommended": random.sample([
            "Simplify medication regimen (combination pills)",
            "Set up automatic refill reminders",
            "Explore patient assistance programs for cost",
            "Schedule motivational interviewing session",
            "Implement pill organizer or smart dispenser",
            "Switch to extended-release formulation",
        ], random.randint(2, 3)),
        "assessed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_care_plan(patient_id: str, conditions: str) -> str:
    """Generate a personalized chronic disease care plan.

    Creates a comprehensive, patient-centered care plan that includes
    treatment goals, medication management, lifestyle modifications,
    monitoring schedule, and care team coordination.

    Args:
        patient_id: The patient identifier to generate a care plan for.
        conditions: Comma-separated list of chronic conditions (e.g., 'diabetes,hypertension,obesity').

    Returns:
        JSON string with structured care plan including goals, interventions, and monitoring schedule.
    """
    condition_list = [c.strip() for c in conditions.split(",")]
    plan_id = f"CP-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    goals = []
    for condition in condition_list[:3]:
        goals.append({
            "condition": condition,
            "short_term_goal": random.choice([
                f"Reduce {condition} symptoms within 30 days",
                f"Achieve target metrics for {condition} within 90 days",
                f"Establish consistent treatment routine for {condition}",
            ]),
            "long_term_goal": random.choice([
                f"Maintain optimal control of {condition} for 12 months",
                f"Prevent complications related to {condition}",
                f"Reduce hospitalization risk from {condition}",
            ]),
            "target_metric": random.choice([
                "HbA1c < 7%", "BP < 130/80", "LDL < 100 mg/dL",
                "Weight loss 5-10%", "FEV1 > 80%", "eGFR stable",
            ]),
        })

    monitoring_schedule = [
        {"activity": "Home vital signs", "frequency": "Daily", "responsible": "Patient"},
        {"activity": "Lab work (comprehensive metabolic panel)", "frequency": "Every 3 months", "responsible": "PCP"},
        {"activity": "Specialist follow-up", "frequency": "Every 6 months", "responsible": "Specialist"},
        {"activity": "Medication review", "frequency": "Monthly", "responsible": "Pharmacist"},
        {"activity": "Lifestyle assessment", "frequency": "Every 3 months", "responsible": "Care Coordinator"},
    ]

    return json.dumps({
        "plan_id": plan_id,
        "patient_id": patient_id,
        "conditions": condition_list,
        "goals": goals,
        "interventions": {
            "medications": random.sample([
                "Continue current regimen with dose optimization",
                "Add complementary therapy for better control",
                "Switch to combination medication for simplicity",
            ], 2),
            "lifestyle_modifications": random.sample([
                "Mediterranean diet plan with nutritionist referral",
                "150 minutes moderate exercise per week",
                "Stress reduction through mindfulness program",
                "Sleep hygiene improvement protocol",
                "Smoking cessation program enrollment",
            ], random.randint(2, 4)),
            "patient_education": [
                "Disease self-management training",
                "Medication management education",
                "Warning signs and when to seek care",
            ],
        },
        "monitoring_schedule": monitoring_schedule,
        "care_team": [
            {"role": "Primary Care Physician", "responsibility": "Overall care coordination"},
            {"role": "Specialist", "responsibility": "Condition-specific management"},
            {"role": "Care Coordinator", "responsibility": "Adherence support and navigation"},
            {"role": "Pharmacist", "responsibility": "Medication therapy management"},
        ],
        "review_date": (datetime.utcnow() + timedelta(days=90)).strftime("%Y-%m-%d"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def trigger_escalation_alert(patient_id: str, metric: str, value: float) -> str:
    """Trigger an escalation alert when patient metrics exceed thresholds.

    Evaluates the reported metric value against clinical thresholds and
    generates appropriate escalation notifications to the care team
    based on severity.

    Args:
        patient_id: The patient identifier triggering the alert.
        metric: The metric name that exceeded threshold (e.g., 'blood_pressure', 'glucose', 'weight').
        value: The actual measured value that triggered the alert.

    Returns:
        JSON string with escalation alert details, severity, and recommended response.
    """
    thresholds = {
        "blood_pressure": {"warning": 140, "critical": 180, "unit": "mmHg systolic"},
        "glucose": {"warning": 250, "critical": 400, "unit": "mg/dL"},
        "weight": {"warning": 3, "critical": 5, "unit": "lbs gained in 48hrs"},
        "heart_rate": {"warning": 110, "critical": 150, "unit": "bpm"},
        "oxygen_saturation": {"warning": 92, "critical": 88, "unit": "%"},
        "temperature": {"warning": 100.4, "critical": 103, "unit": "F"},
    }

    threshold_info = thresholds.get(metric, {"warning": value * 0.8, "critical": value * 0.9, "unit": "units"})

    if metric == "oxygen_saturation":
        is_critical = value <= threshold_info["critical"]
        is_warning = value <= threshold_info["warning"] and not is_critical
    else:
        is_critical = value >= threshold_info["critical"]
        is_warning = value >= threshold_info["warning"] and not is_critical

    severity = "CRITICAL" if is_critical else "WARNING" if is_warning else "INFORMATIONAL"
    alert_id = f"ESC-{datetime.now().strftime('%Y%m%d%H%M')}-{random.randint(1000, 9999)}"

    response_actions = {
        "CRITICAL": [
            "Immediately notify on-call provider",
            "Contact patient for symptom assessment",
            "Consider emergency department referral",
            "Document in patient chart with priority flag",
        ],
        "WARNING": [
            "Notify primary care team within 4 hours",
            "Schedule same-day telehealth check-in",
            "Review and adjust treatment plan if needed",
            "Increase monitoring frequency",
        ],
        "INFORMATIONAL": [
            "Log for trend analysis",
            "Review at next scheduled appointment",
            "Send patient self-management reminder",
        ],
    }

    return json.dumps({
        "alert_id": alert_id,
        "patient_id": patient_id,
        "metric": metric,
        "measured_value": value,
        "unit": threshold_info["unit"],
        "severity": severity,
        "thresholds": {
            "warning_level": threshold_info["warning"],
            "critical_level": threshold_info["critical"],
        },
        "response_actions": response_actions[severity],
        "notification_targets": [
            {"role": "Primary Care Physician", "method": "EHR alert + page" if severity == "CRITICAL" else "EHR alert"},
            {"role": "Care Coordinator", "method": "SMS notification"},
            {"role": "Patient", "method": "App notification"},
        ] if severity != "INFORMATIONAL" else [{"role": "Care Coordinator", "method": "Dashboard update"}],
        "auto_response_triggered": severity == "CRITICAL",
        "triggered_at": datetime.utcnow().isoformat() + "Z",
    })
