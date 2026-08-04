"""Gateway target: analytics — patient trends, population health, readmission risk, care gaps.

All analytics data is a deterministic simulation seeded from the function
inputs (stable within a calendar day).
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok
from toolkit.dispatch import dispatch

DISCLAIMER = ("Predictive model for clinical decision support. "
              "Individual patient assessment required.")


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day)


def get_patient_analytics(patient_id: str) -> dict:
    today = _today()
    r = _rng("patient_analytics", patient_id)
    months = [(today - timedelta(days=i * 30)).strftime("%Y-%m") for i in range(12, 0, -1)]

    base_systolic = r.randint(125, 155)
    base_diastolic = r.randint(75, 95)
    base_bmi = round(r.uniform(24.0, 36.0), 1)
    base_a1c = round(r.uniform(5.8, 9.5), 1)
    base_weight = r.randint(150, 260)
    base_ldl = r.randint(80, 180)
    drift = r.uniform(-0.3, 0.1)  # slight improvement trend

    bp_trend, bmi_trend, a1c_trend, weight_trend, ldl_trend = [], [], [], [], []
    for i, month in enumerate(months):
        bp_trend.append({
            "month": month,
            "systolic": max(105, base_systolic + r.randint(-8, 8) + int(drift * i * 2)),
            "diastolic": max(60, base_diastolic + r.randint(-5, 5) + int(drift * i)),
        })
        bmi_trend.append({"month": month,
                          "value": round(max(18.5, base_bmi + r.uniform(-0.3, 0.3) + drift * i * 0.2), 1)})
        if i % 3 == 0:
            a1c_trend.append({"month": month,
                              "value": round(max(4.5, base_a1c + r.uniform(-0.3, 0.3) + drift * i * 0.1), 1)})
        weight_trend.append({"month": month,
                             "value": max(100, base_weight + r.randint(-3, 3) + int(drift * i * 1.5))})
        if i % 6 == 0:
            ldl_trend.append({"month": month,
                              "value": max(40, base_ldl + r.randint(-15, 15) + int(drift * i * 2))})

    current_a1c = a1c_trend[-1]["value"]
    current_systolic = bp_trend[-1]["systolic"]
    current_bmi = bmi_trend[-1]["value"]
    weight_change = weight_trend[-1]["value"] - weight_trend[0]["value"]

    return tool_ok({
        "patient_id": patient_id,
        "analysis_period": f"{months[0]} to {months[-1]}",
        "trends": {
            "blood_pressure": {
                "data": bp_trend,
                "current": f"{bp_trend[-1]['systolic']}/{bp_trend[-1]['diastolic']} mmHg",
                "target": "<130/80 mmHg",
                "status": "AT TARGET" if current_systolic < 130 else "ABOVE TARGET",
                "trend_direction": ("improving" if bp_trend[-1]["systolic"] < bp_trend[0]["systolic"]
                                    else "worsening"),
            },
            "bmi": {
                "data": bmi_trend,
                "current": current_bmi,
                "classification": ("Normal" if current_bmi < 25 else "Overweight" if current_bmi < 30
                                   else "Obese Class I" if current_bmi < 35 else "Obese Class II+"),
                "trend_direction": ("improving" if bmi_trend[-1]["value"] < bmi_trend[0]["value"]
                                    else "stable" if abs(bmi_trend[-1]["value"] - bmi_trend[0]["value"]) < 0.5
                                    else "worsening"),
            },
            "hemoglobin_a1c": {
                "data": a1c_trend,
                "current": current_a1c,
                "target": "<7.0%",
                "status": "AT TARGET" if current_a1c < 7.0 else "ABOVE TARGET",
                "trend_direction": ("improving" if len(a1c_trend) >= 2
                                    and a1c_trend[-1]["value"] < a1c_trend[0]["value"] else "stable"),
            },
            "weight": {
                "data": weight_trend,
                "current": f"{weight_trend[-1]['value']} lbs",
                "change_12mo": f"{weight_change:+d} lbs",
                "trend_direction": "decreasing" if weight_change < 0 else "increasing",
            },
            "ldl_cholesterol": {
                "data": ldl_trend,
                "current": f"{ldl_trend[-1]['value']} mg/dL",
                "target": "<100 mg/dL (with diabetes/CVD risk)",
                "status": "AT TARGET" if ldl_trend[-1]["value"] < 100 else "ABOVE TARGET",
            },
        },
        "clinical_insights": [
            f"Blood pressure {'trending toward target' if bp_trend[-1]['systolic'] < bp_trend[0]['systolic'] else 'remains above target - consider medication adjustment'}",
            f"A1C {'at goal' if current_a1c < 7.0 else 'above target - review diabetes management plan'}",
            f"BMI {current_bmi} - {'healthy weight' if current_bmi < 25 else 'weight management counseling recommended'}",
            f"Weight change: {weight_change:+d} lbs over 12 months",
        ],
        "hipaa_notice": "Analytics access audit-logged.",
    }, simulated=True)


def get_population_health_metrics() -> dict:
    today = _today()
    r = _rng("population_health", today.strftime("%Y-%m"))
    total_patients = r.randint(2000, 8000)
    male_pct = r.randint(45, 55)

    return tool_ok({
        "practice_panel": {
            "total_active_patients": total_patients,
            "new_patients_30d": r.randint(30, 150),
            "average_age": round(r.uniform(42, 58), 1),
            "sex_distribution": {"male": f"{male_pct}%", "female": f"{100 - male_pct}%"},
        },
        "chronic_disease_prevalence": {
            "diabetes_type_2": {"count": r.randint(300, 800), "rate": f"{round(r.uniform(12, 22), 1)}%"},
            "hypertension": {"count": r.randint(500, 1200), "rate": f"{round(r.uniform(25, 40), 1)}%"},
            "hyperlipidemia": {"count": r.randint(400, 1000), "rate": f"{round(r.uniform(20, 35), 1)}%"},
            "obesity_bmi_30_plus": {"count": r.randint(600, 1500), "rate": f"{round(r.uniform(30, 42), 1)}%"},
            "depression_anxiety": {"count": r.randint(200, 600), "rate": f"{round(r.uniform(10, 20), 1)}%"},
            "asthma_copd": {"count": r.randint(150, 500), "rate": f"{round(r.uniform(8, 16), 1)}%"},
            "heart_failure": {"count": r.randint(50, 200), "rate": f"{round(r.uniform(3, 8), 1)}%"},
        },
        "quality_measures_hedis": {
            "diabetes_a1c_control_lt8": {"performance": f"{r.randint(65, 88)}%", "target": "75%", "national_avg": "72%"},
            "blood_pressure_control": {"performance": f"{r.randint(60, 85)}%", "target": "70%", "national_avg": "68%"},
            "breast_cancer_screening": {"performance": f"{r.randint(55, 82)}%", "target": "75%", "national_avg": "73%"},
            "colorectal_cancer_screening": {"performance": f"{r.randint(50, 78)}%", "target": "70%", "national_avg": "65%"},
            "flu_vaccination_rate": {"performance": f"{r.randint(40, 72)}%", "target": "70%", "national_avg": "52%"},
            "depression_screening": {"performance": f"{r.randint(55, 85)}%", "target": "80%", "national_avg": "65%"},
        },
        "utilization_metrics": {
            "ed_visits_per_1000": r.randint(150, 350),
            "hospital_admissions_per_1000": r.randint(50, 150),
            "readmission_rate_30d": f"{round(r.uniform(8, 18), 1)}%",
            "avg_encounters_per_patient_year": round(r.uniform(3.5, 7.0), 1),
            "telehealth_utilization": f"{r.randint(15, 40)}%",
        },
        "improvement_opportunities": [
            {"area": "Diabetes Management", "gap": "A1C testing overdue for 12% of diabetic patients", "impact": "HIGH"},
            {"area": "Preventive Screening", "gap": "Colorectal cancer screening below national target", "impact": "HIGH"},
            {"area": "Chronic Care", "gap": "15% of hypertensive patients without BP reading in 6 months", "impact": "MEDIUM"},
            {"area": "Immunizations", "gap": "Flu vaccination rate below organizational target", "impact": "MEDIUM"},
            {"area": "Behavioral Health", "gap": "Depression screening gap in 20% of eligible patients", "impact": "MEDIUM"},
        ],
        "report_period": (f"{(today - timedelta(days=90)).strftime('%Y-%m-%d')} "
                          f"to {today.strftime('%Y-%m-%d')}"),
    }, simulated=True)


def get_readmission_risk(patient_id: str) -> dict:
    r = _rng("readmission_risk", patient_id)
    risk_score = round(r.uniform(5.0, 55.0), 1)
    if risk_score < 15:
        risk_level, risk_color = "LOW", "GREEN"
    elif risk_score < 30:
        risk_level, risk_color = "MODERATE", "YELLOW"
    else:
        risk_level, risk_color = "HIGH", "RED"

    num_comorbidities = r.randint(1, 7)
    prior_admissions = r.randint(0, 4)
    ed_visits = r.randint(0, 6)
    age = r.randint(35, 90)

    comorbidities = r.sample([
        {"condition": "Heart Failure", "icd10": "I50.9"},
        {"condition": "COPD", "icd10": "J44.1"},
        {"condition": "Diabetes with complications", "icd10": "E11.65"},
        {"condition": "Chronic Kidney Disease Stage 3", "icd10": "N18.3"},
        {"condition": "Depression", "icd10": "F32.9"},
        {"condition": "Hypertension", "icd10": "I10"},
        {"condition": "Atrial Fibrillation", "icd10": "I48.91"},
        {"condition": "Anemia", "icd10": "D64.9"},
        {"condition": "Malnutrition", "icd10": "E46"},
    ], k=num_comorbidities)

    social = {
        "lives_alone": r.choice([True, False]),
        "transportation_barriers": r.choice([True, False, False]),
        "food_insecurity": r.choice([True, False, False, False]),
        "health_literacy": r.choice(["adequate", "adequate", "limited"]),
        "insurance_type": r.choice(["Commercial", "Medicare", "Medicaid", "Dual Eligible"]),
    }

    contributing = [f for f in [
        f"Age {age} (>65 elevated risk)" if age > 65 else None,
        f"{num_comorbidities} active comorbidities",
        f"{prior_admissions} hospital admissions in past 12 months" if prior_admissions else None,
        f"{ed_visits} ED visits in past 6 months" if ed_visits > 1 else None,
        "Lives alone - limited caregiver support" if social["lives_alone"] else None,
        "Transportation barriers to follow-up" if social["transportation_barriers"] else None,
        "Limited health literacy" if social["health_literacy"] == "limited" else None,
    ] if f]

    interventions = []
    if risk_level in ("MODERATE", "HIGH"):
        interventions += [
            {"intervention": "Transitional care management (TCM) visit within 7 days", "priority": "HIGH"},
            {"intervention": "Medication reconciliation by clinical pharmacist", "priority": "HIGH"},
            {"intervention": "Follow-up phone call within 48 hours of discharge", "priority": "HIGH"},
        ]
    if risk_level == "HIGH":
        interventions += [
            {"intervention": "Home health referral for post-discharge monitoring", "priority": "HIGH"},
            {"intervention": "Care coordinator assignment", "priority": "HIGH"},
            {"intervention": "Enroll in remote patient monitoring program", "priority": "MEDIUM"},
        ]
    if social["lives_alone"]:
        interventions.append({"intervention": "Social work consult for community support services",
                              "priority": "MEDIUM"})
    if social["transportation_barriers"]:
        interventions.append({"intervention": "Arrange medical transportation for follow-up visits",
                              "priority": "MEDIUM"})
    interventions.append({"intervention": "Patient education on warning signs requiring ED return",
                          "priority": "MEDIUM"})

    return tool_ok({
        "patient_id": patient_id,
        "risk_model": "Hospital Readmission Risk Prediction (LACE+ enhanced)",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "probability_30day_readmission": f"{risk_score}%",
        "clinical_profile": {
            "age": age,
            "comorbidity_count": num_comorbidities,
            "comorbidities": comorbidities,
            "prior_admissions_12mo": prior_admissions,
            "ed_visits_6mo": ed_visits,
        },
        "social_determinants": social,
        "contributing_factors": contributing,
        "recommended_interventions": interventions,
        "benchmark": {
            "national_avg_readmission_rate": "15.6%",
            "cms_penalty_threshold": "15.4%",
        },
        "disclaimer": DISCLAIMER,
    }, simulated=True)


def get_care_gap_analysis(patient_id: str) -> dict:
    today = _today()
    r = _rng("care_gaps", patient_id)
    age = r.randint(30, 80)
    sex = r.choice(["Male", "Female"])

    def past(lo, hi):
        return (today - timedelta(days=r.randint(lo, hi))).strftime("%Y-%m-%d")

    all_gaps = [
        {"measure": "Annual Wellness Visit", "description": "Comprehensive preventive health assessment",
         "last_completed": past(380, 800), "due_date": past(10, 200), "status": "OVERDUE",
         "priority": "HIGH", "quality_measure": "AWV (Annual Wellness Visit)",
         "applies_to": "All patients annually"},
        {"measure": "Hemoglobin A1C Test", "description": "Diabetes monitoring - glycemic control assessment",
         "last_completed": past(200, 400), "due_date": past(10, 100), "status": "OVERDUE",
         "priority": "HIGH", "quality_measure": "HEDIS CDC - HbA1c Testing",
         "applies_to": "Patients with diabetes"},
        {"measure": "Influenza Vaccination", "description": "Annual flu vaccine",
         "last_completed": past(365, 500), "due_date": "Next flu season (Oct)",
         "status": "DUE SOON", "priority": "MEDIUM", "quality_measure": "Flu Vaccination Rate",
         "applies_to": "All patients annually (Oct-Mar)"},
        {"measure": "Colorectal Cancer Screening",
         "description": "Colonoscopy or FIT test for colorectal cancer screening",
         "last_completed": past(3650, 5000), "due_date": past(10, 365), "status": "OVERDUE",
         "priority": "HIGH", "quality_measure": "HEDIS COL - Colorectal Cancer Screening",
         "applies_to": "Ages 45-75"},
        {"measure": "Mammogram", "description": "Breast cancer screening mammography",
         "last_completed": past(730, 1200), "due_date": past(10, 200), "status": "OVERDUE",
         "priority": "HIGH", "quality_measure": "HEDIS BCS - Breast Cancer Screening",
         "applies_to": "Females ages 50-74 (every 2 years)"},
        {"measure": "Lipid Panel", "description": "Fasting lipid profile for cardiovascular risk assessment",
         "last_completed": past(400, 800), "due_date": past(1, 100), "status": "OVERDUE",
         "priority": "MEDIUM", "quality_measure": "Statin Therapy Monitoring",
         "applies_to": "Patients on statins or with CVD risk factors"},
        {"measure": "Depression Screening (PHQ-9)", "description": "Annual depression screening questionnaire",
         "last_completed": past(400, 700), "due_date": past(10, 200), "status": "OVERDUE",
         "priority": "MEDIUM", "quality_measure": "HEDIS DSF - Depression Screening",
         "applies_to": "All patients ages 12+ annually"},
        {"measure": "Pneumococcal Vaccination (PCV20)", "description": "Pneumonia vaccine for high-risk adults",
         "last_completed": None, "due_date": "Due now", "status": "NEVER COMPLETED",
         "priority": "MEDIUM", "quality_measure": "Pneumococcal Vaccination Rate",
         "applies_to": "Ages 65+ or high-risk adults"},
        {"measure": "Eye Exam (Diabetic Retinopathy)",
         "description": "Annual dilated eye examination for diabetic patients",
         "last_completed": past(400, 800), "due_date": past(10, 150), "status": "OVERDUE",
         "priority": "HIGH", "quality_measure": "HEDIS EED - Eye Exam for Diabetes",
         "applies_to": "Patients with diabetes annually"},
        {"measure": "Kidney Function Screening (eGFR/UACR)",
         "description": "Annual nephropathy screening for diabetic patients",
         "last_completed": past(380, 600), "due_date": past(10, 100), "status": "OVERDUE",
         "priority": "HIGH", "quality_measure": "HEDIS KED - Kidney Evaluation for Diabetes",
         "applies_to": "Patients with diabetes annually"},
    ]

    applicable = [g for g in all_gaps if not (
        (g["measure"] == "Mammogram" and sex == "Male")
        or (g["measure"] == "Colorectal Cancer Screening" and age < 45)
        or (g["measure"] == "Pneumococcal Vaccination (PCV20)" and age < 65))]
    selected = r.sample(applicable, k=min(r.randint(3, 7), len(applicable)))
    selected.sort(key=lambda g: {"HIGH": 0, "MEDIUM": 1}.get(g["priority"], 2))
    high_priority = sum(1 for g in selected if g["priority"] == "HIGH")

    return tool_ok({
        "patient_id": patient_id,
        "patient_profile": {"age": age, "sex": sex},
        "total_care_gaps": len(selected),
        "high_priority_gaps": high_priority,
        "care_gaps": selected,
        "quality_impact": {
            "hedis_measures_affected": sum(1 for g in selected if "HEDIS" in g["quality_measure"]),
            "message": f"Closing these gaps would improve {high_priority} high-priority quality measures.",
        },
        "recommended_actions": [
            f"Schedule annual wellness visit to address {len(selected)} overdue items",
            "Order overdue lab work (A1C, lipid panel, eGFR/UACR) as standing orders",
            "Send patient outreach for overdue cancer screenings",
            "Update immunization record and administer due vaccines at next visit",
        ],
        "hipaa_notice": "Care gap analysis access audit-logged.",
    }, simulated=True)


TOOLS = {
    "get_patient_analytics": get_patient_analytics,
    "get_population_health_metrics": get_population_health_metrics,
    "get_readmission_risk": get_readmission_risk,
    "get_care_gap_analysis": get_care_gap_analysis,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
