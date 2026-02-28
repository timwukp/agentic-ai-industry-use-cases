from strands import tool
import json, random
from datetime import datetime, timedelta


@tool
def get_patient_analytics(patient_id: str) -> str:
    """Get patient health trend analytics over time including BMI, blood pressure, A1C, and other key metrics.

    Retrieves longitudinal health data for trend visualization and clinical review.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234').

    Returns:
        JSON with health metric trends over 12 months, current status, and clinical notes.
    """
    months = []
    base_date = datetime.utcnow()
    for i in range(12, 0, -1):
        month_date = base_date - timedelta(days=i * 30)
        months.append(month_date.strftime("%Y-%m"))

    # Generate realistic trending data
    base_systolic = random.randint(125, 155)
    base_diastolic = random.randint(75, 95)
    base_bmi = round(random.uniform(24.0, 36.0), 1)
    base_a1c = round(random.uniform(5.8, 9.5), 1)
    base_weight = random.randint(150, 260)
    base_ldl = random.randint(80, 180)

    bp_trend = []
    bmi_trend = []
    a1c_trend = []
    weight_trend = []
    ldl_trend = []

    for i, month in enumerate(months):
        drift = random.uniform(-0.3, 0.1)  # Slight improvement trend
        bp_trend.append({
            "month": month,
            "systolic": max(105, base_systolic + random.randint(-8, 8) + int(drift * i * 2)),
            "diastolic": max(60, base_diastolic + random.randint(-5, 5) + int(drift * i)),
        })
        bmi_trend.append({
            "month": month,
            "value": round(max(18.5, base_bmi + random.uniform(-0.3, 0.3) + drift * i * 0.2), 1),
        })
        if i % 3 == 0:  # A1C measured quarterly
            a1c_trend.append({
                "month": month,
                "value": round(max(4.5, base_a1c + random.uniform(-0.3, 0.3) + drift * i * 0.1), 1),
            })
        weight_trend.append({
            "month": month,
            "value": max(100, base_weight + random.randint(-3, 3) + int(drift * i * 1.5)),
        })
        if i % 6 == 0:  # Lipids measured every 6 months
            ldl_trend.append({
                "month": month,
                "value": max(40, base_ldl + random.randint(-15, 15) + int(drift * i * 2)),
            })

    current_a1c = a1c_trend[-1]["value"] if a1c_trend else base_a1c
    current_systolic = bp_trend[-1]["systolic"]
    current_bmi = bmi_trend[-1]["value"]

    return json.dumps({
        "patient_id": patient_id,
        "analysis_period": f"{months[0]} to {months[-1]}",
        "trends": {
            "blood_pressure": {
                "data": bp_trend,
                "current": f"{bp_trend[-1]['systolic']}/{bp_trend[-1]['diastolic']} mmHg",
                "target": "<130/80 mmHg",
                "status": "AT TARGET" if current_systolic < 130 else "ABOVE TARGET",
                "trend_direction": "improving" if bp_trend[-1]["systolic"] < bp_trend[0]["systolic"] else "worsening",
            },
            "bmi": {
                "data": bmi_trend,
                "current": bmi_trend[-1]["value"],
                "classification": "Normal" if current_bmi < 25 else "Overweight" if current_bmi < 30 else "Obese Class I" if current_bmi < 35 else "Obese Class II+",
                "trend_direction": "improving" if bmi_trend[-1]["value"] < bmi_trend[0]["value"] else "stable" if abs(bmi_trend[-1]["value"] - bmi_trend[0]["value"]) < 0.5 else "worsening",
            },
            "hemoglobin_a1c": {
                "data": a1c_trend,
                "current": current_a1c,
                "target": "<7.0%",
                "status": "AT TARGET" if current_a1c < 7.0 else "ABOVE TARGET",
                "trend_direction": "improving" if len(a1c_trend) >= 2 and a1c_trend[-1]["value"] < a1c_trend[0]["value"] else "stable",
            },
            "weight": {
                "data": weight_trend,
                "current": f"{weight_trend[-1]['value']} lbs",
                "change_12mo": f"{weight_trend[-1]['value'] - weight_trend[0]['value']:+d} lbs",
                "trend_direction": "decreasing" if weight_trend[-1]["value"] < weight_trend[0]["value"] else "increasing",
            },
            "ldl_cholesterol": {
                "data": ldl_trend,
                "current": f"{ldl_trend[-1]['value']} mg/dL" if ldl_trend else "Not measured recently",
                "target": "<100 mg/dL (with diabetes/CVD risk)",
                "status": "AT TARGET" if ldl_trend and ldl_trend[-1]["value"] < 100 else "ABOVE TARGET",
            },
        },
        "clinical_insights": [
            f"Blood pressure {'trending toward target' if bp_trend[-1]['systolic'] < bp_trend[0]['systolic'] else 'remains above target - consider medication adjustment'}",
            f"A1C {'at goal' if current_a1c < 7.0 else 'above target - review diabetes management plan'}",
            f"BMI {current_bmi} - {'healthy weight' if current_bmi < 25 else 'weight management counseling recommended'}",
            f"Weight change: {weight_trend[-1]['value'] - weight_trend[0]['value']:+d} lbs over 12 months",
        ],
        "hipaa_notice": "Analytics access audit-logged.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_population_health_metrics() -> str:
    """Get population-level health metrics for the department or practice.

    Retrieves aggregate health metrics including disease prevalence, quality measures,
    and performance benchmarks for the practice panel.

    Returns:
        JSON with population health statistics, quality measure performance, and improvement opportunities.
    """
    total_patients = random.randint(2000, 8000)

    return json.dumps({
        "practice_panel": {
            "total_active_patients": total_patients,
            "new_patients_30d": random.randint(30, 150),
            "average_age": round(random.uniform(42, 58), 1),
            "sex_distribution": {"male": f"{random.randint(45, 55)}%", "female": f"{100 - random.randint(45, 55)}%"},
        },
        "chronic_disease_prevalence": {
            "diabetes_type_2": {"count": random.randint(300, 800), "rate": f"{round(random.uniform(12, 22), 1)}%"},
            "hypertension": {"count": random.randint(500, 1200), "rate": f"{round(random.uniform(25, 40), 1)}%"},
            "hyperlipidemia": {"count": random.randint(400, 1000), "rate": f"{round(random.uniform(20, 35), 1)}%"},
            "obesity_bmi_30_plus": {"count": random.randint(600, 1500), "rate": f"{round(random.uniform(30, 42), 1)}%"},
            "depression_anxiety": {"count": random.randint(200, 600), "rate": f"{round(random.uniform(10, 20), 1)}%"},
            "asthma_copd": {"count": random.randint(150, 500), "rate": f"{round(random.uniform(8, 16), 1)}%"},
            "heart_failure": {"count": random.randint(50, 200), "rate": f"{round(random.uniform(3, 8), 1)}%"},
        },
        "quality_measures_hedis": {
            "diabetes_a1c_control_lt8": {"performance": f"{random.randint(65, 88)}%", "target": "75%", "national_avg": "72%"},
            "blood_pressure_control": {"performance": f"{random.randint(60, 85)}%", "target": "70%", "national_avg": "68%"},
            "breast_cancer_screening": {"performance": f"{random.randint(55, 82)}%", "target": "75%", "national_avg": "73%"},
            "colorectal_cancer_screening": {"performance": f"{random.randint(50, 78)}%", "target": "70%", "national_avg": "65%"},
            "flu_vaccination_rate": {"performance": f"{random.randint(40, 72)}%", "target": "70%", "national_avg": "52%"},
            "depression_screening": {"performance": f"{random.randint(55, 85)}%", "target": "80%", "national_avg": "65%"},
        },
        "utilization_metrics": {
            "ed_visits_per_1000": random.randint(150, 350),
            "hospital_admissions_per_1000": random.randint(50, 150),
            "readmission_rate_30d": f"{round(random.uniform(8, 18), 1)}%",
            "avg_encounters_per_patient_year": round(random.uniform(3.5, 7.0), 1),
            "telehealth_utilization": f"{random.randint(15, 40)}%",
        },
        "improvement_opportunities": [
            {"area": "Diabetes Management", "gap": "A1C testing overdue for 12% of diabetic patients", "impact": "HIGH"},
            {"area": "Preventive Screening", "gap": "Colorectal cancer screening below national target", "impact": "HIGH"},
            {"area": "Chronic Care", "gap": "15% of hypertensive patients without BP reading in 6 months", "impact": "MEDIUM"},
            {"area": "Immunizations", "gap": "Flu vaccination rate below organizational target", "impact": "MEDIUM"},
            {"area": "Behavioral Health", "gap": "Depression screening gap in 20% of eligible patients", "impact": "MEDIUM"},
        ],
        "report_period": f"{(datetime.utcnow() - timedelta(days=90)).strftime('%Y-%m-%d')} to {datetime.utcnow().strftime('%Y-%m-%d')}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_readmission_risk(patient_id: str) -> str:
    """Predict 30-day hospital readmission risk for a patient.

    Uses clinical factors, social determinants, and utilization history
    to calculate readmission probability and identify modifiable risk factors.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234').

    Returns:
        JSON with readmission risk score, contributing factors, and intervention recommendations.
    """
    risk_score = round(random.uniform(5.0, 55.0), 1)

    if risk_score < 15:
        risk_level = "LOW"
        risk_color = "GREEN"
    elif risk_score < 30:
        risk_level = "MODERATE"
        risk_color = "YELLOW"
    else:
        risk_level = "HIGH"
        risk_color = "RED"

    num_comorbidities = random.randint(1, 7)
    prior_admissions_12mo = random.randint(0, 4)
    ed_visits_6mo = random.randint(0, 6)
    age = random.randint(35, 90)

    comorbidities = random.sample([
        {"condition": "Heart Failure", "icd10": "I50.9", "weight": 0.15},
        {"condition": "COPD", "icd10": "J44.1", "weight": 0.12},
        {"condition": "Diabetes with complications", "icd10": "E11.65", "weight": 0.10},
        {"condition": "Chronic Kidney Disease Stage 3", "icd10": "N18.3", "weight": 0.13},
        {"condition": "Depression", "icd10": "F32.9", "weight": 0.08},
        {"condition": "Hypertension", "icd10": "I10", "weight": 0.05},
        {"condition": "Atrial Fibrillation", "icd10": "I48.91", "weight": 0.09},
        {"condition": "Anemia", "icd10": "D64.9", "weight": 0.06},
        {"condition": "Malnutrition", "icd10": "E46", "weight": 0.11},
    ], k=min(num_comorbidities, 9))

    social_determinants = {
        "lives_alone": random.choice([True, False]),
        "transportation_barriers": random.choice([True, False, False]),
        "food_insecurity": random.choice([True, False, False, False]),
        "health_literacy": random.choice(["adequate", "adequate", "limited"]),
        "primary_language_english": random.choice([True, True, True, False]),
        "insurance_type": random.choice(["Commercial", "Medicare", "Medicaid", "Dual Eligible"]),
    }

    contributing_factors = [
        f for f in [
            f"Age {age} (>65 elevated risk)" if age > 65 else None,
            f"{num_comorbidities} active comorbidities (Charlson Comorbidity Index: {random.randint(2, 8)})",
            f"{prior_admissions_12mo} hospital admissions in past 12 months" if prior_admissions_12mo > 0 else None,
            f"{ed_visits_6mo} ED visits in past 6 months" if ed_visits_6mo > 1 else None,
            "Polypharmacy (>5 medications)" if random.random() > 0.4 else None,
            "Lives alone - limited caregiver support" if social_determinants["lives_alone"] else None,
            "Transportation barriers to follow-up" if social_determinants["transportation_barriers"] else None,
            "Limited health literacy" if social_determinants["health_literacy"] == "limited" else None,
            "Discharge medication complexity" if random.random() > 0.5 else None,
        ] if f is not None
    ]

    interventions = []
    if risk_level in ("MODERATE", "HIGH"):
        interventions.extend([
            {"intervention": "Transitional care management (TCM) visit within 7 days", "priority": "HIGH"},
            {"intervention": "Medication reconciliation by clinical pharmacist", "priority": "HIGH"},
            {"intervention": "Follow-up phone call within 48 hours of discharge", "priority": "HIGH"},
        ])
    if risk_level == "HIGH":
        interventions.extend([
            {"intervention": "Home health referral for post-discharge monitoring", "priority": "HIGH"},
            {"intervention": "Care coordinator assignment", "priority": "HIGH"},
            {"intervention": "Enroll in remote patient monitoring program", "priority": "MEDIUM"},
        ])
    if social_determinants["lives_alone"]:
        interventions.append({"intervention": "Social work consult for community support services", "priority": "MEDIUM"})
    if social_determinants["transportation_barriers"]:
        interventions.append({"intervention": "Arrange medical transportation for follow-up visits", "priority": "MEDIUM"})
    interventions.append({"intervention": "Patient education on warning signs requiring ED return", "priority": "MEDIUM"})

    return json.dumps({
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
            "prior_admissions_12mo": prior_admissions_12mo,
            "ed_visits_6mo": ed_visits_6mo,
            "length_of_stay_days": random.randint(2, 12),
        },
        "social_determinants": social_determinants,
        "contributing_factors": contributing_factors,
        "recommended_interventions": interventions,
        "benchmark": {
            "national_avg_readmission_rate": "15.6%",
            "facility_avg": f"{round(random.uniform(10, 18), 1)}%",
            "cms_penalty_threshold": "15.4%",
        },
        "disclaimer": "Predictive model for clinical decision support. Individual patient assessment required.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_care_gap_analysis(patient_id: str) -> str:
    """Identify gaps in preventive care for a patient including overdue screenings, vaccinations, and wellness checks.

    Analyzes the patient's care history against evidence-based preventive care guidelines
    to identify overdue or missing services.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234').

    Returns:
        JSON with identified care gaps, recommended actions, quality measure impact, and scheduling suggestions.
    """
    age = random.randint(30, 80)
    sex = random.choice(["Male", "Female"])

    all_gaps = [
        {
            "measure": "Annual Wellness Visit",
            "description": "Comprehensive preventive health assessment",
            "last_completed": (datetime.utcnow() - timedelta(days=random.randint(380, 800))).strftime("%Y-%m-%d"),
            "due_date": (datetime.utcnow() - timedelta(days=random.randint(10, 200))).strftime("%Y-%m-%d"),
            "status": "OVERDUE",
            "priority": "HIGH",
            "quality_measure": "AWV (Annual Wellness Visit)",
            "applies_to": "All patients annually",
        },
        {
            "measure": "Hemoglobin A1C Test",
            "description": "Diabetes monitoring - glycemic control assessment",
            "last_completed": (datetime.utcnow() - timedelta(days=random.randint(200, 400))).strftime("%Y-%m-%d"),
            "due_date": (datetime.utcnow() - timedelta(days=random.randint(10, 100))).strftime("%Y-%m-%d"),
            "status": "OVERDUE",
            "priority": "HIGH",
            "quality_measure": "HEDIS CDC - HbA1c Testing",
            "applies_to": "Patients with diabetes",
        },
        {
            "measure": "Influenza Vaccination",
            "description": "Annual flu vaccine",
            "last_completed": (datetime.utcnow() - timedelta(days=random.randint(365, 500))).strftime("%Y-%m-%d"),
            "due_date": "2025-10-01",
            "status": random.choice(["OVERDUE", "DUE SOON"]),
            "priority": "MEDIUM",
            "quality_measure": "Flu Vaccination Rate",
            "applies_to": "All patients annually (Oct-Mar)",
        },
        {
            "measure": "Colorectal Cancer Screening",
            "description": "Colonoscopy or FIT test for colorectal cancer screening",
            "last_completed": (datetime.utcnow() - timedelta(days=random.randint(3650, 5000))).strftime("%Y-%m-%d") if age >= 45 else None,
            "due_date": (datetime.utcnow() - timedelta(days=random.randint(10, 365))).strftime("%Y-%m-%d"),
            "status": "OVERDUE",
            "priority": "HIGH",
            "quality_measure": "HEDIS COL - Colorectal Cancer Screening",
            "applies_to": "Ages 45-75",
        },
        {
            "measure": "Mammogram",
            "description": "Breast cancer screening mammography",
            "last_completed": (datetime.utcnow() - timedelta(days=random.randint(730, 1200))).strftime("%Y-%m-%d"),
            "due_date": (datetime.utcnow() - timedelta(days=random.randint(10, 200))).strftime("%Y-%m-%d"),
            "status": "OVERDUE",
            "priority": "HIGH",
            "quality_measure": "HEDIS BCS - Breast Cancer Screening",
            "applies_to": "Females ages 50-74 (every 2 years)",
        },
        {
            "measure": "Lipid Panel",
            "description": "Fasting lipid profile for cardiovascular risk assessment",
            "last_completed": (datetime.utcnow() - timedelta(days=random.randint(400, 800))).strftime("%Y-%m-%d"),
            "due_date": (datetime.utcnow() - timedelta(days=random.randint(0, 100))).strftime("%Y-%m-%d"),
            "status": "OVERDUE",
            "priority": "MEDIUM",
            "quality_measure": "Statin Therapy Monitoring",
            "applies_to": "Patients on statins or with CVD risk factors",
        },
        {
            "measure": "Depression Screening (PHQ-9)",
            "description": "Annual depression screening questionnaire",
            "last_completed": (datetime.utcnow() - timedelta(days=random.randint(400, 700))).strftime("%Y-%m-%d"),
            "due_date": (datetime.utcnow() - timedelta(days=random.randint(10, 200))).strftime("%Y-%m-%d"),
            "status": "OVERDUE",
            "priority": "MEDIUM",
            "quality_measure": "HEDIS DSF - Depression Screening",
            "applies_to": "All patients ages 12+ annually",
        },
        {
            "measure": "Pneumococcal Vaccination (PCV20)",
            "description": "Pneumonia vaccine for high-risk adults",
            "last_completed": None,
            "due_date": "Due now",
            "status": "NEVER COMPLETED",
            "priority": "MEDIUM",
            "quality_measure": "Pneumococcal Vaccination Rate",
            "applies_to": "Ages 65+ or high-risk adults",
        },
        {
            "measure": "Eye Exam (Diabetic Retinopathy)",
            "description": "Annual dilated eye examination for diabetic patients",
            "last_completed": (datetime.utcnow() - timedelta(days=random.randint(400, 800))).strftime("%Y-%m-%d"),
            "due_date": (datetime.utcnow() - timedelta(days=random.randint(10, 150))).strftime("%Y-%m-%d"),
            "status": "OVERDUE",
            "priority": "HIGH",
            "quality_measure": "HEDIS EED - Eye Exam for Diabetes",
            "applies_to": "Patients with diabetes annually",
        },
        {
            "measure": "Kidney Function Screening (eGFR/UACR)",
            "description": "Annual nephropathy screening for diabetic patients",
            "last_completed": (datetime.utcnow() - timedelta(days=random.randint(380, 600))).strftime("%Y-%m-%d"),
            "due_date": (datetime.utcnow() - timedelta(days=random.randint(10, 100))).strftime("%Y-%m-%d"),
            "status": "OVERDUE",
            "priority": "HIGH",
            "quality_measure": "HEDIS KED - Kidney Evaluation for Diabetes",
            "applies_to": "Patients with diabetes annually",
        },
    ]

    # Filter gaps based on age/sex appropriateness
    applicable_gaps = []
    for gap in all_gaps:
        if gap["measure"] == "Mammogram" and sex == "Male":
            continue
        if gap["measure"] == "Colorectal Cancer Screening" and age < 45:
            continue
        if gap["measure"] == "Pneumococcal Vaccination (PCV20)" and age < 65:
            continue
        applicable_gaps.append(gap)

    selected_gaps = random.sample(applicable_gaps, k=min(random.randint(3, 7), len(applicable_gaps)))
    selected_gaps.sort(key=lambda g: 0 if g["priority"] == "HIGH" else 1 if g["priority"] == "MEDIUM" else 2)

    high_priority = sum(1 for g in selected_gaps if g["priority"] == "HIGH")

    return json.dumps({
        "patient_id": patient_id,
        "patient_profile": {"age": age, "sex": sex},
        "total_care_gaps": len(selected_gaps),
        "high_priority_gaps": high_priority,
        "care_gaps": selected_gaps,
        "quality_impact": {
            "hedis_measures_affected": sum(1 for g in selected_gaps if "HEDIS" in g.get("quality_measure", "")),
            "message": f"Closing these gaps would improve {high_priority} high-priority quality measures.",
        },
        "recommended_actions": [
            f"Schedule annual wellness visit to address {len(selected_gaps)} overdue items",
            "Order overdue lab work (A1C, lipid panel, eGFR/UACR) as standing orders",
            "Send patient outreach for overdue cancer screenings",
            "Update immunization record and administer due vaccines at next visit",
        ],
        "hipaa_notice": "Care gap analysis access audit-logged.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
