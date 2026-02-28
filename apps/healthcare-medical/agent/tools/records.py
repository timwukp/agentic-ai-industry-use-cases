from strands import tool
import json, random, uuid
from datetime import datetime, timedelta


@tool
def get_patient_summary(patient_id: str) -> str:
    """Get a comprehensive patient summary including demographics, conditions, medications, allergies, and recent visits.

    Retrieves a consolidated view of the patient's medical record for clinical review.
    All data is HIPAA-compliant and access is audit-logged.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234', 'MRN-567890').

    Returns:
        JSON with full patient summary including demographics, active conditions, medications, allergies, and recent encounters.
    """
    first_names = ["James", "Maria", "Robert", "Linda", "Michael", "Patricia", "William", "Elizabeth", "David", "Jennifer"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
    blood_types = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]

    conditions = [
        {"code": "E11.9", "description": "Type 2 Diabetes Mellitus", "onset": "2019-03-15", "status": "active"},
        {"code": "I10", "description": "Essential Hypertension", "onset": "2018-07-22", "status": "active"},
        {"code": "E78.5", "description": "Hyperlipidemia", "onset": "2020-01-10", "status": "active"},
        {"code": "J45.20", "description": "Mild Intermittent Asthma", "onset": "2005-11-03", "status": "active"},
        {"code": "M54.5", "description": "Low Back Pain", "onset": "2023-06-18", "status": "resolved"},
        {"code": "F41.1", "description": "Generalized Anxiety Disorder", "onset": "2021-09-01", "status": "active"},
        {"code": "K21.0", "description": "GERD with Esophagitis", "onset": "2022-02-14", "status": "active"},
    ]

    medications = [
        {"name": "Metformin", "dosage": "1000mg", "frequency": "twice daily", "route": "oral", "prescriber": "Dr. Chen"},
        {"name": "Lisinopril", "dosage": "20mg", "frequency": "once daily", "route": "oral", "prescriber": "Dr. Chen"},
        {"name": "Atorvastatin", "dosage": "40mg", "frequency": "once daily at bedtime", "route": "oral", "prescriber": "Dr. Chen"},
        {"name": "Albuterol", "dosage": "90mcg", "frequency": "as needed", "route": "inhaled", "prescriber": "Dr. Patel"},
        {"name": "Omeprazole", "dosage": "20mg", "frequency": "once daily before breakfast", "route": "oral", "prescriber": "Dr. Chen"},
    ]

    allergies = [
        {"allergen": "Penicillin", "reaction": "Anaphylaxis", "severity": "severe", "verified": True},
        {"allergen": "Sulfa drugs", "reaction": "Rash, hives", "severity": "moderate", "verified": True},
        {"allergen": "Latex", "reaction": "Contact dermatitis", "severity": "mild", "verified": False},
    ]

    age = random.randint(28, 85)
    sex = random.choice(["Male", "Female"])

    recent_visits = []
    for i in range(random.randint(2, 5)):
        visit_date = (datetime.utcnow() - timedelta(days=random.randint(7, 180))).strftime("%Y-%m-%d")
        recent_visits.append({
            "date": visit_date,
            "type": random.choice(["Office Visit", "Telehealth", "Lab Work", "Follow-up", "Annual Physical"]),
            "provider": random.choice(["Dr. Chen", "Dr. Patel", "Dr. Wilson", "NP Rodriguez"]),
            "chief_complaint": random.choice([
                "Diabetes follow-up", "Blood pressure check", "Medication review",
                "Annual wellness exam", "Acute back pain", "Anxiety management"
            ]),
            "disposition": random.choice(["Discharged", "Follow-up in 3 months", "Follow-up in 1 month", "Referred to specialist"]),
        })
    recent_visits.sort(key=lambda v: v["date"], reverse=True)

    selected_conditions = random.sample(conditions, k=random.randint(2, 5))
    selected_meds = random.sample(medications, k=random.randint(2, 5))
    selected_allergies = random.sample(allergies, k=random.randint(1, 3))

    return json.dumps({
        "patient_id": patient_id,
        "demographics": {
            "name": f"{random.choice(first_names)} {random.choice(last_names)}",
            "age": age,
            "sex": sex,
            "date_of_birth": (datetime.utcnow() - timedelta(days=age * 365)).strftime("%Y-%m-%d"),
            "blood_type": random.choice(blood_types),
            "primary_language": random.choice(["English", "English", "Spanish", "Mandarin"]),
            "insurance": random.choice(["Blue Cross PPO", "Aetna HMO", "Medicare Part A&B", "United Healthcare", "Medicaid"]),
            "primary_care_provider": "Dr. Sarah Chen, MD",
        },
        "active_conditions": selected_conditions,
        "current_medications": selected_meds,
        "allergies": selected_allergies,
        "recent_visits": recent_visits,
        "vitals_last_recorded": {
            "date": (datetime.utcnow() - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%d"),
            "blood_pressure": f"{random.randint(110, 155)}/{random.randint(65, 95)} mmHg",
            "heart_rate": f"{random.randint(60, 100)} bpm",
            "temperature": f"{round(random.uniform(97.0, 99.2), 1)} F",
            "respiratory_rate": f"{random.randint(12, 20)} breaths/min",
            "oxygen_saturation": f"{random.randint(94, 100)}%",
            "weight": f"{random.randint(120, 250)} lbs",
            "height": f"{random.choice(['5ft 2in', '5ft 5in', '5ft 8in', '5ft 10in', '6ft 0in', '6ft 2in'])}",
            "bmi": round(random.uniform(20.0, 38.0), 1),
        },
        "advance_directives": random.choice([True, False]),
        "emergency_contact": {
            "name": f"{random.choice(first_names)} {random.choice(last_names)}",
            "relationship": random.choice(["Spouse", "Child", "Sibling", "Parent"]),
            "phone": f"({random.randint(200,999)}) {random.randint(200,999)}-{random.randint(1000,9999)}",
        },
        "hipaa_notice": "Access to this record has been audit-logged per HIPAA requirements.",
        "retrieved_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def search_medical_records(patient_id: str, query: str) -> str:
    """Search a patient's medical records by keyword, condition, or clinical term.

    Performs a full-text search across the patient's electronic health record including
    notes, diagnoses, lab results, imaging reports, and procedure records.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234').
        query: Search keyword or clinical term (e.g., 'diabetes', 'chest pain', 'MRI', 'hemoglobin').

    Returns:
        JSON with matching records sorted by relevance, including record type, date, provider, and excerpt.
    """
    record_templates = [
        {
            "record_type": "Clinical Note",
            "excerpts": [
                "Patient presents with {query}-related symptoms. Physical exam reveals...",
                "Follow-up for {query}. Patient reports improvement since last visit...",
                "Assessment: {query} - stable. Continue current management plan...",
            ],
        },
        {
            "record_type": "Lab Result",
            "excerpts": [
                "Lab panel ordered for {query} monitoring. Results within normal limits...",
                "Abnormal finding related to {query}: value elevated above reference range...",
                "Comprehensive metabolic panel - relevant to {query} workup...",
            ],
        },
        {
            "record_type": "Imaging Report",
            "excerpts": [
                "Imaging study performed for evaluation of {query}. Findings: No acute abnormality...",
                "CT scan report: Findings consistent with {query} presentation...",
                "X-ray results related to {query} complaint. Impression: benign finding...",
            ],
        },
        {
            "record_type": "Procedure Note",
            "excerpts": [
                "Procedure performed for {query}. Patient tolerated procedure well...",
                "Surgical note: Intervention related to {query}. No complications...",
            ],
        },
        {
            "record_type": "Referral",
            "excerpts": [
                "Referral to specialist for {query} management. Reason: further evaluation needed...",
                "Consultation requested regarding {query}. Patient history provided...",
            ],
        },
        {
            "record_type": "Discharge Summary",
            "excerpts": [
                "Admission for {query}. Hospital course: uneventful. Discharged in stable condition...",
                "Discharge diagnosis: {query}-related condition. Follow-up in 2 weeks...",
            ],
        },
    ]

    results = []
    num_results = random.randint(3, 8)
    providers = ["Dr. Chen", "Dr. Patel", "Dr. Wilson", "Dr. Kim", "NP Rodriguez", "PA Thompson"]

    for i in range(num_results):
        template = random.choice(record_templates)
        excerpt = random.choice(template["excerpts"]).replace("{query}", query)
        record_date = (datetime.utcnow() - timedelta(days=random.randint(1, 730))).strftime("%Y-%m-%d")

        results.append({
            "record_id": f"REC-{uuid.uuid4().hex[:8].upper()}",
            "record_type": template["record_type"],
            "date": record_date,
            "provider": random.choice(providers),
            "department": random.choice(["Internal Medicine", "Cardiology", "Endocrinology", "Primary Care", "Emergency"]),
            "excerpt": excerpt,
            "relevance_score": round(random.uniform(0.65, 0.99), 2),
        })

    results.sort(key=lambda r: r["relevance_score"], reverse=True)

    return json.dumps({
        "patient_id": patient_id,
        "query": query,
        "total_results": len(results),
        "results": results,
        "search_scope": "All clinical documents, labs, imaging, procedures, and referrals",
        "hipaa_notice": "Record access audit-logged.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_medication_list(patient_id: str) -> str:
    """Get the current medication list for a patient with dosage, frequency, prescriber, and refill status.

    Retrieves the active medication reconciliation including prescription medications,
    OTC medications, and supplements.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234').

    Returns:
        JSON with current medications, dosing details, prescriber, pharmacy, and refill information.
    """
    medications = [
        {"name": "Metformin HCl", "generic": True, "class": "Biguanide", "dosage": "1000mg", "frequency": "BID (twice daily)", "route": "oral", "indication": "Type 2 Diabetes (E11.9)", "prescriber": "Dr. Sarah Chen, MD", "start_date": "2019-04-01"},
        {"name": "Lisinopril", "generic": True, "class": "ACE Inhibitor", "dosage": "20mg", "frequency": "QD (once daily)", "route": "oral", "indication": "Hypertension (I10)", "prescriber": "Dr. Sarah Chen, MD", "start_date": "2018-08-15"},
        {"name": "Atorvastatin", "generic": True, "class": "HMG-CoA Reductase Inhibitor", "dosage": "40mg", "frequency": "QHS (at bedtime)", "route": "oral", "indication": "Hyperlipidemia (E78.5)", "prescriber": "Dr. Sarah Chen, MD", "start_date": "2020-02-10"},
        {"name": "Amlodipine", "generic": True, "class": "Calcium Channel Blocker", "dosage": "5mg", "frequency": "QD (once daily)", "route": "oral", "indication": "Hypertension (I10)", "prescriber": "Dr. Sarah Chen, MD", "start_date": "2021-06-20"},
        {"name": "Omeprazole", "generic": True, "class": "Proton Pump Inhibitor", "dosage": "20mg", "frequency": "QD (before breakfast)", "route": "oral", "indication": "GERD (K21.0)", "prescriber": "Dr. James Wilson, MD", "start_date": "2022-03-01"},
        {"name": "Albuterol HFA", "generic": False, "class": "Beta-2 Agonist", "dosage": "90mcg/actuation", "frequency": "PRN (as needed)", "route": "inhaled", "indication": "Asthma (J45.20)", "prescriber": "Dr. Priya Patel, MD", "start_date": "2005-12-01"},
        {"name": "Sertraline", "generic": True, "class": "SSRI", "dosage": "100mg", "frequency": "QD (once daily, morning)", "route": "oral", "indication": "Generalized Anxiety (F41.1)", "prescriber": "Dr. Lisa Kim, MD", "start_date": "2021-10-15"},
        {"name": "Aspirin", "generic": True, "class": "Antiplatelet", "dosage": "81mg", "frequency": "QD (once daily)", "route": "oral", "indication": "Cardiovascular prophylaxis", "prescriber": "Dr. Sarah Chen, MD", "start_date": "2020-02-10"},
        {"name": "Vitamin D3", "generic": True, "class": "Supplement", "dosage": "2000 IU", "frequency": "QD (once daily)", "route": "oral", "indication": "Vitamin D deficiency (E55.9)", "prescriber": "Dr. Sarah Chen, MD", "start_date": "2023-01-05"},
    ]

    selected_meds = random.sample(medications, k=random.randint(4, len(medications)))

    for med in selected_meds:
        refills_remaining = random.randint(0, 5)
        last_filled = (datetime.utcnow() - timedelta(days=random.randint(5, 60))).strftime("%Y-%m-%d")
        med["refills_remaining"] = refills_remaining
        med["last_filled"] = last_filled
        med["pharmacy"] = random.choice(["CVS Pharmacy #4521", "Walgreens #1089", "Rite Aid #723", "Express Scripts Mail Order"])
        med["adherence_rate"] = f"{random.randint(75, 100)}%"
        if refills_remaining == 0:
            med["refill_alert"] = "NEEDS RENEWAL - No refills remaining"

    return json.dumps({
        "patient_id": patient_id,
        "medication_count": len(selected_meds),
        "medications": selected_meds,
        "allergies_on_file": [
            {"allergen": "Penicillin", "reaction": "Anaphylaxis", "severity": "severe"},
            {"allergen": "Sulfa drugs", "reaction": "Rash", "severity": "moderate"},
        ],
        "last_reconciliation": (datetime.utcnow() - timedelta(days=random.randint(1, 90))).strftime("%Y-%m-%d"),
        "reconciled_by": random.choice(["Dr. Chen", "NP Rodriguez", "Pharm.D. Lee"]),
        "alerts": [
            a for a in [
                {"type": "REFILL_NEEDED", "message": f"{sum(1 for m in selected_meds if m.get('refill_alert'))} medication(s) need refill renewal", "severity": "MEDIUM"} if any(m.get("refill_alert") for m in selected_meds) else None,
                {"type": "POLYPHARMACY", "message": f"Patient on {len(selected_meds)} medications - review for deprescribing opportunities", "severity": "LOW"} if len(selected_meds) >= 6 else None,
            ] if a is not None
        ],
        "hipaa_notice": "Medication record access audit-logged.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_lab_results(patient_id: str, days: int) -> str:
    """Get recent lab results for a patient with reference ranges and abnormal flags.

    Retrieves laboratory test results from the specified time window, including
    complete metabolic panels, CBC, lipid panels, A1C, and other ordered tests.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234').
        days: Number of days to look back for lab results (e.g., 30, 90, 365).

    Returns:
        JSON with lab results including values, reference ranges, flags, and ordering provider.
    """
    lab_panels = {
        "Comprehensive Metabolic Panel": [
            {"test": "Glucose", "value": random.randint(70, 180), "unit": "mg/dL", "ref_range": "70-100", "flag": None},
            {"test": "BUN", "value": random.randint(7, 30), "unit": "mg/dL", "ref_range": "7-20", "flag": None},
            {"test": "Creatinine", "value": round(random.uniform(0.6, 1.8), 2), "unit": "mg/dL", "ref_range": "0.7-1.3", "flag": None},
            {"test": "eGFR", "value": random.randint(45, 120), "unit": "mL/min/1.73m2", "ref_range": ">60", "flag": None},
            {"test": "Sodium", "value": random.randint(132, 148), "unit": "mEq/L", "ref_range": "136-145", "flag": None},
            {"test": "Potassium", "value": round(random.uniform(3.2, 5.5), 1), "unit": "mEq/L", "ref_range": "3.5-5.0", "flag": None},
            {"test": "ALT", "value": random.randint(10, 65), "unit": "U/L", "ref_range": "7-56", "flag": None},
            {"test": "AST", "value": random.randint(10, 55), "unit": "U/L", "ref_range": "10-40", "flag": None},
        ],
        "Complete Blood Count": [
            {"test": "WBC", "value": round(random.uniform(3.5, 12.0), 1), "unit": "x10^3/uL", "ref_range": "4.5-11.0", "flag": None},
            {"test": "RBC", "value": round(random.uniform(3.8, 6.0), 2), "unit": "x10^6/uL", "ref_range": "4.5-5.5", "flag": None},
            {"test": "Hemoglobin", "value": round(random.uniform(10.5, 17.0), 1), "unit": "g/dL", "ref_range": "12.0-16.0", "flag": None},
            {"test": "Hematocrit", "value": round(random.uniform(33.0, 50.0), 1), "unit": "%", "ref_range": "36-46", "flag": None},
            {"test": "Platelets", "value": random.randint(130, 400), "unit": "x10^3/uL", "ref_range": "150-400", "flag": None},
        ],
        "Lipid Panel": [
            {"test": "Total Cholesterol", "value": random.randint(150, 280), "unit": "mg/dL", "ref_range": "<200", "flag": None},
            {"test": "LDL Cholesterol", "value": random.randint(60, 190), "unit": "mg/dL", "ref_range": "<100", "flag": None},
            {"test": "HDL Cholesterol", "value": random.randint(30, 80), "unit": "mg/dL", "ref_range": ">40", "flag": None},
            {"test": "Triglycerides", "value": random.randint(80, 350), "unit": "mg/dL", "ref_range": "<150", "flag": None},
        ],
        "Hemoglobin A1C": [
            {"test": "HbA1c", "value": round(random.uniform(5.0, 10.5), 1), "unit": "%", "ref_range": "<5.7 (normal), 5.7-6.4 (prediabetes), >=6.5 (diabetes)", "flag": None},
        ],
        "Thyroid Panel": [
            {"test": "TSH", "value": round(random.uniform(0.3, 8.0), 2), "unit": "mIU/L", "ref_range": "0.4-4.0", "flag": None},
            {"test": "Free T4", "value": round(random.uniform(0.7, 2.0), 2), "unit": "ng/dL", "ref_range": "0.8-1.8", "flag": None},
        ],
    }

    # Flag abnormal results
    for panel_name, tests in lab_panels.items():
        for test in tests:
            ref = test["ref_range"]
            val = test["value"]
            if ref.startswith("<"):
                threshold = float(ref.replace("<", "").split(" ")[0])
                if val >= threshold:
                    test["flag"] = "HIGH"
            elif ref.startswith(">"):
                threshold = float(ref.replace(">", "").split(" ")[0])
                if val < threshold:
                    test["flag"] = "LOW"
            elif "-" in ref and not ref.startswith("<") and "normal" not in ref:
                parts = ref.split("-")
                try:
                    low, high = float(parts[0]), float(parts[1])
                    if val < low:
                        test["flag"] = "LOW"
                    elif val > high:
                        test["flag"] = "HIGH"
                except (ValueError, IndexError):
                    pass
            if "A1c" in test["test"]:
                if val >= 6.5:
                    test["flag"] = "HIGH"
                elif val >= 5.7:
                    test["flag"] = "BORDERLINE"

    selected_panels = random.sample(list(lab_panels.keys()), k=random.randint(2, len(lab_panels)))
    results = []
    for panel_name in selected_panels:
        panel_date = (datetime.utcnow() - timedelta(days=random.randint(1, days))).strftime("%Y-%m-%d")
        results.append({
            "panel_name": panel_name,
            "order_id": f"LAB-{uuid.uuid4().hex[:8].upper()}",
            "collection_date": panel_date,
            "result_date": (datetime.strptime(panel_date, "%Y-%m-%d") + timedelta(days=random.randint(1, 3))).strftime("%Y-%m-%d"),
            "ordering_provider": random.choice(["Dr. Sarah Chen, MD", "Dr. Priya Patel, MD", "Dr. James Wilson, MD"]),
            "status": "Final",
            "tests": lab_panels[panel_name],
        })

    abnormal_count = sum(1 for r in results for t in r["tests"] if t["flag"] in ("HIGH", "LOW"))
    critical_flags = [
        t["test"] for r in results for t in r["tests"]
        if t["flag"] == "HIGH" and t["test"] in ("Glucose", "Potassium", "Creatinine", "WBC")
    ]

    return json.dumps({
        "patient_id": patient_id,
        "lookback_days": days,
        "panels_returned": len(results),
        "results": results,
        "summary": {
            "total_tests": sum(len(r["tests"]) for r in results),
            "abnormal_count": abnormal_count,
            "critical_flags": critical_flags if critical_flags else None,
        },
        "recommendation": "Critical values detected - notify ordering provider immediately." if critical_flags else "Results reviewed - no critical values.",
        "hipaa_notice": "Lab result access audit-logged.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
