"""Gateway target: records — patient summaries, record search, medications, labs.

All patient data is a deterministic simulation: every random draw is seeded
from the function inputs, so the same call always returns the same payload
(date-relative fields are stable within a calendar day).
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok
from toolkit.dispatch import dispatch

FIRST_NAMES = ["James", "Maria", "Robert", "Linda", "Michael", "Patricia",
               "William", "Elizabeth", "David", "Jennifer"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
              "Miller", "Davis", "Rodriguez", "Martinez"]
BLOOD_TYPES = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
PROVIDERS = ["Dr. Chen", "Dr. Patel", "Dr. Wilson", "Dr. Kim", "NP Rodriguez", "PA Thompson"]

CONDITIONS = [
    {"code": "E11.9", "description": "Type 2 Diabetes Mellitus", "onset": "2019-03-15", "status": "active"},
    {"code": "I10", "description": "Essential Hypertension", "onset": "2018-07-22", "status": "active"},
    {"code": "E78.5", "description": "Hyperlipidemia", "onset": "2020-01-10", "status": "active"},
    {"code": "J45.20", "description": "Mild Intermittent Asthma", "onset": "2005-11-03", "status": "active"},
    {"code": "M54.5", "description": "Low Back Pain", "onset": "2023-06-18", "status": "resolved"},
    {"code": "F41.1", "description": "Generalized Anxiety Disorder", "onset": "2021-09-01", "status": "active"},
    {"code": "K21.0", "description": "GERD with Esophagitis", "onset": "2022-02-14", "status": "active"},
]

MEDICATIONS = [
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

ALLERGIES = [
    {"allergen": "Penicillin", "reaction": "Anaphylaxis", "severity": "severe", "verified": True},
    {"allergen": "Sulfa drugs", "reaction": "Rash, hives", "severity": "moderate", "verified": True},
    {"allergen": "Latex", "reaction": "Contact dermatitis", "severity": "mild", "verified": False},
]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day)


def get_patient_summary(patient_id: str) -> dict:
    r = _rng("patient_summary", patient_id)
    age = r.randint(28, 85)
    sex = r.choice(["Male", "Female"])
    today = _today()

    recent_visits = []
    for _ in range(r.randint(2, 5)):
        recent_visits.append({
            "date": (today - timedelta(days=r.randint(7, 180))).strftime("%Y-%m-%d"),
            "type": r.choice(["Office Visit", "Telehealth", "Lab Work", "Follow-up", "Annual Physical"]),
            "provider": r.choice(["Dr. Chen", "Dr. Patel", "Dr. Wilson", "NP Rodriguez"]),
            "chief_complaint": r.choice([
                "Diabetes follow-up", "Blood pressure check", "Medication review",
                "Annual wellness exam", "Acute back pain", "Anxiety management"]),
            "disposition": r.choice(["Discharged", "Follow-up in 3 months",
                                     "Follow-up in 1 month", "Referred to specialist"]),
        })
    recent_visits.sort(key=lambda v: v["date"], reverse=True)

    conditions = r.sample(CONDITIONS, k=r.randint(2, 5))
    meds = [{"name": m["name"], "dosage": m["dosage"], "frequency": m["frequency"],
             "route": m["route"], "prescriber": m["prescriber"]}
            for m in r.sample(MEDICATIONS, k=r.randint(2, 5))]
    allergies = r.sample(ALLERGIES, k=r.randint(1, 3))

    return tool_ok({
        "patient_id": patient_id,
        "demographics": {
            "name": f"{r.choice(FIRST_NAMES)} {r.choice(LAST_NAMES)}",
            "age": age,
            "sex": sex,
            "date_of_birth": (today - timedelta(days=age * 365)).strftime("%Y-%m-%d"),
            "blood_type": r.choice(BLOOD_TYPES),
            "primary_language": r.choice(["English", "English", "Spanish", "Mandarin"]),
            "insurance": r.choice(["Blue Cross PPO", "Aetna HMO", "Medicare Part A&B",
                                   "United Healthcare", "Medicaid"]),
            "primary_care_provider": "Dr. Sarah Chen, MD",
        },
        "active_conditions": conditions,
        "current_medications": meds,
        "allergies": allergies,
        "recent_visits": recent_visits,
        "vitals_last_recorded": {
            "date": (today - timedelta(days=r.randint(1, 30))).strftime("%Y-%m-%d"),
            "blood_pressure": f"{r.randint(110, 155)}/{r.randint(65, 95)} mmHg",
            "heart_rate": f"{r.randint(60, 100)} bpm",
            "temperature": f"{round(r.uniform(97.0, 99.2), 1)} F",
            "respiratory_rate": f"{r.randint(12, 20)} breaths/min",
            "oxygen_saturation": f"{r.randint(94, 100)}%",
            "weight": f"{r.randint(120, 250)} lbs",
            "height": r.choice(["5ft 2in", "5ft 5in", "5ft 8in", "5ft 10in", "6ft 0in", "6ft 2in"]),
            "bmi": round(r.uniform(20.0, 38.0), 1),
        },
        "advance_directives": r.choice([True, False]),
        "hipaa_notice": "Access to this record has been audit-logged per HIPAA requirements.",
    }, simulated=True)


def search_medical_records(patient_id: str, query: str) -> dict:
    r = _rng("record_search", patient_id, query)
    templates = [
        ("Clinical Note", [
            "Patient presents with {q}-related symptoms. Physical exam reveals...",
            "Follow-up for {q}. Patient reports improvement since last visit...",
            "Assessment: {q} - stable. Continue current management plan...",
        ]),
        ("Lab Result", [
            "Lab panel ordered for {q} monitoring. Results within normal limits...",
            "Abnormal finding related to {q}: value elevated above reference range...",
        ]),
        ("Imaging Report", [
            "Imaging study performed for evaluation of {q}. Findings: No acute abnormality...",
            "CT scan report: Findings consistent with {q} presentation...",
        ]),
        ("Procedure Note", [
            "Procedure performed for {q}. Patient tolerated procedure well...",
        ]),
        ("Referral", [
            "Referral to specialist for {q} management. Reason: further evaluation needed...",
        ]),
        ("Discharge Summary", [
            "Admission for {q}. Hospital course: uneventful. Discharged in stable condition...",
        ]),
    ]
    today = _today()
    results = []
    for _ in range(r.randint(3, 8)):
        record_type, excerpts = r.choice(templates)
        results.append({
            "record_id": f"REC-{r.randrange(16 ** 8):08X}",
            "record_type": record_type,
            "date": (today - timedelta(days=r.randint(1, 730))).strftime("%Y-%m-%d"),
            "provider": r.choice(PROVIDERS),
            "department": r.choice(["Internal Medicine", "Cardiology", "Endocrinology",
                                    "Primary Care", "Emergency"]),
            "excerpt": r.choice(excerpts).replace("{q}", query),
            "relevance_score": round(r.uniform(0.65, 0.99), 2),
        })
    results.sort(key=lambda x: x["relevance_score"], reverse=True)
    return tool_ok({
        "patient_id": patient_id,
        "query": query,
        "total_results": len(results),
        "results": results,
        "search_scope": "All clinical documents, labs, imaging, procedures, and referrals",
        "hipaa_notice": "Record access audit-logged.",
    }, simulated=True)


def get_medication_list(patient_id: str) -> dict:
    r = _rng("medication_list", patient_id)
    today = _today()
    meds = [dict(m) for m in r.sample(MEDICATIONS, k=r.randint(4, len(MEDICATIONS)))]
    for med in meds:
        refills = r.randint(0, 5)
        med["refills_remaining"] = refills
        med["last_filled"] = (today - timedelta(days=r.randint(5, 60))).strftime("%Y-%m-%d")
        med["pharmacy"] = r.choice(["CVS Pharmacy #4521", "Walgreens #1089",
                                    "Rite Aid #723", "Express Scripts Mail Order"])
        med["adherence_rate"] = f"{r.randint(75, 100)}%"
        if refills == 0:
            med["refill_alert"] = "NEEDS RENEWAL - No refills remaining"

    alerts = []
    refill_needed = sum(1 for m in meds if m.get("refill_alert"))
    if refill_needed:
        alerts.append({"type": "REFILL_NEEDED", "severity": "MEDIUM",
                       "message": f"{refill_needed} medication(s) need refill renewal"})
    if len(meds) >= 6:
        alerts.append({"type": "POLYPHARMACY", "severity": "LOW",
                       "message": f"Patient on {len(meds)} medications - review for deprescribing opportunities"})

    return tool_ok({
        "patient_id": patient_id,
        "medication_count": len(meds),
        "medications": meds,
        "allergies_on_file": [
            {"allergen": "Penicillin", "reaction": "Anaphylaxis", "severity": "severe"},
            {"allergen": "Sulfa drugs", "reaction": "Rash", "severity": "moderate"},
        ],
        "last_reconciliation": (today - timedelta(days=r.randint(1, 90))).strftime("%Y-%m-%d"),
        "reconciled_by": r.choice(["Dr. Chen", "NP Rodriguez", "Pharm.D. Lee"]),
        "alerts": alerts,
        "hipaa_notice": "Medication record access audit-logged.",
    }, simulated=True)


def _flag(value, ref_range: str, test_name: str):
    if "A1c" in test_name:
        return "HIGH" if value >= 6.5 else "BORDERLINE" if value >= 5.7 else None
    if ref_range.startswith("<"):
        threshold = float(ref_range.replace("<", "").split(" ")[0])
        return "HIGH" if value >= threshold else None
    if ref_range.startswith(">"):
        threshold = float(ref_range.replace(">", "").split(" ")[0])
        return "LOW" if value < threshold else None
    if "-" in ref_range:
        try:
            low, high = (float(p) for p in ref_range.split("-")[:2])
        except ValueError:
            return None
        return "LOW" if value < low else "HIGH" if value > high else None
    return None


def get_lab_results(patient_id: str, days: int = 90) -> dict:
    days = max(1, int(days))
    r = _rng("lab_results", patient_id, days)
    today = _today()
    panels = {
        "Comprehensive Metabolic Panel": [
            ("Glucose", r.randint(70, 180), "mg/dL", "70-100"),
            ("BUN", r.randint(7, 30), "mg/dL", "7-20"),
            ("Creatinine", round(r.uniform(0.6, 1.8), 2), "mg/dL", "0.7-1.3"),
            ("eGFR", r.randint(45, 120), "mL/min/1.73m2", ">60"),
            ("Sodium", r.randint(132, 148), "mEq/L", "136-145"),
            ("Potassium", round(r.uniform(3.2, 5.5), 1), "mEq/L", "3.5-5.0"),
            ("ALT", r.randint(10, 65), "U/L", "7-56"),
            ("AST", r.randint(10, 55), "U/L", "10-40"),
        ],
        "Complete Blood Count": [
            ("WBC", round(r.uniform(3.5, 12.0), 1), "x10^3/uL", "4.5-11.0"),
            ("RBC", round(r.uniform(3.8, 6.0), 2), "x10^6/uL", "4.5-5.5"),
            ("Hemoglobin", round(r.uniform(10.5, 17.0), 1), "g/dL", "12.0-16.0"),
            ("Hematocrit", round(r.uniform(33.0, 50.0), 1), "%", "36-46"),
            ("Platelets", r.randint(130, 400), "x10^3/uL", "150-400"),
        ],
        "Lipid Panel": [
            ("Total Cholesterol", r.randint(150, 280), "mg/dL", "<200"),
            ("LDL Cholesterol", r.randint(60, 190), "mg/dL", "<100"),
            ("HDL Cholesterol", r.randint(30, 80), "mg/dL", ">40"),
            ("Triglycerides", r.randint(80, 350), "mg/dL", "<150"),
        ],
        "Hemoglobin A1C": [
            ("HbA1c", round(r.uniform(5.0, 10.5), 1), "%", "<5.7"),
        ],
        "Thyroid Panel": [
            ("TSH", round(r.uniform(0.3, 8.0), 2), "mIU/L", "0.4-4.0"),
            ("Free T4", round(r.uniform(0.7, 2.0), 2), "ng/dL", "0.8-1.8"),
        ],
    }
    selected = r.sample(sorted(panels), k=r.randint(2, len(panels)))
    results = []
    for panel_name in selected:
        collection = today - timedelta(days=r.randint(1, days))
        tests = [{"test": name, "value": value, "unit": unit, "ref_range": ref,
                  "flag": _flag(value, ref, name)}
                 for name, value, unit, ref in panels[panel_name]]
        results.append({
            "panel_name": panel_name,
            "order_id": f"LAB-{r.randrange(16 ** 8):08X}",
            "collection_date": collection.strftime("%Y-%m-%d"),
            "result_date": (collection + timedelta(days=r.randint(1, 3))).strftime("%Y-%m-%d"),
            "ordering_provider": r.choice(["Dr. Sarah Chen, MD", "Dr. Priya Patel, MD",
                                           "Dr. James Wilson, MD"]),
            "status": "Final",
            "tests": tests,
        })

    abnormal = sum(1 for p in results for t in p["tests"] if t["flag"] in ("HIGH", "LOW"))
    critical = [t["test"] for p in results for t in p["tests"]
                if t["flag"] == "HIGH" and t["test"] in ("Glucose", "Potassium", "Creatinine", "WBC")]

    return tool_ok({
        "patient_id": patient_id,
        "lookback_days": days,
        "panels_returned": len(results),
        "results": results,
        "summary": {
            "total_tests": sum(len(p["tests"]) for p in results),
            "abnormal_count": abnormal,
            "critical_flags": critical or None,
        },
        "recommendation": ("Critical values detected - notify ordering provider immediately."
                           if critical else "Results reviewed - no critical values."),
        "hipaa_notice": "Lab result access audit-logged.",
    }, simulated=True)


TOOLS = {
    "get_patient_summary": get_patient_summary,
    "search_medical_records": search_medical_records,
    "get_medication_list": get_medication_list,
    "get_lab_results": get_lab_results,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
