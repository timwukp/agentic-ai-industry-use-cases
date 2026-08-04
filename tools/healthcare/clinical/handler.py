"""Gateway target: clinical — drug interactions, triage, guidelines, risk scores.

Reference data (interaction DB, guideline DB, triage rules) is curated and
hardcoded. Any sampled values are seeded from the function inputs, so the
same call always returns the same payload.
"""
import hashlib
import random

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch
from toolkit.responses import parse_json_arg

INTERACTION_DB = {
    ("Warfarin", "Aspirin"): {
        "severity": "major",
        "description": "Increased risk of bleeding. Aspirin inhibits platelet aggregation and may displace warfarin from protein binding sites.",
        "clinical_effect": "Elevated INR, increased hemorrhage risk",
        "recommendation": "Avoid combination if possible. If concurrent use required, monitor INR closely and watch for signs of bleeding.",
        "evidence_level": "Well-established",
    },
    ("Metformin", "Lisinopril"): {
        "severity": "minor",
        "description": "ACE inhibitors may enhance the hypoglycemic effect of metformin.",
        "clinical_effect": "Slight increase in hypoglycemia risk",
        "recommendation": "Monitor blood glucose. Generally safe combination commonly used in diabetic patients with hypertension.",
        "evidence_level": "Theoretical",
    },
    ("Sertraline", "Tramadol"): {
        "severity": "major",
        "description": "Both agents increase serotonin levels. Risk of serotonin syndrome.",
        "clinical_effect": "Agitation, confusion, tachycardia, hyperthermia, muscle rigidity",
        "recommendation": "AVOID combination. If unavoidable, use lowest effective doses and monitor for serotonin syndrome symptoms.",
        "evidence_level": "Well-established",
    },
    ("Lisinopril", "Potassium"): {
        "severity": "moderate",
        "description": "ACE inhibitors reduce potassium excretion. Supplemental potassium may cause hyperkalemia.",
        "clinical_effect": "Risk of hyperkalemia (elevated serum potassium)",
        "recommendation": "Monitor serum potassium levels regularly. Avoid routine potassium supplementation.",
        "evidence_level": "Established",
    },
    ("Atorvastatin", "Amiodarone"): {
        "severity": "major",
        "description": "Amiodarone inhibits CYP3A4, increasing statin plasma levels and risk of rhabdomyolysis.",
        "clinical_effect": "Myopathy, rhabdomyolysis, elevated CK levels",
        "recommendation": "Limit atorvastatin to 40mg/day when used with amiodarone. Monitor for muscle pain/weakness.",
        "evidence_level": "Established",
    },
    ("Omeprazole", "Clopidogrel"): {
        "severity": "major",
        "description": "Omeprazole inhibits CYP2C19, reducing conversion of clopidogrel to its active metabolite.",
        "clinical_effect": "Reduced antiplatelet effect, increased cardiovascular event risk",
        "recommendation": "Use pantoprazole instead of omeprazole. If PPI needed, avoid omeprazole/esomeprazole.",
        "evidence_level": "Well-established",
    },
    ("Metformin", "Contrast Dye"): {
        "severity": "major",
        "description": "Iodinated contrast media may cause acute kidney injury, leading to metformin-associated lactic acidosis.",
        "clinical_effect": "Lactic acidosis risk if renal function declines",
        "recommendation": "Hold metformin 48 hours before and after contrast administration. Check renal function before resuming.",
        "evidence_level": "Well-established",
    },
    ("Amlodipine", "Simvastatin"): {
        "severity": "moderate",
        "description": "Amlodipine inhibits CYP3A4, increasing simvastatin exposure.",
        "clinical_effect": "Increased risk of myopathy and rhabdomyolysis",
        "recommendation": "Limit simvastatin to 20mg/day when used with amlodipine. Consider atorvastatin as alternative.",
        "evidence_level": "Established",
    },
}

EMERGENCY_SYMPTOMS = {"chest pain", "difficulty breathing", "severe bleeding", "loss of consciousness",
                      "sudden severe headache", "stroke symptoms", "anaphylaxis", "seizure",
                      "shortness of breath", "crushing chest pressure"}
URGENT_SYMPTOMS = {"high fever", "persistent vomiting", "severe abdominal pain", "head injury",
                   "deep laceration", "blood in stool", "severe dehydration", "confusion",
                   "suicidal ideation", "severe allergic reaction"}

DIFFERENTIAL_DB = {
    "chest pain": [
        {"condition": "Acute Coronary Syndrome", "icd10": "I21.9", "probability": "age-dependent"},
        {"condition": "Costochondritis", "icd10": "M94.0", "probability": "moderate"},
        {"condition": "GERD", "icd10": "K21.0", "probability": "moderate"},
        {"condition": "Anxiety/Panic Attack", "icd10": "F41.0", "probability": "moderate"},
        {"condition": "Pulmonary Embolism", "icd10": "I26.99", "probability": "low"},
    ],
    "headache": [
        {"condition": "Tension Headache", "icd10": "G44.209", "probability": "high"},
        {"condition": "Migraine", "icd10": "G43.909", "probability": "moderate"},
        {"condition": "Sinusitis", "icd10": "J32.9", "probability": "moderate"},
        {"condition": "Hypertensive Crisis", "icd10": "I16.9", "probability": "low"},
    ],
    "abdominal pain": [
        {"condition": "Gastroenteritis", "icd10": "K52.9", "probability": "high"},
        {"condition": "Appendicitis", "icd10": "K35.80", "probability": "moderate"},
        {"condition": "Cholecystitis", "icd10": "K81.9", "probability": "moderate"},
        {"condition": "Peptic Ulcer Disease", "icd10": "K27.9", "probability": "moderate"},
    ],
    "fever": [
        {"condition": "Upper Respiratory Infection", "icd10": "J06.9", "probability": "high"},
        {"condition": "Urinary Tract Infection", "icd10": "N39.0", "probability": "moderate"},
        {"condition": "Influenza", "icd10": "J11.1", "probability": "moderate"},
        {"condition": "COVID-19", "icd10": "U07.1", "probability": "moderate"},
    ],
    "cough": [
        {"condition": "Acute Bronchitis", "icd10": "J20.9", "probability": "high"},
        {"condition": "Pneumonia", "icd10": "J18.9", "probability": "moderate"},
        {"condition": "Asthma Exacerbation", "icd10": "J45.901", "probability": "moderate"},
        {"condition": "Post-nasal Drip", "icd10": "R09.82", "probability": "moderate"},
    ],
}

GUIDELINES_DB = {
    "type 2 diabetes": {
        "condition": "Type 2 Diabetes Mellitus",
        "icd10": "E11.9",
        "source": "ADA Standards of Care 2025",
        "diagnostic_criteria": [
            "Fasting plasma glucose >= 126 mg/dL",
            "2-hour plasma glucose >= 200 mg/dL during OGTT",
            "HbA1c >= 6.5%",
            "Random plasma glucose >= 200 mg/dL with classic hyperglycemia symptoms",
        ],
        "treatment_algorithm": [
            {"step": 1, "therapy": "Lifestyle modification (diet, exercise, weight management)", "a1c_target": "<7.0%"},
            {"step": 2, "therapy": "Metformin monotherapy (first-line pharmacologic)", "a1c_target": "<7.0%"},
            {"step": 3, "therapy": "Add second agent: GLP-1 RA (preferred if CVD/CKD) or SGLT2i or DPP-4i or sulfonylurea", "a1c_target": "<7.0%"},
            {"step": 4, "therapy": "Triple therapy or add basal insulin", "a1c_target": "Individualized"},
            {"step": 5, "therapy": "Intensify insulin regimen (basal-bolus or premixed)", "a1c_target": "Individualized"},
        ],
        "monitoring": [
            {"test": "HbA1c", "frequency": "Every 3-6 months"},
            {"test": "Fasting glucose / CGM", "frequency": "Daily self-monitoring if on insulin"},
            {"test": "Lipid panel", "frequency": "Annually"},
            {"test": "eGFR and UACR", "frequency": "Annually"},
            {"test": "Dilated eye exam", "frequency": "Annually"},
            {"test": "Foot exam", "frequency": "Every visit"},
            {"test": "Blood pressure", "frequency": "Every visit, target <130/80"},
        ],
        "quality_measures": [
            "HbA1c < 8.0% (HEDIS measure)",
            "Blood pressure < 140/90 mmHg",
            "Statin therapy for ages 40-75 with diabetes",
            "Annual nephropathy screening",
            "Annual eye exam completion",
        ],
    },
    "hypertension": {
        "condition": "Essential Hypertension",
        "icd10": "I10",
        "source": "ACC/AHA 2024 Hypertension Guidelines",
        "diagnostic_criteria": [
            "Elevated: Systolic 120-129 and Diastolic <80 mmHg",
            "Stage 1: Systolic 130-139 or Diastolic 80-89 mmHg",
            "Stage 2: Systolic >=140 or Diastolic >=90 mmHg",
            "Hypertensive Crisis: Systolic >180 and/or Diastolic >120 mmHg",
        ],
        "treatment_algorithm": [
            {"step": 1, "therapy": "Lifestyle modifications: DASH diet, sodium <2300mg/day, exercise 150 min/week, weight loss", "bp_target": "<130/80"},
            {"step": 2, "therapy": "Monotherapy: ACEi or ARB (first-line), CCB, or thiazide diuretic", "bp_target": "<130/80"},
            {"step": 3, "therapy": "Dual therapy: ACEi/ARB + CCB or ACEi/ARB + thiazide", "bp_target": "<130/80"},
            {"step": 4, "therapy": "Triple therapy: ACEi/ARB + CCB + thiazide", "bp_target": "<130/80"},
            {"step": 5, "therapy": "Add spironolactone or beta-blocker for resistant hypertension", "bp_target": "<130/80"},
        ],
        "monitoring": [
            {"test": "Blood pressure", "frequency": "Monthly until controlled, then every 3-6 months"},
            {"test": "Basic metabolic panel", "frequency": "1-2 weeks after starting ACEi/ARB, then annually"},
            {"test": "Potassium level", "frequency": "With BMP if on ACEi/ARB or diuretic"},
            {"test": "Renal function (eGFR)", "frequency": "Annually"},
        ],
        "quality_measures": [
            "Blood pressure <140/90 mmHg (HEDIS measure)",
            "Optimal target <130/80 mmHg for high-risk patients",
            "Medication adherence assessment at each visit",
        ],
    },
}

DISCLAIMER = ("This tool is for clinical decision support only and does not replace "
              "clinical judgment. Always consult a licensed physician.")


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def check_drug_interactions(medications: str) -> dict:
    med_list, err = parse_json_arg(medications, "medications")
    if err:
        med_list = [m.strip() for m in str(medications).replace("[", "").replace("]", "")
                    .replace('"', "").split(",") if m.strip()]
    if not isinstance(med_list, list) or len(med_list) < 2:
        return tool_error("Provide at least two medication names as a JSON array")
    med_list = [str(m).strip() for m in med_list]

    interactions_found = []
    pairs_checked = 0
    for i in range(len(med_list)):
        for j in range(i + 1, len(med_list)):
            pairs_checked += 1
            pair = (med_list[i], med_list[j])
            match = INTERACTION_DB.get(pair) or INTERACTION_DB.get(pair[::-1])
            if match:
                interactions_found.append({"medication_pair": list(pair), **match})

    major = sum(1 for x in interactions_found if x["severity"] == "major")
    moderate = sum(1 for x in interactions_found if x["severity"] == "moderate")
    return tool_ok({
        "medications_checked": med_list,
        "pairs_analyzed": pairs_checked,
        "interactions_found": len(interactions_found),
        "interactions": interactions_found,
        "severity_summary": {
            "major": major,
            "moderate": moderate,
            "minor": len(interactions_found) - major - moderate,
        },
        "overall_risk": ("HIGH - Major interactions detected. Physician review required." if major
                         else "MODERATE - Review recommended." if moderate
                         else "LOW - No significant interactions detected in the reference database."),
        "database_note": "Curated reference database of common interactions; not exhaustive.",
        "disclaimer": DISCLAIMER,
    })


def assess_symptoms(symptoms: str, patient_age: int, patient_sex: str) -> dict:
    patient_age = int(patient_age)
    symptom_list = [s.strip().lower() for s in str(symptoms).split(",") if s.strip()]
    if not symptom_list:
        return tool_error("Provide at least one symptom (comma-separated)")

    has_emergency = any(s in EMERGENCY_SYMPTOMS for s in symptom_list)
    has_urgent = any(s in URGENT_SYMPTOMS for s in symptom_list)

    if has_emergency:
        urgency, color = "EMERGENCY", "RED"
        action = "Call 911 or proceed to nearest Emergency Department immediately."
    elif has_urgent:
        urgency, color = "URGENT", "ORANGE"
        action = "Seek medical attention within 1-2 hours. Consider urgent care or ED."
    elif patient_age >= 65 or patient_age <= 5:
        urgency, color = "URGENT", "YELLOW"
        action = "Schedule same-day appointment. Age-related elevated risk."
    else:
        urgency, color = "ROUTINE", "GREEN"
        action = "Schedule appointment within 24-72 hours with primary care provider."

    differentials = []
    joined = " ".join(symptom_list)
    for key, conditions in DIFFERENTIAL_DB.items():
        if key in joined:
            for c in conditions:
                entry = dict(c)
                if entry["probability"] == "age-dependent":
                    entry["probability"] = "high" if patient_age > 45 else "moderate"
                if entry not in differentials:
                    differentials.append(entry)
    if not differentials:
        differentials = [
            {"condition": "Unspecified symptom complex", "icd10": "R68.89", "probability": "uncertain"},
            {"condition": "Further evaluation needed", "icd10": "Z71.1", "probability": "N/A"},
        ]

    red_flags = []
    if patient_age >= 65 and any(s in ("chest pain", "shortness of breath") for s in symptom_list):
        red_flags.append("Age >65 with cardiac symptoms - high risk for acute coronary event")
    if "fever" in joined and patient_age <= 3:
        red_flags.append("Infant/toddler with fever - requires immediate pediatric evaluation")
    if any(s in symptom_list for s in ("confusion", "loss of consciousness")):
        red_flags.append("Altered mental status - requires emergent neurological assessment")
    if "chest pain" in joined and "shortness of breath" in joined:
        red_flags.append("Combined chest pain and dyspnea - rule out ACS, PE, pneumothorax")

    return tool_ok({
        "assessment": {
            "urgency_level": urgency,
            "triage_color": color,
            "recommended_action": action,
        },
        "patient_info": {"age": patient_age, "sex": patient_sex, "reported_symptoms": symptom_list},
        "differential_diagnoses": differentials[:6],
        "red_flags": red_flags or ["No critical red flags identified"],
        "recommended_workup": [
            "Vital signs assessment",
            "Focused physical examination",
            "Point-of-care testing as indicated",
            "ECG if cardiac symptoms present",
            "Basic laboratory panel if systemic symptoms",
        ],
        "disposition": action,
        "disclaimer": DISCLAIMER,
    })


def get_clinical_guidelines(condition: str) -> dict:
    key = condition.lower().strip()
    guideline = GUIDELINES_DB.get(key)
    if not guideline:
        guideline = {
            "condition": condition.title(),
            "icd10": "See coding reference",
            "source": "Clinical practice guidelines - latest edition",
            "diagnostic_criteria": [
                f"Refer to current diagnostic criteria for {condition}",
                "Clinical presentation and history",
                "Appropriate laboratory and imaging workup",
                "Differential diagnosis consideration",
            ],
            "treatment_algorithm": [
                {"step": 1, "therapy": "Comprehensive evaluation and diagnosis confirmation"},
                {"step": 2, "therapy": "Evidence-based first-line therapy per current guidelines"},
                {"step": 3, "therapy": "Adjunctive therapies and monitoring as indicated"},
                {"step": 4, "therapy": "Specialist referral if refractory to initial treatment"},
            ],
            "monitoring": [
                {"test": "Disease-specific markers", "frequency": "Per guideline recommendations"},
                {"test": "Treatment response assessment", "frequency": "4-8 weeks after initiation"},
            ],
            "quality_measures": [f"Refer to HEDIS/CMS quality measures for {condition}"],
            "coverage_note": "Condition not in the local guideline database; generic framework returned.",
        }
    return tool_ok({**guideline, "last_reviewed": "2025-01-15", "disclaimer": DISCLAIMER})


def calculate_risk_score(patient_id: str, risk_type: str) -> dict:
    risk_type = risk_type.lower().strip()
    r = _rng("risk_score", patient_id, risk_type)

    if risk_type == "cardiovascular":
        score = round(r.uniform(2.0, 35.0), 1)
        if score < 5.0:
            interpretation, category = "LOW RISK", "Low (<5%)"
        elif score < 7.5:
            interpretation, category = "BORDERLINE RISK", "Borderline (5-7.4%)"
        elif score < 20.0:
            interpretation, category = "INTERMEDIATE RISK", "Intermediate (7.5-19.9%)"
        else:
            interpretation, category = "HIGH RISK", "High (>=20%)"
        total_chol, hdl = r.randint(160, 280), r.randint(30, 75)
        systolic, age = r.randint(115, 170), r.randint(40, 80)
        result = {
            "risk_model": "ASCVD 10-Year Risk (Pooled Cohort Equations)",
            "score": score,
            "unit": "% 10-year risk",
            "interpretation": interpretation,
            "risk_category": category,
            "input_parameters": {
                "age": age,
                "sex": r.choice(["Male", "Female"]),
                "total_cholesterol": f"{total_chol} mg/dL",
                "hdl_cholesterol": f"{hdl} mg/dL",
                "systolic_bp": f"{systolic} mmHg",
                "on_bp_medication": r.choice([True, False]),
                "diabetes": r.choice([True, False]),
                "smoker": r.choice([True, False]),
            },
            "risk_factors_present": [f for f in [
                "Hypertension" if systolic >= 140 else None,
                "Low HDL" if hdl < 40 else None,
                "Elevated total cholesterol" if total_chol > 200 else None,
                "Age >55" if age > 55 else None,
            ] if f],
            "recommendations": [f for f in [
                "Initiate statin therapy (moderate-to-high intensity)" if score >= 7.5
                else "Consider statin therapy based on risk enhancers",
                "Aspirin 81mg daily if benefit outweighs bleeding risk" if score >= 10.0
                else "Aspirin not routinely recommended at this risk level",
                "Blood pressure management to target <130/80 mmHg",
                "Lifestyle modifications: Mediterranean diet, 150 min/week moderate exercise",
                "Consider coronary artery calcium (CAC) score for risk reclassification"
                if 5.0 <= score < 20.0 else None,
            ] if f],
        }
    elif risk_type == "diabetes":
        score = r.randint(0, 10)
        interpretation = "LOW RISK" if score <= 2 else "MODERATE RISK" if score <= 4 else "HIGH RISK"
        result = {
            "risk_model": "ADA Type 2 Diabetes Risk Test",
            "score": score,
            "unit": "points (0-10 scale)",
            "interpretation": interpretation,
            "risk_category": f"Score {score}/10 - "
                             f"{'screening recommended' if score >= 5 else 'routine monitoring'}",
            "input_parameters": {
                "age": r.choice(["<40", "40-49", "50-59", "60+"]),
                "sex": r.choice(["Male", "Female"]),
                "family_history_diabetes": r.choice([True, False]),
                "hypertension": r.choice([True, False]),
                "physically_active": r.choice([True, False]),
                "bmi_category": r.choice(["Normal", "Overweight", "Obese Class I", "Obese Class II+"]),
            },
            "recommendations": [f for f in [
                "Order HbA1c and fasting glucose for screening" if score >= 5 else "Rescreen in 3 years",
                "Diabetes Prevention Program referral" if score >= 5 else "Encourage healthy lifestyle",
                "Weight management counseling (target 5-7% weight loss)" if score >= 3 else None,
                "Increase physical activity to 150 min/week" if score >= 3 else None,
                "Annual screening if risk factors persist",
            ] if f],
        }
    elif risk_type == "falls":
        score = r.randint(0, 125)
        if score <= 24:
            interpretation, fall_risk = "LOW RISK", "No intervention required"
        elif score <= 50:
            interpretation, fall_risk = "MODERATE RISK", "Implement standard fall prevention protocol"
        else:
            interpretation, fall_risk = "HIGH RISK", "Implement high-risk fall prevention interventions"
        result = {
            "risk_model": "Morse Fall Scale",
            "score": score,
            "unit": "points (0-125 scale)",
            "interpretation": interpretation,
            "risk_category": f"Score {score} - {fall_risk}",
            "input_parameters": {
                "history_of_falling": r.choice(["Yes (25 pts)", "No (0 pts)"]),
                "secondary_diagnosis": r.choice(["Yes (15 pts)", "No (0 pts)"]),
                "ambulatory_aid": r.choice(["None (0 pts)", "Crutches/Cane/Walker (15 pts)",
                                            "Furniture (30 pts)"]),
                "iv_therapy": r.choice(["Yes (20 pts)", "No (0 pts)"]),
                "gait": r.choice(["Normal (0 pts)", "Weak (10 pts)", "Impaired (20 pts)"]),
                "mental_status": r.choice(["Oriented to own ability (0 pts)",
                                           "Overestimates/forgets limitations (15 pts)"]),
            },
            "recommendations": [f for f in [
                "Bed alarm and non-slip footwear" if score > 50 else "Standard precautions",
                "Physical therapy referral for balance and gait training" if score > 24 else None,
                "Medication review for fall-risk-increasing drugs (FRIDs)" if score > 24 else None,
                "Environmental safety assessment" if score > 50 else None,
                "Vitamin D supplementation (800-1000 IU daily)" if score > 24 else None,
                "Reassess fall risk with each status change",
            ] if f],
        }
    else:
        return tool_error(f"Risk type '{risk_type}' not recognized.",
                          supported_risk_types=["cardiovascular", "diabetes", "falls"])

    return tool_ok({"patient_id": patient_id, **result, "disclaimer": DISCLAIMER}, simulated=True)


TOOLS = {
    "check_drug_interactions": check_drug_interactions,
    "assess_symptoms": assess_symptoms,
    "get_clinical_guidelines": get_clinical_guidelines,
    "calculate_risk_score": calculate_risk_score,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
