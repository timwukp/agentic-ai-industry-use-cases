from strands import tool
import json, random
from datetime import datetime


@tool
def check_drug_interactions(medications: str) -> str:
    """Check for drug-drug interactions between a list of medications.

    Analyzes potential interactions between the provided medications, including
    severity level, clinical significance, and management recommendations.

    Args:
        medications: JSON string of medication names (e.g., '["Metformin", "Lisinopril", "Warfarin"]').

    Returns:
        JSON with interaction details including severity, mechanism, clinical effects, and recommendations.
    """
    try:
        med_list = json.loads(medications)
    except (json.JSONDecodeError, TypeError):
        med_list = [m.strip() for m in medications.replace("[", "").replace("]", "").replace('"', "").split(",")]

    interaction_db = {
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

    interactions_found = []
    checked_pairs = []

    for i in range(len(med_list)):
        for j in range(i + 1, len(med_list)):
            med_a = med_list[i].strip()
            med_b = med_list[j].strip()
            pair = (med_a, med_b)
            reverse_pair = (med_b, med_a)
            checked_pairs.append(f"{med_a} + {med_b}")

            match = interaction_db.get(pair) or interaction_db.get(reverse_pair)
            if match:
                interactions_found.append({
                    "medication_pair": [med_a, med_b],
                    **match,
                })

    # If no known interactions matched but we have 3+ meds, simulate a moderate interaction
    if not interactions_found and len(med_list) >= 3:
        med_a, med_b = random.sample(med_list, 2)
        interactions_found.append({
            "medication_pair": [med_a, med_b],
            "severity": "minor",
            "description": f"Potential additive effect when {med_a} and {med_b} are used concurrently.",
            "clinical_effect": "Minimal clinical significance expected",
            "recommendation": "No action required. Monitor patient as clinically indicated.",
            "evidence_level": "Theoretical",
        })

    major_count = sum(1 for i in interactions_found if i["severity"] == "major")
    moderate_count = sum(1 for i in interactions_found if i["severity"] == "moderate")

    return json.dumps({
        "medications_checked": med_list,
        "pairs_analyzed": len(checked_pairs),
        "interactions_found": len(interactions_found),
        "interactions": interactions_found,
        "severity_summary": {
            "major": major_count,
            "moderate": moderate_count,
            "minor": len(interactions_found) - major_count - moderate_count,
        },
        "overall_risk": "HIGH - Major interactions detected. Physician review required." if major_count > 0
            else "MODERATE - Review recommended." if moderate_count > 0
            else "LOW - No significant interactions detected.",
        "disclaimer": "This interaction check is for decision support only. Always consult clinical pharmacist or physician for final medication decisions.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def assess_symptoms(symptoms: str, patient_age: int, patient_sex: str) -> str:
    """Perform a triage assessment based on reported symptoms, patient age, and sex.

    Evaluates symptom urgency and provides possible differential diagnoses,
    recommended actions, and triage classification.

    Args:
        symptoms: Comma-separated list of symptoms (e.g., 'chest pain, shortness of breath, sweating').
        patient_age: Patient age in years.
        patient_sex: Patient sex ('male' or 'female').

    Returns:
        JSON with urgency level, differential diagnoses, recommended actions, and red flags.
    """
    symptom_list = [s.strip().lower() for s in symptoms.split(",")]

    emergency_symptoms = {"chest pain", "difficulty breathing", "severe bleeding", "loss of consciousness",
                          "sudden severe headache", "stroke symptoms", "anaphylaxis", "seizure",
                          "shortness of breath", "crushing chest pressure"}
    urgent_symptoms = {"high fever", "persistent vomiting", "severe abdominal pain", "head injury",
                       "deep laceration", "blood in stool", "severe dehydration", "confusion",
                       "suicidal ideation", "severe allergic reaction"}

    has_emergency = any(s in emergency_symptoms for s in symptom_list)
    has_urgent = any(s in urgent_symptoms for s in symptom_list)

    if has_emergency:
        urgency = "EMERGENCY"
        urgency_color = "RED"
        recommended_action = "Call 911 or proceed to nearest Emergency Department immediately."
    elif has_urgent:
        urgency = "URGENT"
        urgency_color = "ORANGE"
        recommended_action = "Seek medical attention within 1-2 hours. Consider urgent care or ED."
    elif patient_age >= 65 or patient_age <= 5:
        urgency = "URGENT"
        urgency_color = "YELLOW"
        recommended_action = "Schedule same-day appointment. Age-related elevated risk."
    else:
        urgency = "ROUTINE"
        urgency_color = "GREEN"
        recommended_action = "Schedule appointment within 24-72 hours with primary care provider."

    differential_db = {
        "chest pain": [
            {"condition": "Acute Coronary Syndrome", "icd10": "I21.9", "probability": "high" if patient_age > 45 else "moderate"},
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

    differentials = []
    for symptom in symptom_list:
        for key, conditions in differential_db.items():
            if key in symptom:
                for condition in conditions:
                    if condition not in differentials:
                        differentials.append(condition)

    if not differentials:
        differentials = [
            {"condition": "Unspecified symptom complex", "icd10": "R68.89", "probability": "uncertain"},
            {"condition": "Further evaluation needed", "icd10": "Z71.1", "probability": "N/A"},
        ]

    red_flags = []
    if patient_age >= 65 and any(s in ["chest pain", "shortness of breath"] for s in symptom_list):
        red_flags.append("Age >65 with cardiac symptoms - high risk for acute coronary event")
    if "fever" in " ".join(symptom_list) and patient_age <= 3:
        red_flags.append("Infant/toddler with fever - requires immediate pediatric evaluation")
    if any(s in symptom_list for s in ["confusion", "loss of consciousness"]):
        red_flags.append("Altered mental status - requires emergent neurological assessment")
    if "chest pain" in " ".join(symptom_list) and "shortness of breath" in " ".join(symptom_list):
        red_flags.append("Combined chest pain and dyspnea - rule out ACS, PE, pneumothorax")

    return json.dumps({
        "assessment": {
            "urgency_level": urgency,
            "triage_color": urgency_color,
            "recommended_action": recommended_action,
        },
        "patient_info": {
            "age": patient_age,
            "sex": patient_sex,
            "reported_symptoms": symptom_list,
        },
        "differential_diagnoses": differentials[:6],
        "red_flags": red_flags if red_flags else ["No critical red flags identified"],
        "recommended_workup": [
            "Vital signs assessment",
            "Focused physical examination",
            "Point-of-care testing as indicated",
            "ECG if cardiac symptoms present",
            "Basic laboratory panel if systemic symptoms",
        ],
        "disposition": recommended_action,
        "disclaimer": "DECISION SUPPORT ONLY. This triage assessment does not replace clinical judgment. "
                      "Always consult a licensed healthcare provider for definitive medical evaluation.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_clinical_guidelines(condition: str) -> str:
    """Retrieve evidence-based clinical guidelines for a specific medical condition.

    Returns current best-practice guidelines including diagnostic criteria,
    treatment algorithms, monitoring parameters, and quality measures.

    Args:
        condition: Medical condition name (e.g., 'type 2 diabetes', 'hypertension', 'heart failure', 'asthma').

    Returns:
        JSON with clinical guidelines including diagnostic criteria, treatment steps, monitoring schedule, and references.
    """
    guidelines_db = {
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

    condition_lower = condition.lower().strip()
    guideline = guidelines_db.get(condition_lower)

    if not guideline:
        # Generate a generic guideline response for conditions not in the database
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
                {"test": "Safety monitoring (labs)", "frequency": "As indicated by therapy"},
            ],
            "quality_measures": [
                f"Refer to HEDIS/CMS quality measures for {condition}",
            ],
        }

    return json.dumps({
        **guideline,
        "last_reviewed": "2025-01-15",
        "disclaimer": "Guidelines are for clinical decision support. Individual patient factors may "
                      "warrant deviation from standard protocols. Always apply clinical judgment.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def calculate_risk_score(patient_id: str, risk_type: str) -> str:
    """Calculate a clinical risk score for a patient based on the specified risk model.

    Supports cardiovascular risk (ASCVD 10-year risk), diabetes risk (ADA risk test),
    and falls risk (Morse Fall Scale) assessments.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234').
        risk_type: Type of risk assessment ('cardiovascular', 'diabetes', 'falls').

    Returns:
        JSON with calculated score, risk interpretation, contributing factors, and recommendations.
    """
    risk_type_lower = risk_type.lower().strip()

    if risk_type_lower == "cardiovascular":
        score = round(random.uniform(2.0, 35.0), 1)
        if score < 5.0:
            interpretation = "LOW RISK"
            category = "Low (<5%)"
        elif score < 7.5:
            interpretation = "BORDERLINE RISK"
            category = "Borderline (5-7.4%)"
        elif score < 20.0:
            interpretation = "INTERMEDIATE RISK"
            category = "Intermediate (7.5-19.9%)"
        else:
            interpretation = "HIGH RISK"
            category = "High (>=20%)"

        total_chol = random.randint(160, 280)
        hdl = random.randint(30, 75)
        systolic = random.randint(115, 170)
        age = random.randint(40, 80)

        result = {
            "risk_model": "ASCVD 10-Year Risk (Pooled Cohort Equations)",
            "score": score,
            "unit": "% 10-year risk",
            "interpretation": interpretation,
            "risk_category": category,
            "input_parameters": {
                "age": age,
                "sex": random.choice(["Male", "Female"]),
                "race": random.choice(["White", "African American", "Hispanic", "Asian"]),
                "total_cholesterol": f"{total_chol} mg/dL",
                "hdl_cholesterol": f"{hdl} mg/dL",
                "systolic_bp": f"{systolic} mmHg",
                "on_bp_medication": random.choice([True, False]),
                "diabetes": random.choice([True, False]),
                "smoker": random.choice([True, False]),
            },
            "risk_factors_present": [
                f for f in [
                    "Hypertension" if systolic >= 140 else None,
                    "Low HDL" if hdl < 40 else None,
                    "Elevated total cholesterol" if total_chol > 200 else None,
                    "Age >55" if age > 55 else None,
                    "Diabetes" if random.random() > 0.5 else None,
                    "Family history of premature CVD" if random.random() > 0.6 else None,
                ] if f is not None
            ],
            "recommendations": [
                "Initiate statin therapy (moderate-to-high intensity)" if score >= 7.5 else "Consider statin therapy based on risk enhancers",
                "Aspirin 81mg daily if benefit outweighs bleeding risk" if score >= 10.0 else "Aspirin not routinely recommended at this risk level",
                "Blood pressure management to target <130/80 mmHg",
                "Lifestyle modifications: Mediterranean diet, 150 min/week moderate exercise",
                "Smoking cessation counseling" if random.random() > 0.5 else "Maintain smoke-free status",
                "Consider coronary artery calcium (CAC) score for risk reclassification" if 5.0 <= score < 20.0 else None,
            ],
        }

    elif risk_type_lower == "diabetes":
        score = random.randint(0, 10)
        if score <= 2:
            interpretation = "LOW RISK"
        elif score <= 4:
            interpretation = "MODERATE RISK"
        else:
            interpretation = "HIGH RISK"

        result = {
            "risk_model": "ADA Type 2 Diabetes Risk Test",
            "score": score,
            "unit": "points (0-10 scale)",
            "interpretation": interpretation,
            "risk_category": f"Score {score}/10 - {'screening recommended' if score >= 5 else 'routine monitoring'}",
            "input_parameters": {
                "age": random.choice(["<40", "40-49", "50-59", "60+"]),
                "sex": random.choice(["Male", "Female"]),
                "family_history_diabetes": random.choice([True, False]),
                "hypertension": random.choice([True, False]),
                "physically_active": random.choice([True, False]),
                "bmi_category": random.choice(["Normal", "Overweight", "Obese Class I", "Obese Class II+"]),
                "history_gestational_diabetes": random.choice([True, False, "N/A"]),
            },
            "risk_factors_present": [
                f for f in [
                    "BMI >= 25 (overweight/obese)" if random.random() > 0.4 else None,
                    "Age >= 45" if random.random() > 0.4 else None,
                    "Family history of Type 2 diabetes" if random.random() > 0.5 else None,
                    "Sedentary lifestyle" if random.random() > 0.5 else None,
                    "History of hypertension" if random.random() > 0.5 else None,
                    "History of gestational diabetes" if random.random() > 0.7 else None,
                ] if f is not None
            ],
            "recommendations": [
                "Order HbA1c and fasting glucose for screening" if score >= 5 else "Rescreen in 3 years",
                "Diabetes Prevention Program referral" if score >= 5 else "Encourage healthy lifestyle",
                "Weight management counseling (target 5-7% weight loss)" if score >= 3 else None,
                "Increase physical activity to 150 min/week" if score >= 3 else None,
                "Annual screening if risk factors persist",
            ],
        }

    elif risk_type_lower == "falls":
        score = random.randint(0, 125)
        if score <= 24:
            interpretation = "LOW RISK"
            fall_risk = "No intervention required"
        elif score <= 50:
            interpretation = "MODERATE RISK"
            fall_risk = "Implement standard fall prevention protocol"
        else:
            interpretation = "HIGH RISK"
            fall_risk = "Implement high-risk fall prevention interventions"

        result = {
            "risk_model": "Morse Fall Scale",
            "score": score,
            "unit": "points (0-125 scale)",
            "interpretation": interpretation,
            "risk_category": f"Score {score} - {fall_risk}",
            "input_parameters": {
                "history_of_falling": random.choice(["Yes (25 pts)", "No (0 pts)"]),
                "secondary_diagnosis": random.choice(["Yes (15 pts)", "No (0 pts)"]),
                "ambulatory_aid": random.choice(["None (0 pts)", "Crutches/Cane/Walker (15 pts)", "Furniture (30 pts)"]),
                "iv_therapy": random.choice(["Yes (20 pts)", "No (0 pts)"]),
                "gait": random.choice(["Normal (0 pts)", "Weak (10 pts)", "Impaired (20 pts)"]),
                "mental_status": random.choice(["Oriented to own ability (0 pts)", "Overestimates/forgets limitations (15 pts)"]),
            },
            "risk_factors_present": [
                f for f in [
                    "History of falls within 3 months" if random.random() > 0.5 else None,
                    "Multiple comorbidities" if random.random() > 0.4 else None,
                    "Use of high-risk medications (sedatives, antihypertensives)" if random.random() > 0.5 else None,
                    "Impaired gait/balance" if random.random() > 0.5 else None,
                    "Cognitive impairment" if random.random() > 0.6 else None,
                    "Age >65" if random.random() > 0.4 else None,
                    "Environmental hazards identified" if random.random() > 0.6 else None,
                ] if f is not None
            ],
            "recommendations": [
                "Bed alarm and non-slip footwear" if score > 50 else "Standard precautions",
                "Physical therapy referral for balance and gait training" if score > 24 else None,
                "Medication review for fall-risk-increasing drugs (FRIDs)" if score > 24 else None,
                "Environmental safety assessment" if score > 50 else None,
                "Assistive device evaluation" if score > 50 else None,
                "Vitamin D supplementation (800-1000 IU daily)" if score > 24 else None,
                "Reassess fall risk with each status change",
            ],
        }

    else:
        result = {
            "risk_model": risk_type,
            "error": f"Risk type '{risk_type}' not recognized. Supported types: cardiovascular, diabetes, falls.",
            "supported_risk_types": ["cardiovascular", "diabetes", "falls"],
        }

    # Clean None values from recommendations
    if "recommendations" in result:
        result["recommendations"] = [r for r in result["recommendations"] if r is not None]

    return json.dumps({
        "patient_id": patient_id,
        **result,
        "disclaimer": "Risk scores are clinical decision support tools and should be interpreted "
                      "in the context of the individual patient. Physician review required.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
