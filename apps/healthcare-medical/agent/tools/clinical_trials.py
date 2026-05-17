"""Clinical trials tools for the Healthcare Medical Assistant.

Provides patient-to-trial matching, eligibility criteria checking, active trial
searching, and trial summary generation for clinical research coordination.
"""

import json
import random
from datetime import datetime, timedelta

from strands import tool


@tool
def match_patient_to_trials(patient_id: str) -> str:
    """Match a patient profile against active clinical trials.

    Compares patient demographics, diagnosis, treatment history, and biomarkers
    against eligibility criteria of registered clinical trials to find potential matches.

    Args:
        patient_id: The patient identifier to match against available trials.

    Returns:
        JSON string with matched trials ranked by compatibility score.
    """
    num_matches = random.randint(1, 5)
    conditions = ["Type 2 Diabetes", "Non-Small Cell Lung Cancer", "Rheumatoid Arthritis",
                  "Major Depressive Disorder", "Chronic Heart Failure", "Alzheimer's Disease"]
    patient_condition = random.choice(conditions)

    matches = []
    for i in range(num_matches):
        trial_id = f"NCT{random.randint(10000000, 99999999)}"
        compatibility = round(random.uniform(0.5, 0.98), 3)

        matches.append({
            "trial_id": trial_id,
            "title": f"Phase {random.choice(['II', 'III', 'IV'])} Study of {random.choice(['Novel', 'Investigational', 'Combination'])} "
                     f"Therapy for {patient_condition}",
            "compatibility_score": compatibility,
            "sponsor": random.choice(["Pfizer", "Roche", "Novartis", "AstraZeneca", "Merck", "Academic Medical Center"]),
            "phase": random.choice(["Phase I", "Phase II", "Phase III", "Phase IV"]),
            "status": "RECRUITING",
            "distance_miles": round(random.uniform(5, 150), 1),
            "matching_criteria": random.sample([
                "Age range match",
                "Diagnosis confirmed",
                "Prior treatment history compatible",
                "Lab values within range",
                "No conflicting medications",
                "Performance status eligible",
            ], random.randint(3, 5)),
        })

    matches.sort(key=lambda x: x["compatibility_score"], reverse=True)

    return json.dumps({
        "patient_id": patient_id,
        "patient_condition": patient_condition,
        "total_trials_screened": random.randint(50, 200),
        "matches_found": num_matches,
        "matched_trials": matches,
        "matching_parameters_used": [
            "Demographics", "Diagnosis/ICD-10", "Biomarkers",
            "Prior treatments", "Comorbidities", "Geographic proximity",
        ],
        "matched_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def check_eligibility_criteria(patient_id: str, trial_id: str) -> str:
    """Check a patient against specific trial inclusion and exclusion criteria.

    Performs detailed evaluation of each eligibility criterion, identifying
    which criteria are met, not met, or require additional information.

    Args:
        patient_id: The patient identifier to evaluate.
        trial_id: The clinical trial identifier to check eligibility against.

    Returns:
        JSON string with detailed eligibility assessment for each criterion.
    """
    inclusion_criteria = [
        {"criterion": "Age 18-75 years", "status": random.choice(["MET", "MET", "MET", "NOT_MET"])},
        {"criterion": "Confirmed diagnosis via biopsy or imaging", "status": random.choice(["MET", "MET", "PENDING"])},
        {"criterion": "ECOG performance status 0-2", "status": random.choice(["MET", "MET", "NOT_MET"])},
        {"criterion": "Adequate organ function (labs within 14 days)", "status": random.choice(["MET", "PENDING"])},
        {"criterion": "Prior treatment with standard of care", "status": random.choice(["MET", "MET", "NOT_MET"])},
        {"criterion": "Willing to provide informed consent", "status": "MET"},
    ]

    exclusion_criteria = [
        {"criterion": "Active autoimmune disease", "status": random.choice(["CLEAR", "CLEAR", "FLAGGED"])},
        {"criterion": "Prior organ transplant", "status": "CLEAR"},
        {"criterion": "Concurrent enrollment in another trial", "status": random.choice(["CLEAR", "FLAGGED"])},
        {"criterion": "Uncontrolled cardiac disease", "status": random.choice(["CLEAR", "CLEAR", "PENDING"])},
        {"criterion": "Pregnancy or breastfeeding", "status": "CLEAR"},
        {"criterion": "Known hypersensitivity to study drug class", "status": random.choice(["CLEAR", "PENDING"])},
    ]

    inclusion_met = sum(1 for c in inclusion_criteria if c["status"] == "MET")
    exclusion_clear = sum(1 for c in exclusion_criteria if c["status"] == "CLEAR")
    pending_items = sum(1 for c in inclusion_criteria + exclusion_criteria if c["status"] in ["PENDING"])

    if inclusion_met == len(inclusion_criteria) and exclusion_clear == len(exclusion_criteria):
        overall_status = "ELIGIBLE"
    elif any(c["status"] == "NOT_MET" for c in inclusion_criteria) or any(
        c["status"] == "FLAGGED" for c in exclusion_criteria
    ):
        overall_status = "INELIGIBLE"
    else:
        overall_status = "PENDING_REVIEW"

    return json.dumps({
        "patient_id": patient_id,
        "trial_id": trial_id,
        "overall_eligibility": overall_status,
        "inclusion_criteria": inclusion_criteria,
        "exclusion_criteria": exclusion_criteria,
        "summary": {
            "inclusion_met": inclusion_met,
            "inclusion_total": len(inclusion_criteria),
            "exclusion_clear": exclusion_clear,
            "exclusion_total": len(exclusion_criteria),
            "pending_items": pending_items,
        },
        "next_steps": (
            ["Schedule screening visit", "Obtain informed consent"] if overall_status == "ELIGIBLE"
            else ["Collect pending lab results", "Complete imaging study"] if overall_status == "PENDING_REVIEW"
            else ["Document ineligibility reason", "Consider alternative trials"]
        ),
        "checked_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def search_active_trials(condition: str, location: str) -> str:
    """Search for active clinical trials by condition and location.

    Queries trial registries for currently recruiting studies that match
    the specified medical condition and geographic location.

    Args:
        condition: The medical condition or disease to search trials for.
        location: Geographic location for proximity search (city, state, or country).

    Returns:
        JSON string with list of matching active trials and key details.
    """
    num_results = random.randint(3, 8)
    phases = ["Phase I", "Phase II", "Phase IIa", "Phase IIb", "Phase III", "Phase IV"]
    sponsors = ["Pfizer", "Roche", "Novartis", "AstraZeneca", "Merck", "BMS", "Eli Lilly",
                "University Hospital", "National Cancer Institute", "NIH"]
    interventions = ["monoclonal antibody", "small molecule inhibitor", "gene therapy",
                     "cell therapy", "combination regimen", "bispecific antibody", "vaccine"]

    trials = []
    for _ in range(num_results):
        trial_id = f"NCT{random.randint(10000000, 99999999)}"
        enrollment_target = random.randint(50, 1000)
        current_enrollment = random.randint(10, enrollment_target)

        trials.append({
            "trial_id": trial_id,
            "title": f"A {random.choice(phases)} Study Evaluating {random.choice(interventions).title()} "
                     f"in Patients with {condition}",
            "phase": random.choice(phases),
            "sponsor": random.choice(sponsors),
            "status": "RECRUITING",
            "intervention_type": random.choice(interventions),
            "enrollment": {
                "target": enrollment_target,
                "current": current_enrollment,
                "pct_enrolled": round(current_enrollment / enrollment_target * 100, 1),
            },
            "distance_miles": round(random.uniform(2, 100), 1),
            "estimated_completion": (datetime.utcnow() + timedelta(days=random.randint(180, 1095))).strftime("%Y-%m-%d"),
            "primary_endpoint": random.choice([
                "Overall Survival", "Progression-Free Survival", "Objective Response Rate",
                "HbA1c Reduction", "Change in symptom score", "Disease-free survival",
            ]),
        })

    trials.sort(key=lambda x: x["distance_miles"])

    return json.dumps({
        "condition": condition,
        "location": location,
        "total_results": num_results,
        "trials": trials,
        "search_parameters": {
            "radius_miles": 100,
            "status_filter": "RECRUITING",
            "registries_searched": ["ClinicalTrials.gov", "WHO ICTRP", "EU Clinical Trials Register"],
        },
        "searched_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_trial_summary(trial_id: str) -> str:
    """Generate a patient-friendly summary of a clinical trial.

    Creates an accessible, plain-language summary of the trial including
    what is being studied, what participation involves, and potential
    risks and benefits.

    Args:
        trial_id: The clinical trial identifier to summarize.

    Returns:
        JSON string with patient-friendly trial summary and key information.
    """
    condition = random.choice(["Type 2 Diabetes", "Breast Cancer", "Rheumatoid Arthritis",
                               "COPD", "Heart Failure", "Multiple Sclerosis"])
    phase = random.choice(["Phase II", "Phase III"])
    duration_months = random.randint(6, 36)

    return json.dumps({
        "trial_id": trial_id,
        "plain_language_title": f"A study testing a new treatment for {condition}",
        "condition_studied": condition,
        "phase": phase,
        "summary": {
            "what_is_studied": f"This study is testing whether a new {random.choice(['medication', 'therapy', 'treatment approach'])} "
                               f"can help people with {condition} better than current standard treatments.",
            "who_can_participate": f"Adults aged 18-75 with diagnosed {condition} who have tried at least one "
                                   f"standard treatment.",
            "what_participation_involves": [
                f"Study visits every {random.choice([2, 4])} weeks for {duration_months} months",
                f"Taking study {random.choice(['medication', 'treatment'])} as directed",
                "Regular blood tests and health assessments",
                "Keeping a symptom diary",
            ],
            "duration_months": duration_months,
            "randomized": True,
            "placebo_controlled": random.choice([True, False]),
        },
        "potential_benefits": [
            "Access to a new treatment not yet available",
            "Close monitoring by a specialized medical team",
            "Contribute to medical knowledge that may help others",
            "No cost for study-related treatments and tests",
        ],
        "potential_risks": random.sample([
            "Side effects from the study treatment (detailed in consent form)",
            "Additional time commitment for study visits",
            "Possibility of receiving placebo instead of active treatment",
            "Unknown long-term effects of new treatment",
        ], random.randint(2, 3)),
        "compensation": {
            "travel_reimbursement": True,
            "stipend_per_visit": round(random.uniform(25, 100), 2),
        },
        "contact_info": {
            "site_name": f"{random.choice(['University', 'Regional', 'City'])} Medical Center",
            "coordinator_available": True,
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })
