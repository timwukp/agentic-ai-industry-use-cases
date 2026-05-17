from strands import tool
import json
import random
from datetime import datetime, timedelta


@tool
def check_coverage_policy(procedure_code: str, insurance_id: str) -> str:
    """Check if a procedure requires prior authorization and review coverage policy.

    Looks up the procedure code against the insurance plan's coverage policies
    to determine authorization requirements and any applicable limitations.

    Args:
        procedure_code: The CPT or HCPCS procedure code to check.
        insurance_id: The insurance plan identifier to check against.

    Returns:
        JSON string with coverage status, prior auth requirements, and policy details.
    """
    requires_auth = random.choice([True, True, True, False])
    coverage_status = random.choice(["COVERED", "COVERED_WITH_CONDITIONS", "NOT_COVERED", "COVERED"])

    medical_necessity_criteria = [
        "Conservative treatment attempted for minimum 6 weeks",
        "Documented failure of first-line therapy",
        "Clinical documentation supports medical necessity",
        "Imaging studies confirm diagnosis",
        "Specialist referral obtained",
    ]

    return json.dumps({
        "procedure_code": procedure_code,
        "insurance_id": insurance_id,
        "coverage_status": coverage_status,
        "requires_prior_auth": requires_auth,
        "policy_details": {
            "plan_type": random.choice(["HMO", "PPO", "EPO", "POS"]),
            "in_network_coverage_pct": random.choice([80, 90, 100]),
            "out_of_network_coverage_pct": random.choice([50, 60, 70, 0]),
            "deductible_applies": random.choice([True, False]),
            "copay_amount": round(random.uniform(20, 100), 2),
            "annual_limit": random.choice([None, 10000, 25000, 50000]),
        },
        "authorization_requirements": {
            "clinical_documentation_needed": random.sample(medical_necessity_criteria, random.randint(2, 4)),
            "review_type": random.choice(["STANDARD", "EXPEDITED", "RETROSPECTIVE"]),
            "typical_turnaround_days": random.randint(3, 15),
            "valid_for_days": random.choice([30, 60, 90, 180]),
        } if requires_auth else None,
        "alternative_codes": [
            {"code": f"{random.randint(10000, 99999)}", "description": "Alternative procedure", "requires_auth": False}
        ] if coverage_status == "NOT_COVERED" else [],
        "checked_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def submit_prior_auth(patient_id: str, procedure_code: str, justification: str) -> str:
    """Submit a prior authorization request to the insurance payer.

    Creates and submits a structured prior authorization request with
    clinical justification and supporting documentation references.

    Args:
        patient_id: The patient identifier for the authorization request.
        procedure_code: The CPT/HCPCS procedure code requiring authorization.
        justification: Clinical justification narrative for the procedure.

    Returns:
        JSON string with submission confirmation, tracking details, and expected timeline.
    """
    auth_id = f"PA-{datetime.now().strftime('%Y%m%d')}-{random.randint(10000, 99999)}"
    submission_status = random.choice(["SUBMITTED", "SUBMITTED", "PENDING_ADDITIONAL_INFO"])

    return json.dumps({
        "auth_request_id": auth_id,
        "patient_id": patient_id,
        "procedure_code": procedure_code,
        "submission_status": submission_status,
        "request_details": {
            "request_type": random.choice(["STANDARD", "URGENT"]),
            "service_type": random.choice(["Outpatient Surgery", "Imaging", "DME", "Specialist Visit", "Medication"]),
            "clinical_justification": justification[:500],
            "supporting_documents": random.sample([
                "Office visit notes",
                "Diagnostic imaging results",
                "Lab results",
                "Prior treatment records",
                "Specialist consultation note",
                "Physical therapy progress notes",
            ], random.randint(2, 4)),
        },
        "timeline": {
            "submitted_at": datetime.utcnow().isoformat() + "Z",
            "expected_decision_date": (datetime.utcnow() + timedelta(days=random.randint(3, 14))).strftime("%Y-%m-%d"),
            "expedited_review_requested": random.choice([True, False]),
        },
        "payer_info": {
            "payer_name": random.choice(["United Healthcare", "Aetna", "Cigna", "Blue Cross", "Humana"]),
            "submission_method": random.choice(["ELECTRONIC_278", "FAX", "WEB_PORTAL"]),
            "reference_number": f"REF-{random.randint(100000, 999999)}",
        },
        "next_steps": (
            ["Await payer decision within stated timeline", "Monitor for additional information requests"]
            if submission_status == "SUBMITTED"
            else ["Upload additional clinical documentation", "Resubmit with complete information"]
        ),
    })


@tool
def predict_denial_risk(auth_request_id: str) -> str:
    """Predict likelihood of prior authorization denial and suggest improvements.

    Analyzes the authorization request against historical approval patterns,
    payer-specific criteria, and documentation completeness to predict
    denial risk and recommend strengthening actions.

    Args:
        auth_request_id: The authorization request identifier to assess.

    Returns:
        JSON string with denial probability, risk factors, and documentation recommendations.
    """
    denial_probability = round(random.uniform(0.05, 0.75), 3)

    if denial_probability > 0.5:
        risk_level = "HIGH"
    elif denial_probability > 0.25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    risk_factors = random.sample([
        {"factor": "Incomplete clinical documentation", "impact": round(random.uniform(0.1, 0.3), 2)},
        {"factor": "First-line therapy not attempted", "impact": round(random.uniform(0.1, 0.25), 2)},
        {"factor": "Procedure has high denial rate with this payer", "impact": round(random.uniform(0.05, 0.2), 2)},
        {"factor": "Missing specialist referral", "impact": round(random.uniform(0.05, 0.15), 2)},
        {"factor": "Medical necessity criteria partially met", "impact": round(random.uniform(0.1, 0.2), 2)},
        {"factor": "Diagnosis code mismatch", "impact": round(random.uniform(0.05, 0.15), 2)},
        {"factor": "Out-of-network provider", "impact": round(random.uniform(0.05, 0.2), 2)},
    ], random.randint(2, 4))

    recommendations = []
    if denial_probability > 0.3:
        recommendations = random.sample([
            "Add peer-reviewed literature supporting medical necessity",
            "Include detailed conservative treatment history with dates",
            "Obtain letter of medical necessity from specialist",
            "Attach imaging/lab results documenting clinical progression",
            "Reference payer-specific clinical policy bulletin criteria",
            "Include functional limitation documentation",
        ], random.randint(2, 4))

    return json.dumps({
        "auth_request_id": auth_request_id,
        "denial_probability": denial_probability,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "documentation_completeness_pct": round(random.uniform(60, 100), 1),
        "historical_context": {
            "payer_approval_rate_for_code": round(random.uniform(50, 90), 1),
            "similar_requests_approved_pct": round(random.uniform(55, 85), 1),
            "avg_review_cycles": round(random.uniform(1, 2.5), 1),
        },
        "recommendations_to_strengthen": recommendations,
        "predicted_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def draft_appeal_letter(auth_request_id: str, denial_reason: str) -> str:
    """Draft an appeal letter for a denied prior authorization request.

    Creates a structured appeal letter addressing the specific denial reason
    with clinical evidence, medical necessity arguments, and regulatory references.

    Args:
        auth_request_id: The denied authorization request identifier.
        denial_reason: The stated reason for denial from the payer.

    Returns:
        JSON string with drafted appeal letter content, supporting references, and submission guidance.
    """
    appeal_id = f"APL-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
    appeal_level = random.choice(["FIRST_LEVEL", "SECOND_LEVEL", "EXTERNAL_REVIEW"])

    return json.dumps({
        "appeal_id": appeal_id,
        "auth_request_id": auth_request_id,
        "denial_reason": denial_reason,
        "appeal_level": appeal_level,
        "appeal_letter": {
            "opening": (
                f"We are writing to appeal the denial of prior authorization request {auth_request_id}. "
                f"The stated denial reason was: {denial_reason}. We believe this decision should be reversed "
                f"based on the clinical evidence presented below."
            ),
            "clinical_argument": (
                "The patient has exhausted conservative treatment options over the recommended timeframe. "
                "Clinical documentation demonstrates progressive deterioration despite adherence to "
                "first-line therapies. The requested procedure is medically necessary to prevent "
                "further functional decline."
            ),
            "evidence_cited": random.sample([
                "Peer-reviewed clinical guidelines supporting intervention",
                "Patient-specific clinical progression documentation",
                "Specialist opinion confirming medical necessity",
                "Failed conservative treatment records with dates",
                "Imaging demonstrating clinical indication",
                "Lab values confirming disease progression",
            ], random.randint(3, 5)),
            "regulatory_references": random.sample([
                "AMA CPT coding guidelines",
                "CMS National Coverage Determination",
                "State prompt pay/clean claim regulations",
                "ERISA protections for plan beneficiaries",
                "Payer's own clinical policy bulletin criteria",
            ], random.randint(2, 3)),
            "closing": (
                "Based on the above clinical evidence and applicable guidelines, we respectfully request "
                "that the denial be overturned and authorization granted for the requested procedure."
            ),
        },
        "submission_guidance": {
            "deadline": (datetime.utcnow() + timedelta(days=random.choice([30, 60, 180]))).strftime("%Y-%m-%d"),
            "submission_method": random.choice(["Certified mail", "Payer web portal", "Electronic submission"]),
            "additional_docs_recommended": random.sample([
                "Updated clinical notes",
                "Letter of medical necessity",
                "Peer-to-peer review request",
                "Patient impact statement",
            ], 2),
        },
        "success_probability": round(random.uniform(0.3, 0.75), 2),
        "drafted_at": datetime.utcnow().isoformat() + "Z",
    })
