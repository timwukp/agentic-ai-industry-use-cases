"""Underwriting tools for the Insurance Claims Assistant.

Provides risk factor assessment, premium calculation, application review,
and policy terms recommendation for automated underwriting workflows.
"""

import json
import random
from datetime import datetime

from strands import tool


@tool
def assess_risk_factors(application_id: str) -> str:
    """Extract and score risk factors from an insurance application.

    Evaluates applicant demographics, health history, property characteristics,
    or driving record depending on policy type. Returns weighted risk scores
    for each factor category.

    Args:
        application_id: The application identifier to assess.

    Returns:
        JSON string with extracted risk factors, individual scores, and overall risk rating.
    """
    policy_type = random.choice(["AUTO", "HOME", "LIFE", "HEALTH", "COMMERCIAL"])

    risk_factors_by_type = {
        "AUTO": [
            {"factor": "Driving record (violations)", "score": round(random.uniform(0, 1), 2), "weight": 0.25},
            {"factor": "Vehicle safety rating", "score": round(random.uniform(0.5, 1), 2), "weight": 0.15},
            {"factor": "Annual mileage", "score": round(random.uniform(0, 1), 2), "weight": 0.10},
            {"factor": "Age/experience factor", "score": round(random.uniform(0.3, 1), 2), "weight": 0.20},
            {"factor": "Credit-based insurance score", "score": round(random.uniform(0, 1), 2), "weight": 0.15},
            {"factor": "Geographic risk zone", "score": round(random.uniform(0, 1), 2), "weight": 0.15},
        ],
        "HOME": [
            {"factor": "Property age and condition", "score": round(random.uniform(0, 1), 2), "weight": 0.20},
            {"factor": "Roof condition/age", "score": round(random.uniform(0, 1), 2), "weight": 0.15},
            {"factor": "Natural disaster exposure", "score": round(random.uniform(0, 1), 2), "weight": 0.25},
            {"factor": "Claims history", "score": round(random.uniform(0, 1), 2), "weight": 0.20},
            {"factor": "Security systems", "score": round(random.uniform(0.5, 1), 2), "weight": 0.10},
            {"factor": "Proximity to fire station", "score": round(random.uniform(0.3, 1), 2), "weight": 0.10},
        ],
        "LIFE": [
            {"factor": "Age and gender", "score": round(random.uniform(0, 1), 2), "weight": 0.25},
            {"factor": "Medical history", "score": round(random.uniform(0, 1), 2), "weight": 0.30},
            {"factor": "Tobacco use", "score": round(random.uniform(0, 1), 2), "weight": 0.15},
            {"factor": "BMI and fitness", "score": round(random.uniform(0, 1), 2), "weight": 0.15},
            {"factor": "Occupation hazard", "score": round(random.uniform(0.5, 1), 2), "weight": 0.10},
            {"factor": "Family medical history", "score": round(random.uniform(0, 1), 2), "weight": 0.05},
        ],
        "HEALTH": [
            {"factor": "Pre-existing conditions", "score": round(random.uniform(0, 1), 2), "weight": 0.30},
            {"factor": "Age factor", "score": round(random.uniform(0, 1), 2), "weight": 0.20},
            {"factor": "Lifestyle factors", "score": round(random.uniform(0, 1), 2), "weight": 0.15},
            {"factor": "Geographic healthcare costs", "score": round(random.uniform(0, 1), 2), "weight": 0.15},
            {"factor": "Prescription drug usage", "score": round(random.uniform(0, 1), 2), "weight": 0.10},
            {"factor": "Preventive care engagement", "score": round(random.uniform(0.3, 1), 2), "weight": 0.10},
        ],
        "COMMERCIAL": [
            {"factor": "Industry classification risk", "score": round(random.uniform(0, 1), 2), "weight": 0.20},
            {"factor": "Revenue and employee count", "score": round(random.uniform(0, 1), 2), "weight": 0.15},
            {"factor": "Claims loss history", "score": round(random.uniform(0, 1), 2), "weight": 0.25},
            {"factor": "Safety programs in place", "score": round(random.uniform(0.3, 1), 2), "weight": 0.15},
            {"factor": "Years in business", "score": round(random.uniform(0.3, 1), 2), "weight": 0.10},
            {"factor": "Regulatory compliance record", "score": round(random.uniform(0.5, 1), 2), "weight": 0.15},
        ],
    }

    factors = risk_factors_by_type[policy_type]
    overall_score = round(sum(f["score"] * f["weight"] for f in factors), 3)

    if overall_score > 0.7:
        risk_rating = "PREFERRED"
    elif overall_score > 0.5:
        risk_rating = "STANDARD"
    elif overall_score > 0.3:
        risk_rating = "SUBSTANDARD"
    else:
        risk_rating = "DECLINE"

    return json.dumps({
        "application_id": application_id,
        "policy_type": policy_type,
        "risk_factors": factors,
        "overall_risk_score": overall_score,
        "risk_rating": risk_rating,
        "underwriting_class": risk_rating,
        "flags": [f["factor"] for f in factors if f["score"] < 0.3],
        "assessed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def calculate_premium(policy_type: str, risk_profile: str) -> str:
    """Calculate insurance premium based on risk profile and actuarial tables.

    Applies base rates, risk multipliers, discounts, and surcharges to
    determine the final premium for the policy.

    Args:
        policy_type: Type of insurance (e.g., 'AUTO', 'HOME', 'LIFE', 'HEALTH').
        risk_profile: Risk classification (e.g., 'PREFERRED', 'STANDARD', 'SUBSTANDARD').

    Returns:
        JSON string with premium breakdown including base rate, adjustments, and final amount.
    """
    base_rates = {
        "AUTO": random.uniform(800, 2000),
        "HOME": random.uniform(1200, 3500),
        "LIFE": random.uniform(500, 2500),
        "HEALTH": random.uniform(3000, 8000),
        "COMMERCIAL": random.uniform(5000, 25000),
    }

    risk_multipliers = {
        "PREFERRED": 0.80,
        "STANDARD": 1.00,
        "SUBSTANDARD": 1.35,
        "HIGH_RISK": 1.75,
    }

    base_rate = round(base_rates.get(policy_type, 1500), 2)
    multiplier = risk_multipliers.get(risk_profile, 1.0)
    risk_adjusted = round(base_rate * multiplier, 2)

    discounts = []
    possible_discounts = [
        {"name": "Multi-policy bundle", "pct": round(random.uniform(5, 15), 1)},
        {"name": "Claims-free history", "pct": round(random.uniform(5, 20), 1)},
        {"name": "Loyalty discount", "pct": round(random.uniform(3, 10), 1)},
        {"name": "Electronic payment", "pct": round(random.uniform(2, 5), 1)},
    ]
    discounts = random.sample(possible_discounts, random.randint(1, 3))
    total_discount_pct = sum(d["pct"] for d in discounts)

    surcharges = []
    if risk_profile in ["SUBSTANDARD", "HIGH_RISK"]:
        surcharges.append({"name": "Risk surcharge", "pct": round(random.uniform(10, 25), 1)})
    total_surcharge_pct = sum(s["pct"] for s in surcharges)

    final_premium = round(risk_adjusted * (1 - total_discount_pct / 100 + total_surcharge_pct / 100), 2)

    return json.dumps({
        "policy_type": policy_type,
        "risk_profile": risk_profile,
        "premium_breakdown": {
            "base_rate": base_rate,
            "risk_multiplier": multiplier,
            "risk_adjusted_premium": risk_adjusted,
            "discounts_applied": discounts,
            "total_discount_pct": round(total_discount_pct, 1),
            "surcharges_applied": surcharges,
            "total_surcharge_pct": round(total_surcharge_pct, 1),
        },
        "final_premium": {
            "annual": final_premium,
            "semi_annual": round(final_premium / 2 * 1.02, 2),
            "quarterly": round(final_premium / 4 * 1.04, 2),
            "monthly": round(final_premium / 12 * 1.06, 2),
        },
        "effective_date": datetime.utcnow().strftime("%Y-%m-%d"),
        "calculated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def review_application(application_id: str) -> str:
    """Perform a comprehensive application review with decision recommendation.

    Evaluates all aspects of the application including risk factors, documentation
    completeness, and underwriting guidelines to produce a decision recommendation.

    Args:
        application_id: The application identifier to review.

    Returns:
        JSON string with review results, decision recommendation, and any conditions.
    """
    decision = random.choice(["APPROVE", "APPROVE_WITH_CONDITIONS", "REFER_TO_SENIOR", "DECLINE"])

    completeness_score = round(random.uniform(0.7, 1.0), 2)
    missing_docs = []
    all_docs = [
        "Signed application form",
        "Government-issued ID",
        "Proof of address",
        "Medical exam results",
        "Financial statements",
        "Prior insurance declaration",
        "Property inspection report",
    ]
    if completeness_score < 0.9:
        missing_docs = random.sample(all_docs, random.randint(1, 2))

    conditions = []
    if decision == "APPROVE_WITH_CONDITIONS":
        possible_conditions = [
            "Annual medical checkup required",
            "Home security system installation within 60 days",
            "Defensive driving course completion",
            "Higher deductible required",
            "Exclusion for pre-existing condition",
            "Reduced coverage limit recommended",
        ]
        conditions = random.sample(possible_conditions, random.randint(1, 3))

    return json.dumps({
        "application_id": application_id,
        "review_status": "COMPLETE",
        "decision": decision,
        "documentation": {
            "completeness_score": completeness_score,
            "missing_documents": missing_docs,
            "verification_status": "VERIFIED" if completeness_score >= 0.95 else "PENDING_VERIFICATION",
        },
        "risk_assessment_summary": {
            "overall_risk": random.choice(["LOW", "MODERATE", "HIGH"]),
            "loss_ratio_estimate": round(random.uniform(40, 80), 1),
            "expected_claim_frequency": round(random.uniform(0.05, 0.3), 3),
        },
        "conditions": conditions,
        "underwriter_notes": random.choice([
            "Standard risk, no concerns identified.",
            "Applicant has strong claims-free history.",
            "Minor risk factors noted, within acceptable range.",
            "Elevated risk factors require additional review.",
        ]),
        "review_completed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def suggest_policy_terms(application_id: str, risk_level: str) -> str:
    """Suggest policy terms, exclusions, and special conditions based on risk level.

    Generates tailored policy recommendations including coverage limits,
    deductibles, exclusions, and endorsements appropriate for the risk profile.

    Args:
        application_id: The application identifier to generate terms for.
        risk_level: The assessed risk level (e.g., 'LOW', 'MODERATE', 'HIGH').

    Returns:
        JSON string with suggested policy terms, exclusions, and special conditions.
    """
    deductible_ranges = {
        "LOW": (500, 1000),
        "MODERATE": (1000, 2500),
        "HIGH": (2500, 5000),
    }
    deductible_range = deductible_ranges.get(risk_level, (1000, 2500))
    deductible = random.randint(deductible_range[0], deductible_range[1])

    coverage_limit = round(random.uniform(100000, 2000000), -3)

    exclusions = []
    possible_exclusions = [
        "Acts of war or terrorism",
        "Intentional damage",
        "Normal wear and tear",
        "Nuclear hazard",
        "Government action",
        "Pre-existing structural damage",
        "Flood damage (separate policy required)",
        "Earthquake damage (endorsement available)",
    ]
    base_exclusions = possible_exclusions[:5]
    if risk_level == "HIGH":
        base_exclusions.extend(random.sample(possible_exclusions[5:], random.randint(1, 3)))
    exclusions = base_exclusions

    endorsements = []
    possible_endorsements = [
        {"name": "Extended replacement cost", "premium_impact_pct": 5.0},
        {"name": "Personal property replacement value", "premium_impact_pct": 3.5},
        {"name": "Identity theft protection", "premium_impact_pct": 2.0},
        {"name": "Equipment breakdown", "premium_impact_pct": 4.0},
        {"name": "Scheduled personal property", "premium_impact_pct": 6.0},
    ]
    endorsements = random.sample(possible_endorsements, random.randint(1, 3))

    return json.dumps({
        "application_id": application_id,
        "risk_level": risk_level,
        "suggested_terms": {
            "coverage_limit": coverage_limit,
            "deductible": deductible,
            "policy_term_months": random.choice([6, 12, 24, 36]),
            "payment_frequency": random.choice(["MONTHLY", "QUARTERLY", "ANNUAL"]),
            "coinsurance_pct": random.choice([80, 90, 100]),
        },
        "exclusions": exclusions,
        "special_conditions": [
            c for c in [
                "Annual property inspection required" if risk_level == "HIGH" else None,
                "Claims-free discount eligible after 3 years" if risk_level != "HIGH" else None,
                "Deductible buy-down available at renewal" if risk_level == "MODERATE" else None,
            ] if c
        ],
        "recommended_endorsements": endorsements,
        "waiting_period_days": 0 if risk_level == "LOW" else 30 if risk_level == "MODERATE" else 90,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })
