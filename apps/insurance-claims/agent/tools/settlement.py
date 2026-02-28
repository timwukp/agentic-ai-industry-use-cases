from strands import tool
import json, random
from datetime import datetime, timedelta


@tool
def calculate_settlement(claim_id: str, damage_assessment: str, coverage_limit: float) -> str:
    """Calculate recommended settlement amount for a claim.

    Uses damage assessment data, policy limits, and actuarial models
    to determine fair settlement.

    Args:
        claim_id: The claim identifier.
        damage_assessment: Summary of damage findings.
        coverage_limit: Maximum coverage limit from the policy.

    Returns:
        JSON with settlement calculation breakdown and recommendation.
    """
    base_amount = round(random.uniform(1000, coverage_limit * 0.8), 2)
    deductible = round(random.uniform(250, 5000), 2)
    depreciation = round(base_amount * random.uniform(0.05, 0.25), 2)
    net_amount = round(max(0, base_amount - deductible - depreciation), 2)

    return json.dumps({
        "claim_id": claim_id,
        "settlement_calculation": {
            "gross_damage_estimate": base_amount,
            "less_deductible": -deductible,
            "less_depreciation": -depreciation,
            "policy_limit": coverage_limit,
            "net_settlement_amount": net_amount,
            "payment_method": "Direct deposit" if random.random() > 0.3 else "Check",
        },
        "breakdown": {
            "repair_costs": round(base_amount * 0.6, 2),
            "replacement_costs": round(base_amount * 0.25, 2),
            "additional_living_expenses": round(base_amount * 0.1, 2),
            "other": round(base_amount * 0.05, 2),
        },
        "recommendation": "APPROVE" if net_amount < coverage_limit * 0.5 else "REVIEW_WITH_MANAGER",
        "confidence": round(random.uniform(0.75, 0.98), 2),
        "comparable_settlements": {
            "average": round(net_amount * random.uniform(0.8, 1.2), 2),
            "median": round(net_amount * random.uniform(0.85, 1.15), 2),
            "range": [round(net_amount * 0.6, 2), round(net_amount * 1.4, 2)],
        },
    })


@tool
def approve_settlement(claim_id: str, amount: float, approver_notes: str) -> str:
    """Approve a settlement for payment processing.

    Args:
        claim_id: The claim identifier.
        amount: Settlement amount in USD.
        approver_notes: Notes from the approver.

    Returns:
        JSON with approval confirmation and payment details.
    """
    return json.dumps({
        "claim_id": claim_id,
        "status": "SETTLEMENT_APPROVED",
        "approved_amount": amount,
        "payment_reference": f"PAY-{datetime.now().strftime('%Y%m%d')}-{random.randint(10000, 99999)}",
        "payment_method": "ACH Direct Deposit",
        "estimated_payment_date": (datetime.utcnow() + timedelta(days=random.randint(3, 10))).strftime("%Y-%m-%d"),
        "approver_notes": approver_notes,
        "approved_at": datetime.utcnow().isoformat() + "Z",
        "compliance_checks": {
            "fair_claims_practices": "PASSED",
            "state_regulation": "PASSED",
            "fraud_clearance": "PASSED",
            "supervisor_approval": "REQUIRED" if amount > 25000 else "NOT_REQUIRED",
        },
    })


@tool
def get_settlement_analytics() -> str:
    """Get settlement analytics and performance metrics.

    Returns:
        JSON with settlement KPIs, trends, and efficiency metrics.
    """
    return json.dumps({
        "period": "current_month",
        "kpis": {
            "total_settlements": random.randint(100, 500),
            "total_amount_paid": round(random.uniform(500000, 2000000), 2),
            "average_settlement": round(random.uniform(3000, 15000), 2),
            "median_settlement": round(random.uniform(2000, 10000), 2),
            "avg_processing_days": round(random.uniform(5, 20), 1),
            "straight_through_rate_pct": round(random.uniform(55, 75), 1),
            "customer_satisfaction": round(random.uniform(4.0, 4.8), 1),
        },
        "by_claim_type": {
            "auto": {"count": random.randint(40, 150), "avg_amount": round(random.uniform(3000, 12000), 2)},
            "home": {"count": random.randint(20, 80), "avg_amount": round(random.uniform(5000, 25000), 2)},
            "health": {"count": random.randint(30, 120), "avg_amount": round(random.uniform(2000, 15000), 2)},
            "property": {"count": random.randint(10, 50), "avg_amount": round(random.uniform(4000, 20000), 2)},
        },
        "trend": {
            "settlements_vs_prior_month": round(random.uniform(-10, 15), 1),
            "avg_amount_vs_prior_month": round(random.uniform(-5, 10), 1),
            "processing_time_vs_prior_month": round(random.uniform(-15, 5), 1),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def estimate_reserve(claim_id: str, claim_type: str, severity: str) -> str:
    """Estimate the loss reserve for an open claim.

    Calculates the expected total cost of a claim for financial reserving purposes.

    Args:
        claim_id: The claim identifier.
        claim_type: Type of claim (auto, home, health, property, liability).
        severity: Claim severity (low, medium, high, catastrophic).

    Returns:
        JSON with reserve estimate and confidence intervals.
    """
    severity_multipliers = {"low": 1, "medium": 3, "high": 8, "catastrophic": 25}
    base = random.uniform(1000, 5000)
    mult = severity_multipliers.get(severity.lower(), 3)
    reserve = round(base * mult, 2)

    return json.dumps({
        "claim_id": claim_id,
        "claim_type": claim_type,
        "severity": severity.upper(),
        "reserve_estimate": reserve,
        "confidence_interval": {
            "p10": round(reserve * 0.5, 2),
            "p50": reserve,
            "p90": round(reserve * 2.0, 2),
        },
        "components": {
            "indemnity": round(reserve * 0.7, 2),
            "loss_adjustment_expense": round(reserve * 0.2, 2),
            "legal_costs": round(reserve * 0.1, 2),
        },
        "development_factor": round(random.uniform(1.0, 1.5), 3),
        "actuarial_method": "Chain-Ladder with Bornhuetter-Ferguson",
    })
