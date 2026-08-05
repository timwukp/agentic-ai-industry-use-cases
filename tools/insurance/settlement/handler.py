"""Gateway target: settlement — settlement calculation, approval, analytics, reserves.

Settlement figures are deterministic simulations seeded from the function inputs.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

SEVERITY_MULTIPLIERS = {"low": 1, "medium": 3, "high": 8, "catastrophic": 25}


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def calculate_settlement(
    claim_id: str, damage_assessment: str, coverage_limit: float
) -> dict:
    coverage_limit = float(coverage_limit)
    if coverage_limit <= 0:
        return tool_error("coverage_limit must be positive")
    r = _rng("calc_settlement", claim_id, damage_assessment, coverage_limit)
    base_amount = round(r.uniform(1000, coverage_limit * 0.8), 2)
    deductible = round(r.uniform(250, 5000), 2)
    depreciation = round(base_amount * r.uniform(0.05, 0.25), 2)
    net_amount = round(max(0, base_amount - deductible - depreciation), 2)

    return tool_ok(
        {
            "claim_id": claim_id,
            "settlement_calculation": {
                "gross_damage_estimate": base_amount,
                "less_deductible": -deductible,
                "less_depreciation": -depreciation,
                "policy_limit": coverage_limit,
                "net_settlement_amount": net_amount,
            },
            "breakdown": {
                "repair_costs": round(base_amount * 0.6, 2),
                "replacement_costs": round(base_amount * 0.25, 2),
                "additional_living_expenses": round(base_amount * 0.1, 2),
                "other": round(base_amount * 0.05, 2),
            },
            "recommendation": (
                "APPROVE"
                if net_amount < coverage_limit * 0.5
                else "REVIEW_WITH_MANAGER"
            ),
            "confidence": round(r.uniform(0.75, 0.98), 2),
            "comparable_settlements": {
                "average": round(net_amount * r.uniform(0.8, 1.2), 2),
                "median": round(net_amount * r.uniform(0.85, 1.15), 2),
                "range": [round(net_amount * 0.6, 2), round(net_amount * 1.4, 2)],
            },
        },
        simulated=True,
    )


def approve_settlement(claim_id: str, amount: float, approver_notes: str) -> dict:
    amount = float(amount)
    if amount <= 0:
        return tool_error("amount must be positive")
    r = _rng("approve_settlement", claim_id, amount, approver_notes)
    now = _today()

    return tool_ok(
        {
            "claim_id": claim_id,
            "status": "SETTLEMENT_APPROVED",
            "approved_amount": amount,
            "payment_reference": f"PAY-{now.strftime('%Y%m%d')}-{r.randint(10000, 99999)}",
            "payment_method": "ACH Direct Deposit",
            "estimated_payment_date": (now + timedelta(days=r.randint(3, 10))).strftime(
                "%Y-%m-%d"
            ),
            "approver_notes": approver_notes,
            "approved_at": now.isoformat(),
            "compliance_checks": {
                "fair_claims_practices": "PASSED",
                "state_regulation": "PASSED",
                "fraud_clearance": "PASSED",
                "supervisor_approval": "REQUIRED" if amount > 25000 else "NOT_REQUIRED",
            },
            "note": "Demo settlement system: approval and payment are simulated.",
        },
        simulated=True,
    )


def get_settlement_analytics() -> dict:
    """Monthly settlement book, aggregated up from the per-claim-type mix.

    The headline KPIs are computed FROM by_claim_type, not drawn beside it: the
    card header renders "N settlements - $X paid" directly above the four
    per-type rows, so an independent randint for the total produced "328
    settlements" over rows summing to 232.
    """
    now = datetime.now(timezone.utc)
    r = _rng("settlement_analytics", now.strftime("%Y-%m"))

    # (count range, average settlement range) per claim type
    mix = {
        "auto": ((40, 150), (3000, 12000)),
        "home": ((20, 80), (5000, 25000)),
        "health": ((30, 120), (2000, 15000)),
        "property": ((10, 50), (4000, 20000)),
    }
    by_claim_type = {
        name: {
            "count": r.randint(*counts),
            "avg_amount": round(r.uniform(*amounts), 2),
        }
        for name, (counts, amounts) in mix.items()
    }

    total_settlements = sum(t["count"] for t in by_claim_type.values())
    total_paid = round(
        sum(t["count"] * t["avg_amount"] for t in by_claim_type.values()), 2
    )
    average_settlement = round(total_paid / total_settlements, 2)
    # Claim amounts are right-skewed — a few large losses pull the mean above the
    # median. Deriving the median as a fraction of the mean keeps that ordering;
    # an independent draw let the median land above the average.
    median_settlement = round(average_settlement * r.uniform(0.65, 0.9), 2)

    return tool_ok(
        {
            "period": "current_month",
            "kpis": {
                "total_settlements": total_settlements,
                "total_amount_paid": total_paid,
                "average_settlement": average_settlement,
                "median_settlement": median_settlement,
                "avg_processing_days": round(r.uniform(5, 20), 1),
                "straight_through_rate_pct": round(r.uniform(55, 75), 1),
                "customer_satisfaction": round(r.uniform(4.0, 4.8), 1),
            },
            "by_claim_type": by_claim_type,
            "trend": {
                "settlements_vs_prior_month": round(r.uniform(-10, 15), 1),
                "avg_amount_vs_prior_month": round(r.uniform(-5, 10), 1),
                "processing_time_vs_prior_month": round(r.uniform(-15, 5), 1),
            },
        },
        simulated=True,
    )


def estimate_reserve(claim_id: str, claim_type: str, severity: str) -> dict:
    severity = severity.lower()
    if severity not in SEVERITY_MULTIPLIERS:
        return tool_error(
            f"Invalid severity: {severity}", valid=sorted(SEVERITY_MULTIPLIERS)
        )
    r = _rng("estimate_reserve", claim_id, claim_type, severity)
    reserve = round(r.uniform(1000, 5000) * SEVERITY_MULTIPLIERS[severity], 2)

    return tool_ok(
        {
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
            "development_factor": round(r.uniform(1.0, 1.5), 3),
            "actuarial_method": "Chain-Ladder with Bornhuetter-Ferguson",
        },
        simulated=True,
    )


TOOLS = {
    "calculate_settlement": calculate_settlement,
    "approve_settlement": approve_settlement,
    "get_settlement_analytics": get_settlement_analytics,
    "estimate_reserve": estimate_reserve,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
