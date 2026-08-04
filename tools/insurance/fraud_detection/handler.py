"""Gateway target: fraud_detection — fraud risk analysis, pattern checks, reports.

Fraud scores and samples are deterministic simulations seeded from the
function inputs.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok
from toolkit.dispatch import dispatch

FRAUD_INDICATORS = [
    {
        "name": "Claim filed within 30 days of policy inception",
        "severity": "HIGH",
        "weight": 0.15,
    },
    {"name": "Multiple claims in short period", "severity": "HIGH", "weight": 0.12},
    {
        "name": "Inconsistent damage description vs photos",
        "severity": "MEDIUM",
        "weight": 0.10,
    },
    {"name": "Prior fraud history in database", "severity": "CRITICAL", "weight": 0.20},
    {"name": "Claim amount near policy limit", "severity": "MEDIUM", "weight": 0.08},
    {"name": "Late reporting of incident", "severity": "LOW", "weight": 0.05},
    {"name": "Unusual geographic pattern", "severity": "MEDIUM", "weight": 0.07},
    {"name": "Staged accident indicators", "severity": "HIGH", "weight": 0.15},
    {"name": "Provider on watch list", "severity": "HIGH", "weight": 0.12},
    {"name": "Inconsistent witness statements", "severity": "MEDIUM", "weight": 0.09},
]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def analyze_fraud_risk(claim_id: str) -> dict:
    r = _rng("fraud_risk", claim_id)
    risk_score = round(r.uniform(0, 1), 3)
    flagged = r.sample(
        FRAUD_INDICATORS, min(int(risk_score * 6), len(FRAUD_INDICATORS))
    )

    if risk_score > 0.7:
        recommendation, risk_level = "REFER_TO_SIU", "HIGH"
    elif risk_score > 0.4:
        recommendation, risk_level = "ENHANCED_REVIEW", "MEDIUM"
    else:
        recommendation, risk_level = "STANDARD_PROCESSING", "LOW"

    return tool_ok(
        {
            "claim_id": claim_id,
            "fraud_risk_score": risk_score,
            "risk_level": risk_level,
            "indicators_flagged": len(flagged),
            "indicators": flagged,
            "recommendation": recommendation,
            "analysis_details": {
                "pattern_match_score": round(r.uniform(0, 1), 2),
                "anomaly_score": round(r.uniform(0, 1), 2),
                "behavioral_score": round(r.uniform(0, 1), 2),
                "network_analysis_score": round(r.uniform(0, 1), 2),
            },
            "similar_fraud_cases": r.randint(0, 5),
        },
        simulated=True,
    )


def check_fraud_patterns(claimant_id: str) -> dict:
    r = _rng("fraud_patterns", claimant_id)
    today = _today()
    num_past_claims = r.randint(0, 8)
    flagged_claims = r.randint(0, min(2, num_past_claims)) if num_past_claims else 0

    return tool_ok(
        {
            "claimant_id": claimant_id,
            "total_past_claims": num_past_claims,
            "flagged_claims": flagged_claims,
            "claim_frequency": (
                "HIGH"
                if num_past_claims > 5
                else "MEDIUM" if num_past_claims > 2 else "LOW"
            ),
            "total_claimed_amount": round(r.uniform(0, 200000), 2),
            "total_paid_amount": round(r.uniform(0, 150000), 2),
            "patterns_detected": [
                p
                for p in [
                    "Frequent small claims" if num_past_claims > 4 else None,
                    "Claims across multiple policy types" if r.random() > 0.5 else None,
                    (
                        "Claims coincide with financial difficulties"
                        if r.random() > 0.7
                        else None
                    ),
                    "Previous SIU referral" if flagged_claims > 0 else None,
                ]
                if p
            ],
            "risk_category": "WATCH_LIST" if flagged_claims > 0 else "STANDARD",
            "last_claim_date": (
                (today - timedelta(days=r.randint(30, 365))).strftime("%Y-%m-%d")
                if num_past_claims
                else None
            ),
        },
        simulated=True,
    )


def generate_fraud_report(claim_id: str, investigation_findings: str) -> dict:
    r = _rng("fraud_report", claim_id, investigation_findings)
    now = datetime.now(timezone.utc)
    claimed = round(r.uniform(5000, 100000), 2)
    legitimate = round(claimed * r.uniform(0.2, 0.8), 2)

    return tool_ok(
        {
            "report_id": f"FIR-{now.strftime('%Y%m%d')}-{r.randint(1000, 9999)}",
            "claim_id": claim_id,
            "report_type": "FRAUD_INVESTIGATION",
            "status": "DRAFT",
            "sections": {
                "executive_summary": investigation_findings[:500],
                "evidence_collected": [
                    "Claim documentation reviewed",
                    "Photo/video evidence analyzed",
                    "Witness statements collected",
                    "Database cross-reference completed",
                    "Provider verification conducted",
                ],
                "risk_indicators": [
                    {
                        "indicator": "Pattern anomaly",
                        "confidence": round(r.uniform(0.5, 0.95), 2),
                    },
                    {
                        "indicator": "Timeline inconsistency",
                        "confidence": round(r.uniform(0.3, 0.85), 2),
                    },
                ],
                "financial_impact": {
                    "claimed_amount": claimed,
                    "estimated_legitimate_amount": legitimate,
                    "potential_savings": round(claimed - legitimate, 2),
                },
                "recommendation": r.choice(
                    [
                        "DENY_CLAIM",
                        "REDUCE_SETTLEMENT",
                        "REFER_TO_LAW_ENFORCEMENT",
                        "CLOSE_NO_FRAUD",
                    ]
                ),
            },
            "compliance": {
                "fair_claims_practices_compliant": True,
                "state_regulation_checked": True,
                "documentation_complete": r.choice([True, False]),
            },
        },
        simulated=True,
    )


def get_fraud_dashboard() -> dict:
    """Monthly fraud funnel.

    Every number here is derived from the one above it in the funnel: screened
    -> flagged -> confirmed, then the pattern breakdown partitions the confirmed
    cases. Drawing each independently produced a dashboard that said "9
    confirmed cases" above a pattern chart whose bars summed to 20, and a
    detection rate unrelated to the counts beside it.
    """
    today = _today()
    r = _rng("fraud_dashboard", today.strftime("%Y-%m"))

    screened = r.randint(500, 2000)
    flagged = max(4, round(screened * r.uniform(0.03, 0.07)))
    confirmed = max(1, round(flagged * r.uniform(0.10, 0.25)))
    # A flagged claim is either confirmed fraud or a false positive — the two
    # must therefore partition `flagged`, not be drawn apart from it.
    false_positives = flagged - confirmed
    # Some fraud slips through screening entirely; recall needs that denominator.
    missed = max(0, round(confirmed * r.uniform(0.02, 0.09)))

    # The pattern counts partition the confirmed cases, so the bars sum to
    # exactly `confirmed` and each pct is that share of the total.
    weights = [
        r.uniform(*w) for w in ((0.15, 0.30), (0.20, 0.35), (0.10, 0.20), (0.05, 0.15))
    ]
    total_weight = sum(weights)
    counts = [max(0, round(confirmed * w / total_weight)) for w in weights]
    # rounding can drift by a case or two — settle the difference on the largest
    drift = confirmed - sum(counts)
    counts[counts.index(max(counts))] += drift

    return tool_ok(
        {
            "period": "current_month",
            "metrics": {
                "total_claims_screened": screened,
                "flagged_for_review": flagged,
                "confirmed_fraud": confirmed,
                "false_positives": false_positives,
                # recall: of all fraud that existed, the share screening caught
                "detection_rate_pct": round(confirmed / (confirmed + missed) * 100, 1),
                # of everything screened, the share wrongly flagged
                "false_positive_rate_pct": round(false_positives / screened * 100, 1),
                "missed_fraud_estimate": missed,
                "savings_from_detection": round(confirmed * r.uniform(15000, 45000), 2),
            },
            "top_fraud_types": [
                {
                    "type": name,
                    "count": count,
                    "pct": round(count / confirmed * 100, 1) if confirmed else 0.0,
                }
                for name, count in zip(
                    (
                        "Staged accidents",
                        "Inflated claims",
                        "Phantom damage",
                        "Identity fraud",
                    ),
                    counts,
                )
            ],
            "trend": "IMPROVING" if r.random() > 0.3 else "STABLE",
        },
        simulated=True,
    )


TOOLS = {
    "analyze_fraud_risk": analyze_fraud_risk,
    "check_fraud_patterns": check_fraud_patterns,
    "generate_fraud_report": generate_fraud_report,
    "get_fraud_dashboard": get_fraud_dashboard,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
