from strands import tool
import json, random
from datetime import datetime, timedelta


@tool
def analyze_fraud_risk(claim_id: str) -> str:
    """Analyze a claim for potential fraud indicators.

    Runs multi-factor fraud analysis including pattern matching, anomaly detection,
    and behavioral analysis against known fraud patterns.

    Args:
        claim_id: The claim identifier to analyze.

    Returns:
        JSON with fraud risk score, indicators, and recommended actions.
    """
    risk_score = round(random.uniform(0, 1), 3)

    all_indicators = [
        {"name": "Claim filed within 30 days of policy inception", "severity": "HIGH", "weight": 0.15},
        {"name": "Multiple claims in short period", "severity": "HIGH", "weight": 0.12},
        {"name": "Inconsistent damage description vs photos", "severity": "MEDIUM", "weight": 0.10},
        {"name": "Prior fraud history in database", "severity": "CRITICAL", "weight": 0.20},
        {"name": "Claim amount near policy limit", "severity": "MEDIUM", "weight": 0.08},
        {"name": "Late reporting of incident", "severity": "LOW", "weight": 0.05},
        {"name": "Unusual geographic pattern", "severity": "MEDIUM", "weight": 0.07},
        {"name": "Staged accident indicators", "severity": "HIGH", "weight": 0.15},
        {"name": "Provider on watch list", "severity": "HIGH", "weight": 0.12},
        {"name": "Inconsistent witness statements", "severity": "MEDIUM", "weight": 0.09},
    ]

    num_flags = int(risk_score * 6)
    flagged = random.sample(all_indicators, min(num_flags, len(all_indicators)))

    if risk_score > 0.7:
        recommendation = "REFER_TO_SIU"
        risk_level = "HIGH"
    elif risk_score > 0.4:
        recommendation = "ENHANCED_REVIEW"
        risk_level = "MEDIUM"
    else:
        recommendation = "STANDARD_PROCESSING"
        risk_level = "LOW"

    return json.dumps({
        "claim_id": claim_id,
        "fraud_risk_score": risk_score,
        "risk_level": risk_level,
        "indicators_flagged": len(flagged),
        "indicators": flagged,
        "recommendation": recommendation,
        "analysis_details": {
            "pattern_match_score": round(random.uniform(0, 1), 2),
            "anomaly_score": round(random.uniform(0, 1), 2),
            "behavioral_score": round(random.uniform(0, 1), 2),
            "network_analysis_score": round(random.uniform(0, 1), 2),
        },
        "similar_fraud_cases": random.randint(0, 5),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def check_fraud_patterns(claimant_id: str) -> str:
    """Check claimant history for fraud patterns across all claims.

    Args:
        claimant_id: The claimant/policyholder identifier.

    Returns:
        JSON with claimant fraud profile and historical patterns.
    """
    num_past_claims = random.randint(0, 8)
    flagged_claims = random.randint(0, min(2, num_past_claims))

    return json.dumps({
        "claimant_id": claimant_id,
        "total_past_claims": num_past_claims,
        "flagged_claims": flagged_claims,
        "claim_frequency": "HIGH" if num_past_claims > 5 else "MEDIUM" if num_past_claims > 2 else "LOW",
        "total_claimed_amount": round(random.uniform(0, 200000), 2),
        "total_paid_amount": round(random.uniform(0, 150000), 2),
        "patterns_detected": [
            p for p in [
                "Frequent small claims" if num_past_claims > 4 else None,
                "Claims across multiple policy types" if random.random() > 0.5 else None,
                "Claims coincide with financial difficulties" if random.random() > 0.7 else None,
                "Previous SIU referral" if flagged_claims > 0 else None,
            ] if p
        ],
        "risk_category": "WATCH_LIST" if flagged_claims > 0 else "STANDARD",
        "last_claim_date": (datetime.utcnow() - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d"),
    })


@tool
def generate_fraud_report(claim_id: str, investigation_findings: str) -> str:
    """Generate a formal fraud investigation report.

    Creates a structured report for SIU (Special Investigation Unit) review.

    Args:
        claim_id: The claim under investigation.
        investigation_findings: Summary of investigation findings.

    Returns:
        JSON with the formal investigation report structure.
    """
    report_id = f"FIR-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    return json.dumps({
        "report_id": report_id,
        "claim_id": claim_id,
        "report_type": "FRAUD_INVESTIGATION",
        "status": "DRAFT",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "sections": {
            "executive_summary": investigation_findings[:500],
            "evidence_collected": [
                "Claim documentation reviewed",
                "Photo/video evidence analyzed",
                "Witness statements collected",
                "Database cross-reference completed",
                "Provider verification conducted"
            ],
            "risk_indicators": [
                {"indicator": "Pattern anomaly", "confidence": round(random.uniform(0.5, 0.95), 2)},
                {"indicator": "Timeline inconsistency", "confidence": round(random.uniform(0.3, 0.85), 2)},
            ],
            "financial_impact": {
                "claimed_amount": round(random.uniform(5000, 100000), 2),
                "estimated_legitimate_amount": round(random.uniform(1000, 50000), 2),
                "potential_savings": round(random.uniform(2000, 50000), 2),
            },
            "recommendation": random.choice(["DENY_CLAIM", "REDUCE_SETTLEMENT", "REFER_TO_LAW_ENFORCEMENT", "CLOSE_NO_FRAUD"]),
        },
        "compliance": {
            "fair_claims_practices_compliant": True,
            "state_regulation_checked": True,
            "documentation_complete": random.choice([True, False]),
        },
    })


@tool
def get_fraud_dashboard() -> str:
    """Get fraud detection dashboard metrics and KPIs.

    Returns:
        JSON with fraud detection performance metrics.
    """
    return json.dumps({
        "period": "current_month",
        "metrics": {
            "total_claims_screened": random.randint(500, 2000),
            "flagged_for_review": random.randint(30, 100),
            "confirmed_fraud": random.randint(5, 20),
            "false_positives": random.randint(10, 30),
            "detection_rate_pct": round(random.uniform(92, 98), 1),
            "false_positive_rate_pct": round(random.uniform(2, 8), 1),
            "savings_from_detection": round(random.uniform(100000, 500000), 2),
        },
        "top_fraud_types": [
            {"type": "Staged accidents", "count": random.randint(3, 10), "pct": round(random.uniform(15, 30), 1)},
            {"type": "Inflated claims", "count": random.randint(5, 15), "pct": round(random.uniform(20, 35), 1)},
            {"type": "Phantom damage", "count": random.randint(2, 8), "pct": round(random.uniform(10, 20), 1)},
            {"type": "Identity fraud", "count": random.randint(1, 5), "pct": round(random.uniform(5, 15), 1)},
        ],
        "trend": "IMPROVING" if random.random() > 0.3 else "STABLE",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
