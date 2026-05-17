"""AML/KYC compliance tools for the Trading Assistant.

Provides transaction screening, sanctions checking, customer behavior analysis,
and Suspicious Activity Report generation for anti-money laundering compliance.
"""

import json
import random
from datetime import datetime, timedelta

from strands import tool


@tool
def screen_transaction(transaction_id: str) -> str:
    """Screen a transaction against Anti-Money Laundering rules.

    Evaluates the transaction for suspicious patterns including structuring,
    layering, unusual velocity, and high-risk jurisdictions. Returns a risk
    score and recommendation for action.

    Args:
        transaction_id: The unique identifier of the transaction to screen.

    Returns:
        JSON string with AML risk score, flagged patterns, and recommendation (CLEAR/REVIEW/BLOCK).
    """
    risk_score = round(random.uniform(0, 1), 3)

    all_patterns = [
        {"pattern": "Structuring - multiple transactions just below reporting threshold", "severity": "HIGH"},
        {"pattern": "Rapid movement through multiple accounts (layering)", "severity": "HIGH"},
        {"pattern": "Transaction with high-risk jurisdiction", "severity": "MEDIUM"},
        {"pattern": "Unusual transaction velocity for customer profile", "severity": "MEDIUM"},
        {"pattern": "Round dollar amounts inconsistent with business type", "severity": "LOW"},
        {"pattern": "Transaction inconsistent with stated source of funds", "severity": "HIGH"},
        {"pattern": "Dormant account sudden activity", "severity": "MEDIUM"},
        {"pattern": "Third-party transfer to unrelated beneficiary", "severity": "MEDIUM"},
    ]

    num_flags = max(0, int(risk_score * 5))
    flagged_patterns = random.sample(all_patterns, min(num_flags, len(all_patterns)))

    if risk_score > 0.75:
        recommendation = "BLOCK"
    elif risk_score > 0.4:
        recommendation = "REVIEW"
    else:
        recommendation = "CLEAR"

    amount = round(random.uniform(500, 250000), 2)
    currencies = ["USD", "EUR", "GBP", "CHF", "JPY", "AED", "SGD"]

    return json.dumps({
        "transaction_id": transaction_id,
        "amount": amount,
        "currency": random.choice(currencies),
        "risk_score": risk_score,
        "recommendation": recommendation,
        "flagged_patterns": flagged_patterns,
        "screening_details": {
            "jurisdiction_risk": random.choice(["LOW", "MEDIUM", "HIGH"]),
            "velocity_check": random.choice(["PASS", "FLAG"]),
            "threshold_proximity": round(random.uniform(0, 1), 2),
            "pep_match": random.choice([True, False]),
        },
        "screened_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def check_sanctions_list(entity_name: str) -> str:
    """Check an entity against OFAC, UN, and EU sanctions lists.

    Performs fuzzy name matching against consolidated sanctions databases
    and returns potential matches with confidence scores.

    Args:
        entity_name: The name of the individual or organization to check.

    Returns:
        JSON string with match results including confidence scores and list sources.
    """
    has_match = random.random() > 0.7

    matches = []
    if has_match:
        num_matches = random.randint(1, 3)
        lists = ["OFAC-SDN", "OFAC-SSI", "UN-CONSOLIDATED", "EU-SANCTIONS", "UK-HMT"]
        for i in range(num_matches):
            matches.append({
                "matched_name": f"{entity_name} {'Jr.' if i > 0 else ''}".strip(),
                "list_source": random.choice(lists),
                "confidence_score": round(random.uniform(0.65, 0.99), 3),
                "match_type": random.choice(["EXACT", "FUZZY", "ALIAS", "PHONETIC"]),
                "sanctions_program": random.choice([
                    "Counter Terrorism",
                    "Non-Proliferation",
                    "Narcotics Trafficking",
                    "Transnational Criminal Organizations",
                    "Human Rights Abuse",
                ]),
                "listed_since": (datetime.utcnow() - timedelta(days=random.randint(30, 3650))).strftime("%Y-%m-%d"),
            })

    overall_status = "MATCH_FOUND" if has_match else "CLEAR"

    return json.dumps({
        "entity_name": entity_name,
        "screening_status": overall_status,
        "total_matches": len(matches),
        "matches": matches,
        "lists_checked": ["OFAC-SDN", "OFAC-SSI", "UN-CONSOLIDATED", "EU-SANCTIONS", "UK-HMT"],
        "recommendation": "BLOCK_AND_REPORT" if has_match else "PROCEED",
        "checked_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def analyze_customer_behavior(customer_id: str) -> str:
    """Analyze customer transaction behavior for anomalies.

    Reviews historical transaction patterns and identifies deviations from
    established behavioral baselines that may indicate money laundering or
    other financial crimes.

    Args:
        customer_id: The unique identifier of the customer to analyze.

    Returns:
        JSON string with behavioral risk profile including anomaly indicators and risk level.
    """
    avg_monthly_volume = round(random.uniform(5000, 500000), 2)
    current_month_volume = round(avg_monthly_volume * random.uniform(0.5, 3.0), 2)
    volume_deviation = round((current_month_volume - avg_monthly_volume) / avg_monthly_volume * 100, 1)

    anomalies = []
    possible_anomalies = [
        "Transaction volume spike exceeds 2 standard deviations",
        "New counterparty countries detected",
        "Shift from domestic to international transfers",
        "Increased use of cash deposits",
        "Change in transaction timing patterns",
        "New high-value beneficiaries added",
        "Sudden increase in wire transfers",
        "Activity inconsistent with declared occupation",
    ]
    num_anomalies = random.randint(0, 4)
    anomalies = random.sample(possible_anomalies, num_anomalies)

    if num_anomalies >= 3 or abs(volume_deviation) > 150:
        risk_level = "HIGH"
    elif num_anomalies >= 1 or abs(volume_deviation) > 75:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return json.dumps({
        "customer_id": customer_id,
        "risk_level": risk_level,
        "behavioral_profile": {
            "avg_monthly_volume": avg_monthly_volume,
            "current_month_volume": current_month_volume,
            "volume_deviation_pct": volume_deviation,
            "avg_transaction_size": round(avg_monthly_volume / random.randint(5, 50), 2),
            "typical_counterparties": random.randint(3, 20),
            "new_counterparties_this_month": random.randint(0, 5),
        },
        "anomalies_detected": anomalies,
        "peer_comparison": {
            "peer_group": random.choice(["Retail Banking", "SME", "Corporate", "High Net Worth"]),
            "percentile_rank": random.randint(1, 100),
            "deviation_from_peer_avg": round(random.uniform(-50, 200), 1),
        },
        "account_tenure_months": random.randint(3, 120),
        "last_review_date": (datetime.utcnow() - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d"),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_sar_report(customer_id: str, alert_id: str) -> str:
    """Generate a Suspicious Activity Report draft with narrative and supporting evidence.

    Creates a structured SAR filing draft compliant with FinCEN requirements,
    including a narrative summary, subject information, and suspicious activity details.

    Args:
        customer_id: The customer identifier associated with the suspicious activity.
        alert_id: The alert identifier that triggered the SAR filing.

    Returns:
        JSON string with SAR report draft including narrative, subject info, and filing details.
    """
    report_id = f"SAR-{datetime.now().strftime('%Y%m%d')}-{random.randint(10000, 99999)}"

    activity_types = [
        "Structuring/Smurfing",
        "Terrorist Financing",
        "Wire Transfer Fraud",
        "Identity Theft",
        "Mortgage Loan Fraud",
        "Check Fraud",
        "Money Laundering",
        "Bribery/Gratuity",
    ]

    total_amount = round(random.uniform(10000, 2000000), 2)
    num_transactions = random.randint(3, 50)

    start_date = datetime.utcnow() - timedelta(days=random.randint(30, 180))
    end_date = datetime.utcnow() - timedelta(days=random.randint(1, 29))

    return json.dumps({
        "report_id": report_id,
        "customer_id": customer_id,
        "alert_id": alert_id,
        "filing_status": "DRAFT",
        "subject_information": {
            "account_number": f"****{random.randint(1000, 9999)}",
            "account_type": random.choice(["Checking", "Savings", "Wire Transfer", "Investment"]),
            "relationship_start": (datetime.utcnow() - timedelta(days=random.randint(90, 3650))).strftime("%Y-%m-%d"),
        },
        "suspicious_activity": {
            "activity_type": random.sample(activity_types, random.randint(1, 3)),
            "total_amount_involved": total_amount,
            "number_of_transactions": num_transactions,
            "date_range_start": start_date.strftime("%Y-%m-%d"),
            "date_range_end": end_date.strftime("%Y-%m-%d"),
            "instruments_used": random.sample(
                ["Wire Transfer", "Cash", "Check", "ACH", "Cryptocurrency", "Money Order"],
                random.randint(1, 3),
            ),
        },
        "narrative_summary": (
            f"Subject account ending {random.randint(1000, 9999)} exhibited suspicious transaction patterns "
            f"involving {num_transactions} transactions totaling ${total_amount:,.2f} between "
            f"{start_date.strftime('%m/%d/%Y')} and {end_date.strftime('%m/%d/%Y')}. "
            f"Activity is inconsistent with the customer's stated business purpose and historical profile."
        ),
        "supporting_evidence": [
            "Transaction logs showing unusual patterns",
            "Customer profile deviation analysis",
            "Third-party adverse media findings",
            "Peer group comparison results",
        ],
        "filing_deadline": (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })
