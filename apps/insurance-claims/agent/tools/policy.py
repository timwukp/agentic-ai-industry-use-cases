from strands import tool
import json, random
from datetime import datetime, timedelta


@tool
def verify_policy(policy_number: str) -> str:
    """Verify an insurance policy and retrieve its details.

    Args:
        policy_number: The policy number to verify (e.g., 'POL-2024-001234').

    Returns:
        JSON with policy details, coverage limits, and status.
    """
    policy_types = ["auto", "homeowners", "health", "life", "commercial", "umbrella"]
    policy_type = random.choice(policy_types)

    coverage_map = {
        "auto": {"liability": 300000, "collision": 50000, "comprehensive": 50000, "medical": 10000, "uninsured": 100000},
        "homeowners": {"dwelling": 500000, "personal_property": 250000, "liability": 300000, "medical": 5000, "additional_living": 100000},
        "health": {"annual_max": 1000000, "deductible": 2500, "out_of_pocket_max": 8000, "copay": 30, "coinsurance_pct": 20},
        "life": {"death_benefit": 500000, "accidental_death": 1000000, "cash_value": 50000},
        "commercial": {"general_liability": 1000000, "property": 500000, "business_interruption": 250000, "workers_comp": 500000},
        "umbrella": {"coverage_limit": 2000000, "underlying_auto": 300000, "underlying_home": 300000},
    }

    start_date = datetime.utcnow() - timedelta(days=random.randint(30, 365))
    end_date = start_date + timedelta(days=365)
    is_active = end_date > datetime.utcnow()

    return json.dumps({
        "policy_number": policy_number,
        "status": "ACTIVE" if is_active else "EXPIRED",
        "policy_type": policy_type,
        "policyholder": {
            "name": "Jane Smith",
            "id": f"PH-{random.randint(100000, 999999)}",
            "address": "123 Main St, Anytown, USA",
            "phone": "555-0123",
        },
        "effective_date": start_date.strftime("%Y-%m-%d"),
        "expiration_date": end_date.strftime("%Y-%m-%d"),
        "premium": {
            "annual": round(random.uniform(1000, 8000), 2),
            "payment_frequency": random.choice(["monthly", "quarterly", "annual"]),
            "next_due": (datetime.utcnow() + timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%d"),
            "paid_to_date": True,
        },
        "coverage": coverage_map.get(policy_type, {}),
        "deductible": round(random.uniform(250, 5000), 2),
        "endorsements": random.sample(
            ["Roadside assistance", "Rental car coverage", "Flood insurance", "Jewelry rider", "Home office coverage"],
            k=random.randint(0, 3)
        ),
    })


@tool
def check_coverage(policy_number: str, claim_type: str, claimed_amount: float) -> str:
    """Check if a claim is covered under a policy and verify limits.

    Args:
        policy_number: The policy number.
        claim_type: Type of coverage being claimed.
        claimed_amount: Amount being claimed in USD.

    Returns:
        JSON with coverage determination and applicable limits.
    """
    coverage_limit = round(random.uniform(50000, 500000), 2)
    deductible = round(random.uniform(250, 5000), 2)
    is_covered = random.random() > 0.1

    payable = max(0, min(claimed_amount - deductible, coverage_limit))

    return json.dumps({
        "policy_number": policy_number,
        "claim_type": claim_type,
        "coverage_determination": "COVERED" if is_covered else "NOT_COVERED",
        "coverage_limit": coverage_limit,
        "deductible": deductible,
        "claimed_amount": claimed_amount,
        "payable_amount": round(payable, 2) if is_covered else 0,
        "remaining_limit": round(coverage_limit - payable, 2),
        "exclusions_checked": [
            "Pre-existing conditions", "Intentional acts", "War/terrorism",
            "Normal wear and tear", "Nuclear hazard"
        ],
        "exclusion_applies": not is_covered,
        "notes": "Claim falls within policy coverage and limits" if is_covered else "Claim may fall under policy exclusion. Review required.",
    })


@tool
def get_policy_history(policy_number: str) -> str:
    """Get claims history for a specific policy.

    Args:
        policy_number: The policy number.

    Returns:
        JSON with historical claims and policy changes.
    """
    num_claims = random.randint(0, 5)
    claims = []
    for i in range(num_claims):
        claims.append({
            "claim_id": f"CLM-{2024 + i // 3}-{random.randint(100000, 999999)}",
            "date": (datetime.utcnow() - timedelta(days=random.randint(30, 730))).strftime("%Y-%m-%d"),
            "type": random.choice(["auto", "home", "health", "property"]),
            "amount_claimed": round(random.uniform(500, 30000), 2),
            "amount_paid": round(random.uniform(200, 25000), 2),
            "status": "CLOSED",
        })

    return json.dumps({
        "policy_number": policy_number,
        "total_claims": num_claims,
        "total_paid": round(sum(c["amount_paid"] for c in claims), 2),
        "claims": sorted(claims, key=lambda c: c["date"], reverse=True),
        "loss_ratio": round(random.uniform(0.3, 0.9), 2),
        "policy_changes": [
            {"date": "2025-01-15", "change": "Coverage limit increased"},
            {"date": "2024-06-01", "change": "Deductible changed from $500 to $1000"},
        ],
        "renewal_recommendation": "STANDARD" if num_claims < 3 else "REVIEW_PREMIUM",
    })


@tool
def search_policies(search_term: str) -> str:
    """Search for policies by policyholder name, policy number, or claim ID.

    Args:
        search_term: Name, policy number, or claim ID to search for.

    Returns:
        JSON with matching policies.
    """
    results = []
    for i in range(random.randint(1, 5)):
        results.append({
            "policy_number": f"POL-{random.randint(2020, 2026)}-{random.randint(100000, 999999)}",
            "policyholder": f"{'John' if random.random() > 0.5 else 'Jane'} {'Smith' if random.random() > 0.5 else 'Doe'}",
            "type": random.choice(["auto", "homeowners", "health", "life"]),
            "status": random.choice(["ACTIVE", "ACTIVE", "ACTIVE", "EXPIRED"]),
            "premium": round(random.uniform(1000, 5000), 2),
            "match_field": random.choice(["name", "policy_number", "address"]),
        })

    return json.dumps({
        "search_term": search_term,
        "results_count": len(results),
        "results": results,
    })
