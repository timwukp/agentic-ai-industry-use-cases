"""Gateway target: policy — verification, coverage checks, history, search.

Policy data is a deterministic simulation seeded from the function inputs.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok
from toolkit.dispatch import dispatch

COVERAGE_MAP = {
    "auto": {
        "liability": 300000,
        "collision": 50000,
        "comprehensive": 50000,
        "medical": 10000,
        "uninsured": 100000,
    },
    "homeowners": {
        "dwelling": 500000,
        "personal_property": 250000,
        "liability": 300000,
        "medical": 5000,
        "additional_living": 100000,
    },
    "health": {
        "annual_max": 1000000,
        "deductible": 2500,
        "out_of_pocket_max": 8000,
        "copay": 30,
        "coinsurance_pct": 20,
    },
    "life": {"death_benefit": 500000, "accidental_death": 1000000, "cash_value": 50000},
    "commercial": {
        "general_liability": 1000000,
        "property": 500000,
        "business_interruption": 250000,
        "workers_comp": 500000,
    },
    "umbrella": {
        "coverage_limit": 2000000,
        "underlying_auto": 300000,
        "underlying_home": 300000,
    },
}


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def verify_policy(policy_number: str) -> dict:
    r = _rng("verify_policy", policy_number)
    today = _today()
    policy_type = r.choice(sorted(COVERAGE_MAP))
    start_date = today - timedelta(days=r.randint(30, 365))
    end_date = start_date + timedelta(days=365)

    return tool_ok(
        {
            "policy_number": policy_number,
            "status": "ACTIVE" if end_date > today else "EXPIRED",
            "policy_type": policy_type,
            "policyholder": {
                "name": "Jane Smith",
                "id": f"PH-{r.randint(100000, 999999)}",
                "address": "123 Main St, Anytown, USA",
            },
            "effective_date": start_date.strftime("%Y-%m-%d"),
            "expiration_date": end_date.strftime("%Y-%m-%d"),
            "premium": {
                "annual": round(r.uniform(1000, 8000), 2),
                "payment_frequency": r.choice(["monthly", "quarterly", "annual"]),
                "next_due": (today + timedelta(days=r.randint(1, 30))).strftime(
                    "%Y-%m-%d"
                ),
                "paid_to_date": True,
            },
            "coverage": COVERAGE_MAP[policy_type],
            "deductible": round(r.uniform(250, 5000), 2),
            "endorsements": r.sample(
                [
                    "Roadside assistance",
                    "Rental car coverage",
                    "Flood insurance",
                    "Jewelry rider",
                    "Home office coverage",
                ],
                k=r.randint(0, 3),
            ),
        },
        simulated=True,
    )


def check_coverage(policy_number: str, claim_type: str, claimed_amount: float) -> dict:
    claimed_amount = float(claimed_amount)
    r = _rng("check_coverage", policy_number, claim_type, claimed_amount)
    coverage_limit = round(r.uniform(50000, 500000), 2)
    deductible = round(r.uniform(250, 5000), 2)
    is_covered = r.random() > 0.1
    payable = max(0.0, min(claimed_amount - deductible, coverage_limit))

    return tool_ok(
        {
            "policy_number": policy_number,
            "claim_type": claim_type,
            "coverage_determination": "COVERED" if is_covered else "NOT_COVERED",
            "coverage_limit": coverage_limit,
            "deductible": deductible,
            "claimed_amount": claimed_amount,
            "payable_amount": round(payable, 2) if is_covered else 0,
            "remaining_limit": round(coverage_limit - payable, 2),
            "exclusions_checked": [
                "Pre-existing conditions",
                "Intentional acts",
                "War/terrorism",
                "Normal wear and tear",
                "Nuclear hazard",
            ],
            "exclusion_applies": not is_covered,
            "notes": (
                "Claim falls within policy coverage and limits"
                if is_covered
                else "Claim may fall under policy exclusion. Review required."
            ),
        },
        simulated=True,
    )


def get_policy_history(policy_number: str) -> dict:
    r = _rng("policy_history", policy_number)
    today = _today()
    num_claims = r.randint(0, 5)
    claims = [
        {
            "claim_id": f"CLM-{2024 + i // 3}-{r.randint(100000, 999999)}",
            "date": (today - timedelta(days=r.randint(30, 730))).strftime("%Y-%m-%d"),
            "type": r.choice(["auto", "home", "health", "property"]),
            "amount_claimed": round(r.uniform(500, 30000), 2),
            "amount_paid": round(r.uniform(200, 25000), 2),
            "status": "CLOSED",
        }
        for i in range(num_claims)
    ]

    return tool_ok(
        {
            "policy_number": policy_number,
            "total_claims": num_claims,
            "total_paid": round(sum(c["amount_paid"] for c in claims), 2),
            "claims": sorted(claims, key=lambda c: c["date"], reverse=True),
            "loss_ratio": round(r.uniform(0.3, 0.9), 2),
            "policy_changes": [
                {"date": "2025-01-15", "change": "Coverage limit increased"},
                {
                    "date": "2024-06-01",
                    "change": "Deductible changed from $500 to $1000",
                },
            ],
            "renewal_recommendation": (
                "STANDARD" if num_claims < 3 else "REVIEW_PREMIUM"
            ),
        },
        simulated=True,
    )


def search_policies(search_term: str) -> dict:
    r = _rng("search_policies", search_term)
    results = [
        {
            "policy_number": f"POL-{r.randint(2020, 2026)}-{r.randint(100000, 999999)}",
            "policyholder": f"{r.choice(['John', 'Jane'])} {r.choice(['Smith', 'Doe'])}",
            "type": r.choice(["auto", "homeowners", "health", "life"]),
            "status": r.choice(["ACTIVE", "ACTIVE", "ACTIVE", "EXPIRED"]),
            "premium": round(r.uniform(1000, 5000), 2),
            "match_field": r.choice(["name", "policy_number", "address"]),
        }
        for _ in range(r.randint(1, 5))
    ]

    return tool_ok(
        {
            "search_term": search_term,
            "results_count": len(results),
            "results": results,
        },
        simulated=True,
    )


TOOLS = {
    "verify_policy": verify_policy,
    "check_coverage": check_coverage,
    "get_policy_history": get_policy_history,
    "search_policies": search_policies,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
