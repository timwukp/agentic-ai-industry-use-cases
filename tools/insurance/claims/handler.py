"""Gateway target: claims — claim intake, status, damage assessment, listing.

Claim data is a deterministic simulation seeded from the function inputs.
submit_claim additionally persists the claim to INSURANCE_TABLE when that
env var is configured (graceful no-persist fallback otherwise).
"""
import hashlib
import os
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

VALID_CLAIM_TYPES = ["auto", "home", "health", "life", "property", "liability"]
CLAIM_STAGES = ["SUBMITTED", "UNDER_REVIEW", "INVESTIGATION", "ASSESSMENT",
                "SETTLEMENT_OFFERED", "CLOSED"]

SEVERITY_MAP = {
    "vehicle": {"minor": (500, 3000), "moderate": (3000, 15000), "severe": (15000, 50000), "total_loss": (20000, 80000)},
    "structural": {"minor": (1000, 5000), "moderate": (5000, 25000), "severe": (25000, 100000), "total_loss": (50000, 500000)},
    "water": {"minor": (500, 2000), "moderate": (2000, 15000), "severe": (15000, 75000), "total_loss": (30000, 200000)},
    "fire": {"minor": (1000, 5000), "moderate": (5000, 30000), "severe": (30000, 150000), "total_loss": (50000, 500000)},
    "medical": {"minor": (200, 2000), "moderate": (2000, 20000), "severe": (20000, 100000), "total_loss": (50000, 500000)},
    "theft": {"minor": (100, 1000), "moderate": (1000, 10000), "severe": (10000, 50000), "total_loss": (20000, 100000)},
}


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def _persist_claim(claim: dict) -> str:
    """Write the claim to INSURANCE_TABLE if configured; report the outcome."""
    if not os.environ.get("INSURANCE_TABLE"):
        return "disabled (INSURANCE_TABLE not configured)"
    try:
        from toolkit.dynamo import table, to_decimal
        table("INSURANCE_TABLE").put_item(Item=to_decimal(claim))
        return "persisted"
    except Exception as exc:  # graceful: templates run without DynamoDB
        return f"failed ({type(exc).__name__}: {exc})"


def submit_claim(policy_number: str, claim_type: str, description: str,
                 incident_date: str) -> dict:
    claim_type = claim_type.lower()
    if claim_type not in VALID_CLAIM_TYPES:
        return tool_error(f"Invalid claim type: {claim_type}", valid=VALID_CLAIM_TYPES)
    try:
        datetime.strptime(incident_date, "%Y-%m-%d")
    except ValueError:
        return tool_error("incident_date must be in YYYY-MM-DD format")

    r = _rng("submit_claim", policy_number, claim_type, description, incident_date)
    now = _today()
    claim_id = f"CLM-{now.strftime('%Y')}-{r.randrange(16 ** 6):06X}"

    claim = {
        "claimId": claim_id,
        "policyNumber": policy_number,
        "claimType": claim_type,
        "description": description[:200],
        "incidentDate": incident_date,
        "status": "SUBMITTED",
        "assignedAdjuster": f"ADJ-{r.randint(1000, 9999)}",
        "priority": r.choice(["LOW", "MEDIUM", "HIGH"]),
        "submittedAt": now.isoformat(),
    }
    persistence = _persist_claim(claim)

    return tool_ok({
        "claim_id": claim_id,
        "status": "SUBMITTED",
        "policy_number": policy_number,
        "claim_type": claim_type,
        "description": claim["description"],
        "incident_date": incident_date,
        "submitted_at": claim["submittedAt"],
        "assigned_adjuster": claim["assignedAdjuster"],
        "priority": claim["priority"],
        "estimated_processing_days": r.randint(3, 30),
        "next_steps": [
            "Claim registered in system",
            "Adjuster assigned for review",
            "Supporting documentation requested",
            "Initial assessment within 48 hours",
        ],
        "required_documents": [
            "Proof of loss",
            "Photos of damage" if claim_type in ("auto", "home", "property") else "Medical records",
            "Police report" if claim_type in ("auto", "liability") else "Receipts/invoices",
            "Signed claim form",
        ],
        "persistence": persistence,
    }, simulated=True)


def get_claim_status(claim_id: str) -> dict:
    r = _rng("claim_status", claim_id)
    today = _today()
    stage_idx = r.randint(0, len(CLAIM_STAGES) - 1)
    timeline = [{
        "stage": CLAIM_STAGES[i],
        "date": (today - timedelta(days=(stage_idx - i) * 3)).strftime("%Y-%m-%d"),
        "note": f"Claim progressed to {CLAIM_STAGES[i].lower().replace('_', ' ')} stage",
    } for i in range(stage_idx + 1)]

    return tool_ok({
        "claim_id": claim_id,
        "current_status": CLAIM_STAGES[stage_idx],
        "stage_progress": f"{stage_idx + 1}/{len(CLAIM_STAGES)}",
        "claim_type": r.choice(["auto", "home", "health", "property"]),
        "assigned_adjuster": f"ADJ-{r.randint(1000, 9999)}",
        "filed_date": (today - timedelta(days=stage_idx * 3 + 5)).strftime("%Y-%m-%d"),
        "estimated_amount": round(r.uniform(1000, 50000), 2),
        "timeline": timeline,
        "documents_received": r.randint(1, 5),
        "documents_required": 5,
        "fraud_risk_score": round(r.uniform(0, 1), 2),
    }, simulated=True)


def assess_damage(claim_id: str, damage_type: str, photos_submitted: int) -> dict:
    damage_type = damage_type.lower()
    if damage_type not in SEVERITY_MAP:
        return tool_error(f"Invalid damage_type: {damage_type}", valid=sorted(SEVERITY_MAP))
    photos_submitted = max(0, int(photos_submitted))

    r = _rng("assess_damage", claim_id, damage_type, photos_submitted)
    severity = r.choice(["minor", "moderate", "severe", "total_loss"])
    cost_range = SEVERITY_MAP[damage_type][severity]
    estimated_cost = round(r.uniform(*cost_range), 2)
    confidence = round(min(0.95, 0.5 + photos_submitted * 0.08), 2)

    return tool_ok({
        "claim_id": claim_id,
        "damage_type": damage_type,
        "severity": severity.upper(),
        "estimated_repair_cost": estimated_cost,
        "cost_range": {"low": round(estimated_cost * 0.8, 2),
                       "high": round(estimated_cost * 1.3, 2)},
        "assessment_confidence": confidence,
        "photos_analyzed": photos_submitted,
        "findings": [
            f"{damage_type.capitalize()} damage detected - {severity} severity",
            f"Estimated repair/replacement cost: ${estimated_cost:,.2f}",
            f"Assessment confidence: {confidence * 100:.0f}% based on {photos_submitted} evidence items",
            ("Recommend independent adjuster verification"
             if severity in ("severe", "total_loss") else "Standard processing recommended"),
        ],
        "recommended_action": ("FAST_TRACK" if severity == "minor"
                               else "STANDARD_REVIEW" if severity == "moderate"
                               else "DETAILED_INVESTIGATION"),
    }, simulated=True)


def list_claims(status_filter: str = "all", days: int = 30) -> dict:
    days = min(max(1, int(days)), 90)
    status_filter = status_filter.lower()
    if status_filter not in ("all", "open", "pending", "closed", "flagged"):
        return tool_error(f"Invalid status_filter: {status_filter}",
                          valid=["all", "open", "pending", "closed", "flagged"])
    today = _today()
    r = _rng("list_claims", status_filter, days, today.strftime("%Y-%m-%d"))

    claims = []
    for _ in range(r.randint(8, 20)):
        status = r.choice(CLAIM_STAGES)
        if status_filter == "open" and status == "CLOSED":
            status = "UNDER_REVIEW"
        elif status_filter == "closed":
            status = "CLOSED"
        elif status_filter == "flagged":
            status = r.choice(["INVESTIGATION", "UNDER_REVIEW"])
        claims.append({
            "claim_id": f"CLM-{today.year}-{r.randrange(16 ** 6):06X}",
            "status": status,
            "claim_type": r.choice(["auto", "home", "health", "property", "liability"]),
            "filed_date": (today - timedelta(days=r.randint(0, days))).strftime("%Y-%m-%d"),
            "amount": round(r.uniform(500, 75000), 2),
            "priority": r.choice(["LOW", "MEDIUM", "HIGH"]),
            "fraud_risk": round(r.uniform(0, 1), 2),
        })
    claims.sort(key=lambda c: c["filed_date"], reverse=True)

    return tool_ok({
        "filter": status_filter,
        "period_days": days,
        "total_claims": len(claims),
        "claims": claims,
        "summary": {
            "total_amount": round(sum(c["amount"] for c in claims), 2),
            "avg_amount": round(sum(c["amount"] for c in claims) / len(claims), 2),
            "high_priority": sum(1 for c in claims if c["priority"] == "HIGH"),
            "flagged_fraud": sum(1 for c in claims if c["fraud_risk"] > 0.7),
        },
    }, simulated=True)


TOOLS = {
    "submit_claim": submit_claim,
    "get_claim_status": get_claim_status,
    "assess_damage": assess_damage,
    "list_claims": list_claims,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
