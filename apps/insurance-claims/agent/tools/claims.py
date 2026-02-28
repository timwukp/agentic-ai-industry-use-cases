from strands import tool
import json, uuid, random
from datetime import datetime, timedelta


@tool
def submit_claim(policy_number: str, claim_type: str, description: str, incident_date: str) -> str:
    """Submit a new insurance claim for processing.

    Initiates the claims workflow including validation, assignment, and initial assessment.

    Args:
        policy_number: The insurance policy number (e.g., 'POL-2024-001234').
        claim_type: Type of claim - 'auto', 'home', 'health', 'life', 'property', 'liability'.
        description: Detailed description of the incident or loss.
        incident_date: Date of the incident in YYYY-MM-DD format.

    Returns:
        JSON with claim ID, status, assigned adjuster, and next steps.
    """
    # Validate claim type
    valid_types = ["auto", "home", "health", "life", "property", "liability"]
    if claim_type.lower() not in valid_types:
        return json.dumps({"error": f"Invalid claim type. Must be one of: {valid_types}"})

    claim_id = f"CLM-{datetime.now().strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"

    return json.dumps({
        "claim_id": claim_id,
        "status": "SUBMITTED",
        "policy_number": policy_number,
        "claim_type": claim_type.lower(),
        "description": description[:200],
        "incident_date": incident_date,
        "submitted_at": datetime.utcnow().isoformat() + "Z",
        "assigned_adjuster": f"ADJ-{random.randint(1000, 9999)}",
        "priority": random.choice(["LOW", "MEDIUM", "HIGH"]),
        "estimated_processing_days": random.randint(3, 30),
        "next_steps": [
            "Claim registered in system",
            "Adjuster assigned for review",
            "Supporting documentation requested",
            "Initial assessment within 48 hours"
        ],
        "required_documents": [
            "Proof of loss",
            "Photos of damage" if claim_type in ["auto", "home", "property"] else "Medical records",
            "Police report" if claim_type in ["auto", "liability"] else "Receipts/invoices",
            "Signed claim form"
        ]
    })


@tool
def get_claim_status(claim_id: str) -> str:
    """Get the current status and details of an insurance claim.

    Args:
        claim_id: The claim identifier (e.g., 'CLM-2024-A1B2C3').

    Returns:
        JSON with claim status, timeline, and current stage details.
    """
    stages = ["SUBMITTED", "UNDER_REVIEW", "INVESTIGATION", "ASSESSMENT", "SETTLEMENT_OFFERED", "CLOSED"]
    current_stage_idx = random.randint(0, len(stages) - 1)

    timeline = []
    for i in range(current_stage_idx + 1):
        timeline.append({
            "stage": stages[i],
            "date": (datetime.utcnow() - timedelta(days=(current_stage_idx - i) * 3)).strftime("%Y-%m-%d"),
            "note": f"Claim progressed to {stages[i].lower().replace('_', ' ')} stage"
        })

    return json.dumps({
        "claim_id": claim_id,
        "current_status": stages[current_stage_idx],
        "stage_progress": f"{current_stage_idx + 1}/{len(stages)}",
        "claim_type": random.choice(["auto", "home", "health", "property"]),
        "claimant": "John Doe",
        "assigned_adjuster": f"ADJ-{random.randint(1000, 9999)}",
        "filed_date": (datetime.utcnow() - timedelta(days=current_stage_idx * 3 + 5)).strftime("%Y-%m-%d"),
        "estimated_amount": round(random.uniform(1000, 50000), 2),
        "timeline": timeline,
        "documents_received": random.randint(1, 5),
        "documents_required": 5,
        "fraud_risk_score": round(random.uniform(0, 1), 2),
    })


@tool
def assess_damage(claim_id: str, damage_type: str, photos_submitted: int) -> str:
    """Perform AI-assisted damage assessment for a claim.

    Analyzes submitted evidence to estimate repair costs and damage severity.
    Uses AgentCore Code Interpreter for complex cost modeling.

    Args:
        claim_id: The claim identifier.
        damage_type: Type of damage - 'vehicle', 'structural', 'water', 'fire', 'medical', 'theft'.
        photos_submitted: Number of photos/evidence files submitted.

    Returns:
        JSON with damage assessment, estimated costs, and severity rating.
    """
    severity_map = {
        "vehicle": {"minor": (500, 3000), "moderate": (3000, 15000), "severe": (15000, 50000), "total_loss": (20000, 80000)},
        "structural": {"minor": (1000, 5000), "moderate": (5000, 25000), "severe": (25000, 100000), "total_loss": (50000, 500000)},
        "water": {"minor": (500, 2000), "moderate": (2000, 15000), "severe": (15000, 75000), "total_loss": (30000, 200000)},
        "fire": {"minor": (1000, 5000), "moderate": (5000, 30000), "severe": (30000, 150000), "total_loss": (50000, 500000)},
        "medical": {"minor": (200, 2000), "moderate": (2000, 20000), "severe": (20000, 100000), "total_loss": (50000, 500000)},
        "theft": {"minor": (100, 1000), "moderate": (1000, 10000), "severe": (10000, 50000), "total_loss": (20000, 100000)},
    }

    if damage_type not in severity_map:
        return json.dumps({"error": f"Invalid damage_type. Must be one of: {list(severity_map.keys())}"})

    severity = random.choice(["minor", "moderate", "severe", "total_loss"])
    cost_range = severity_map[damage_type][severity]
    estimated_cost = round(random.uniform(*cost_range), 2)

    confidence = min(0.95, 0.5 + photos_submitted * 0.08)

    return json.dumps({
        "claim_id": claim_id,
        "damage_type": damage_type,
        "severity": severity.upper(),
        "severity_score": round(random.uniform(0.1, 1.0), 2),
        "estimated_repair_cost": estimated_cost,
        "cost_range": {"low": round(estimated_cost * 0.8, 2), "high": round(estimated_cost * 1.3, 2)},
        "assessment_confidence": round(confidence, 2),
        "photos_analyzed": photos_submitted,
        "findings": [
            f"{damage_type.capitalize()} damage detected - {severity} severity",
            f"Estimated repair/replacement cost: ${estimated_cost:,.2f}",
            f"Assessment confidence: {confidence*100:.0f}% based on {photos_submitted} evidence items",
            "Recommend independent adjuster verification" if severity in ["severe", "total_loss"] else "Standard processing recommended"
        ],
        "recommended_action": "FAST_TRACK" if severity == "minor" else "STANDARD_REVIEW" if severity == "moderate" else "DETAILED_INVESTIGATION",
    })


@tool
def list_claims(status_filter: str, days: int) -> str:
    """List claims with optional status filter.

    Args:
        status_filter: Filter by status - 'all', 'open', 'pending', 'closed', 'flagged'.
        days: Number of days to look back (max 90).

    Returns:
        JSON with list of claims matching the filter.
    """
    days = min(days, 90)
    statuses = ["SUBMITTED", "UNDER_REVIEW", "INVESTIGATION", "ASSESSMENT", "SETTLEMENT_OFFERED", "CLOSED"]
    claim_types = ["auto", "home", "health", "property", "liability"]

    claims = []
    for i in range(random.randint(8, 20)):
        status = random.choice(statuses)
        if status_filter == "open" and status == "CLOSED":
            status = "UNDER_REVIEW"
        elif status_filter == "closed":
            status = "CLOSED"
        elif status_filter == "flagged":
            status = random.choice(["INVESTIGATION", "UNDER_REVIEW"])

        claims.append({
            "claim_id": f"CLM-2026-{uuid.uuid4().hex[:6].upper()}",
            "status": status,
            "claim_type": random.choice(claim_types),
            "filed_date": (datetime.utcnow() - timedelta(days=random.randint(0, days))).strftime("%Y-%m-%d"),
            "amount": round(random.uniform(500, 75000), 2),
            "priority": random.choice(["LOW", "MEDIUM", "HIGH"]),
            "fraud_risk": round(random.uniform(0, 1), 2),
        })

    claims.sort(key=lambda c: c["filed_date"], reverse=True)

    return json.dumps({
        "filter": status_filter,
        "period_days": days,
        "total_claims": len(claims),
        "claims": claims,
        "summary": {
            "total_amount": round(sum(c["amount"] for c in claims), 2),
            "avg_amount": round(sum(c["amount"] for c in claims) / len(claims), 2),
            "high_priority": sum(1 for c in claims if c["priority"] == "HIGH"),
            "flagged_fraud": sum(1 for c in claims if c["fraud_risk"] > 0.7),
        }
    })
