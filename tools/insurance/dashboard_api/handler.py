"""REST API Lambda behind API Gateway (HTTP API + Cognito JWT authorizer).

Routes (claims-operations dashboard):
  GET /api/insurance/overview  — fraud detection + settlement KPIs (book level)
  GET /api/insurance/claims    — claims queue (?status=all|open|pending|closed|flagged&days=30)
  GET /api/insurance/claim     — one claim's status + fraud risk (?claimId=CLM-...)

Reuses the deterministic gateway-tool logic (aliased at packaging time), so
dashboard numbers always match what the agent reports in chat.
"""

import json

from claims_tools import get_claim_status, list_claims
from fraud_tools import analyze_fraud_risk, get_fraud_dashboard
from settlement_tools import get_settlement_analytics


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def lambda_handler(event, context):
    route = event.get("routeKey", "")
    params = event.get("queryStringParameters") or {}

    if route == "GET /api/insurance/overview":
        return _response(
            200,
            {
                "fraud": get_fraud_dashboard(),
                "settlement": get_settlement_analytics(),
            },
        )

    if route == "GET /api/insurance/claims":
        status_filter = params.get("status", "all")
        days = int(params.get("days", "30"))
        return _response(200, list_claims(status_filter, days))

    if route == "GET /api/insurance/claim":
        claim_id = params.get("claimId", "")
        if not claim_id:
            return _response(400, {"error": "claimId is required"})
        return _response(
            200,
            {
                "status": get_claim_status(claim_id),
                "fraud": analyze_fraud_risk(claim_id),
            },
        )

    return _response(404, {"error": f"Unknown route: {route}"})
