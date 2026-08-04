"""REST API Lambda behind API Gateway (HTTP API + Cognito JWT authorizer).

Routes:
  GET /api/healthcare/population   — panel demographics, prevalence, HEDIS quality
  GET /api/healthcare/patient      — per-patient analytics (?patientId=PT-1001)
  GET /api/healthcare/availability — provider slots (?providerId=DR-SMITH&days=5)

Reuses the deterministic gateway-tool logic (aliased at packaging time), so
dashboard numbers always match what the agent reports in chat.
"""

import json

from analytics_tools import (
    get_patient_analytics,
    get_population_health_metrics,
    get_readmission_risk,
)
from scheduling_tools import get_provider_availability


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def lambda_handler(event, context):
    route = event.get("routeKey", "")
    params = event.get("queryStringParameters") or {}

    if route == "GET /api/healthcare/population":
        return _response(200, get_population_health_metrics())
    if route == "GET /api/healthcare/patient":
        patient_id = params.get("patientId", "PT-1001")
        return _response(200, {
            "analytics": get_patient_analytics(patient_id),
            "readmission": get_readmission_risk(patient_id),
        })
    if route == "GET /api/healthcare/availability":
        provider_id = params.get("providerId", "DR-SMITH")
        days = params.get("days", "5")
        return _response(200, get_provider_availability(provider_id, days))
    return _response(404, {"error": f"Unknown route: {route}"})
