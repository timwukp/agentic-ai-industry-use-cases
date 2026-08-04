"""REST API Lambda behind API Gateway (HTTP API + Cognito JWT authorizer).

Routes (care-manager dashboard):
  GET /api/healthcare/population   — panel demographics, prevalence, HEDIS, utilization
  GET /api/healthcare/patient      — Patient 360 composite (?patientId=PT-1001)
  GET /api/healthcare/labs         — lab panels + medications (?patientId=&days=90)
  GET /api/healthcare/risk         — preventive risk score (?patientId=&type=cardiovascular)
  GET /api/healthcare/availability — provider slots (?providerId=DR-CHEN&days=5)

Reuses the deterministic gateway-tool logic (aliased at packaging time), so
dashboard numbers always match what the agent reports in chat.
"""

import json

from analytics_tools import (
    get_care_gap_analysis,
    get_patient_analytics,
    get_population_health_metrics,
    get_readmission_risk,
)
from clinical_tools import calculate_risk_score
from records_tools import (
    get_lab_results,
    get_medication_list,
    get_patient_summary,
)
from scheduling_tools import get_provider_availability, get_upcoming_appointments


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
        return _response(
            200,
            {
                "summary": get_patient_summary(patient_id),
                "analytics": get_patient_analytics(patient_id),
                "readmission": get_readmission_risk(patient_id),
                "care_gaps": get_care_gap_analysis(patient_id),
                "appointments": get_upcoming_appointments(patient_id),
            },
        )

    if route == "GET /api/healthcare/labs":
        patient_id = params.get("patientId", "PT-1001")
        days = int(params.get("days", "90"))
        return _response(
            200,
            {
                "labs": get_lab_results(patient_id, days),
                "medications": get_medication_list(patient_id),
            },
        )

    if route == "GET /api/healthcare/risk":
        patient_id = params.get("patientId", "PT-1001")
        risk_type = params.get("type", "cardiovascular")
        return _response(200, calculate_risk_score(patient_id, risk_type))

    if route == "GET /api/healthcare/availability":
        provider_id = params.get("providerId", "DR-CHEN")
        days = params.get("days", "5")
        return _response(200, get_provider_availability(provider_id, days))

    return _response(404, {"error": f"Unknown route: {route}"})
