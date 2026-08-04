"""REST API Lambda behind API Gateway (HTTP API + Cognito JWT authorizer).

Routes (plant reliability dashboard):
  GET /api/manufacturing/overview   — fleet health, alerts, maintenance load, parts
  GET /api/manufacturing/equipment  — one asset: prediction + reliability (?equipmentId=)
  GET /api/manufacturing/sensor     — sensor history (?equipmentId=&sensorType=&hours=)

Reuses the deterministic gateway-tool logic (aliased at packaging time), so
dashboard numbers always match what the agent reports in chat.
"""

import json

from equipment_tools import get_equipment_alerts, get_equipment_list, get_sensor_data
from maintenance_tools import get_maintenance_calendar
from parts_tools import get_parts_inventory_report
from prediction_tools import get_reliability_metrics, predict_failure


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def lambda_handler(event, context):
    route = event.get("routeKey", "")
    params = event.get("queryStringParameters") or {}

    if route == "GET /api/manufacturing/overview":
        facility = params.get("facilityId", "all")
        return _response(
            200,
            {
                "fleet": get_equipment_list(facility),
                "alerts": get_equipment_alerts(),
                "calendar": get_maintenance_calendar(facility, 30),
                "parts": get_parts_inventory_report(),
            },
        )

    if route == "GET /api/manufacturing/equipment":
        equipment_id = params.get("equipmentId", "")
        if not equipment_id:
            return _response(400, {"error": "equipmentId is required"})
        return _response(
            200,
            {
                "prediction": predict_failure(equipment_id),
                "reliability": get_reliability_metrics(equipment_id),
            },
        )

    if route == "GET /api/manufacturing/sensor":
        equipment_id = params.get("equipmentId", "")
        if not equipment_id:
            return _response(400, {"error": "equipmentId is required"})
        sensor_type = params.get("sensorType", "vibration")
        hours = int(params.get("hours", "24"))
        return _response(200, get_sensor_data(equipment_id, sensor_type, hours))

    return _response(404, {"error": f"Unknown route: {route}"})
