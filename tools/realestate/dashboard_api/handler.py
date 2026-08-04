"""REST API Lambda behind API Gateway (HTTP API + Cognito JWT authorizer).

Routes (market analyst dashboard):
  GET /api/realestate/market       — conditions + 12mo history + 12mo forecast (?zipcode=)
  GET /api/realestate/listings     — active listings for a market (?zipcode=&bedsMin=)
  GET /api/realestate/comparables  — comps for a subject address (?address=&radius=)

Reuses the deterministic gateway-tool logic (aliased at packaging time), so
dashboard numbers always match what the agent reports in chat.
"""

import json

from market_tools import get_market_conditions, get_market_forecast, get_market_trends
from property_tools import search_properties
from valuation_tools import get_comparables


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def lambda_handler(event, context):
    route = event.get("routeKey", "")
    params = event.get("queryStringParameters") or {}

    if route == "GET /api/realestate/market":
        zipcode = params.get("zipcode", "78701")
        return _response(
            200,
            {
                "conditions": get_market_conditions(zipcode),
                "trends": get_market_trends(zipcode, params.get("period", "1y")),
                "forecast": get_market_forecast(zipcode, 12),
            },
        )

    if route == "GET /api/realestate/listings":
        # search_properties takes a JSON string (same contract the agent uses)
        criteria = {
            "zipcode": params.get("zipcode", "78701"),
            "beds_min": int(params.get("bedsMin", "3")),
        }
        return _response(200, search_properties(json.dumps(criteria)))

    if route == "GET /api/realestate/comparables":
        address = params.get("address", "")
        if not address:
            return _response(400, {"error": "address is required"})
        radius = float(params.get("radius", "1.0"))
        return _response(200, get_comparables(address, radius, 6))

    return _response(404, {"error": f"Unknown route: {route}"})
