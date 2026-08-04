"""REST API Lambda behind API Gateway (HTTP API + Cognito JWT authorizer).

Routes (inventory-planner dashboard):
  GET /api/retail/overview   — inventory summary, ABC mix, margins, supplier risk
  GET /api/retail/stockouts  — active stockouts with revenue impact
  GET /api/retail/demand     — category demand trend (?category=all&period=month)
  GET /api/retail/forecast   — per-SKU demand forecast (?sku=SKU-1001&days=30)

Reuses the deterministic gateway-tool logic (aliased at packaging time), so
dashboard numbers always match what the agent reports in chat.
"""

import json

from forecast_tools import forecast_demand, get_abc_analysis, get_demand_trends
from inventory_tools import get_inventory_summary, get_stockout_report
from pricing_tools import get_margin_report
from supplier_tools import get_supplier_risk_report


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def lambda_handler(event, context):
    route = event.get("routeKey", "")
    params = event.get("queryStringParameters") or {}

    if route == "GET /api/retail/overview":
        category = params.get("category", "all")
        return _response(
            200,
            {
                "inventory": get_inventory_summary(category),
                "abc": get_abc_analysis(),
                "margins": get_margin_report(category),
                "supplier_risk": get_supplier_risk_report(),
            },
        )

    if route == "GET /api/retail/stockouts":
        return _response(200, get_stockout_report())

    if route == "GET /api/retail/demand":
        category = params.get("category", "all")
        period = params.get("period", "month")
        return _response(200, get_demand_trends(category, period))

    if route == "GET /api/retail/forecast":
        sku = params.get("sku", "SKU-1001")
        days = int(params.get("days", "30"))
        return _response(200, forecast_demand(sku, days))

    return _response(404, {"error": f"Unknown route: {route}"})
