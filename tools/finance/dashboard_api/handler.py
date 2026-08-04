"""REST API Lambda behind API Gateway (HTTP API + Cognito JWT authorizer).

Routes:
  GET /api/finance/portfolio        — positions + summary
  GET /api/finance/orders           — recent orders
  GET /api/finance/market/overview  — indices, VIX, treasury, sectors
"""
import json

from portfolio_tools import get_portfolio_positions  # aliased at packaging time
from trading_tools import get_trade_history
from toolkit import MarketSim

CORS_HEADERS_BASE = {
    "Content-Type": "application/json",
}


def _response(status: int, body: dict) -> dict:
    return {"statusCode": status, "headers": CORS_HEADERS_BASE, "body": json.dumps(body)}


def lambda_handler(event, context):
    route = event.get("routeKey", "")
    params = event.get("queryStringParameters") or {}
    portfolio_id = params.get("portfolioId", "default")

    if route == "GET /api/finance/portfolio":
        return _response(200, get_portfolio_positions(portfolio_id))
    if route == "GET /api/finance/orders":
        days = int(params.get("days", "30"))
        return _response(200, get_trade_history(portfolio_id, days))
    if route == "GET /api/finance/market/overview":
        sim = MarketSim()
        return _response(200, {**sim.market_overview(),
                               "sectors": sim.sector_performance(),
                               "source": "simulated"})
    return _response(404, {"error": f"Unknown route: {route}"})
