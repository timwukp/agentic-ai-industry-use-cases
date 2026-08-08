"""REST API Lambda behind API Gateway (HTTP API + Cognito JWT authorizer).

Routes:
  GET /api/finance/portfolio        — positions + summary
  GET /api/finance/orders           — recent orders
  GET /api/finance/market/overview  — indices, VIX, treasury, sectors (simulated)
  GET /api/finance/market/live      — real quotes/index/treasury/rates snapshots
"""

import json

from portfolio_tools import get_portfolio_positions  # aliased at packaging time
from trading_tools import get_trade_history
from market_live_tools import (
    get_index_level,
    get_live_quote,
    get_policy_rates,
    get_treasury_yields,
    list_tracked_symbols,
)
from toolkit import MarketSim

CORS_HEADERS_BASE = {
    "Content-Type": "application/json",
}


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": CORS_HEADERS_BASE,
        "body": json.dumps(body),
    }


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
        return _response(
            200,
            {
                **sim.market_overview(),
                "sectors": sim.sector_performance(),
                "source": "simulated",
            },
        )
    if route == "GET /api/finance/market/live":
        # Same functions the agent calls through the market-live gateway
        # target — one number, one function.
        tracked = list_tracked_symbols()
        symbols = tracked.get("symbols", [])
        return _response(
            200,
            {
                "indices": [get_index_level(ix) for ix in ("QQQ", "SPY")],
                "treasury": get_treasury_yields(),
                "rates": get_policy_rates(),
                "quotes": [get_live_quote(s) for s in symbols],
                "tracked": tracked,
            },
        )
    return _response(404, {"error": f"Unknown route: {route}"})
