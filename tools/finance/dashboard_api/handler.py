"""REST API Lambda behind API Gateway (HTTP API + Cognito JWT authorizer).

Routes:
  GET /api/finance/portfolio        — positions + summary
  GET /api/finance/orders           — recent orders
  GET /api/finance/market/overview  — indices, VIX, treasury, sectors (simulated)
  GET /api/finance/market/live      — real quotes/index/treasury/rates snapshots
  GET /api/finance/signals          — factor loadings, hotspots, macro series
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
from macro_signals_tools import (
    get_factor_snapshot,
    get_macro_series,
    get_news_hotspots,
)
from quant_insights_tools import (
    get_confirmed_regularities,
    get_regime_state,
    get_tail_risk,
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
    if route == "GET /api/finance/prism":
        return _response(
            200,
            {
                "regime": get_regime_state(),
                "regularities": get_confirmed_regularities(),
                "tails": {
                    "NASDAQCOM": get_tail_risk("NASDAQCOM"),
                    "DGS10": get_tail_risk("DGS10"),
                },
            },
        )
    if route == "GET /api/finance/signals":
        return _response(
            200,
            {
                "factors": get_factor_snapshot(),
                "hotspots": get_news_hotspots(),
                "macro": get_macro_series(),
                "gold": get_macro_series("XAUUSD"),
            },
        )
    return _response(404, {"error": f"Unknown route: {route}"})
