"""Gateway target: market_data — quotes, overview, history, sectors.

Data is a deterministic simulation (toolkit.MarketSim); payloads are labeled
"source": "simulated" so the agent can disclose provenance.
"""

from toolkit import MarketSim, tool_ok
from toolkit.dispatch import dispatch


def get_stock_quote(symbol: str) -> dict:
    return tool_ok(MarketSim().quote(symbol), simulated=True)


def get_market_overview() -> dict:
    return tool_ok(MarketSim().market_overview(), simulated=True)


def get_historical_prices(symbol: str, days: int = 30) -> dict:
    sim = MarketSim()
    return tool_ok(
        {
            "symbol": symbol.upper(),
            "period_days": min(int(days), 252),
            "data": sim.historical(symbol, int(days)),
        },
        simulated=True,
    )


def get_sector_performance() -> dict:
    return tool_ok({"sectors": MarketSim().sector_performance()}, simulated=True)


TOOLS = {
    "get_stock_quote": get_stock_quote,
    "get_market_overview": get_market_overview,
    "get_historical_prices": get_historical_prices,
    "get_sector_performance": get_sector_performance,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
