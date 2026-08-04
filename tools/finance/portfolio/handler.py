"""Gateway target: portfolio — positions, P&L, allocation, rebalancing.

Positions live in DynamoDB (PORTFOLIO_TABLE); current prices come from the
deterministic market simulator so values are consistent with market_data tools.
"""
from datetime import datetime, timezone

from boto3.dynamodb.conditions import Key

from toolkit import MarketSim, tool_ok, tool_error
from toolkit.dispatch import dispatch
from toolkit.dynamo import table, from_decimal
from toolkit.responses import parse_json_arg

SECTOR_MAP = {
    "AAPL": "Technology", "MSFT": "Technology", "GOOGL": "Communication Services",
    "AMZN": "Consumer Discretionary", "NVDA": "Technology", "META": "Communication Services",
    "TSLA": "Consumer Discretionary", "JPM": "Financials", "V": "Financials",
    "JNJ": "Healthcare", "WMT": "Consumer Staples", "PG": "Consumer Staples",
    "MA": "Financials", "HD": "Consumer Discretionary", "BAC": "Financials", "XOM": "Energy",
}


def _load_positions(portfolio_id: str) -> list[dict]:
    resp = table("PORTFOLIO_TABLE").query(
        KeyConditionExpression=Key("portfolioId").eq(portfolio_id)
        & Key("sk").begins_with("POSITION#")
    )
    return [from_decimal(item) for item in resp.get("Items", [])]


def _enrich(positions: list[dict], sim: MarketSim) -> tuple[list[dict], float, float]:
    total_cost = total_value = 0.0
    out = []
    for pos in positions:
        price = sim.close_price(pos["symbol"])
        qty = pos["quantity"]
        cost_basis = round(qty * pos["avgCost"], 2)
        market_value = round(qty * price, 2)
        out.append({
            "symbol": pos["symbol"], "quantity": qty, "avg_cost": pos["avgCost"],
            "current_price": price, "cost_basis": cost_basis, "market_value": market_value,
            "unrealized_pnl": round(market_value - cost_basis, 2),
            "unrealized_pnl_pct": round((price / pos["avgCost"] - 1) * 100, 2),
        })
        total_cost += cost_basis
        total_value += market_value
    return out, round(total_cost, 2), round(total_value, 2)


def get_portfolio_positions(portfolio_id: str = "default") -> dict:
    positions = _load_positions(portfolio_id)
    if not positions:
        return tool_error(f"Portfolio not found: {portfolio_id}")
    enriched, total_cost, total_value = _enrich(positions, MarketSim())
    return tool_ok({
        "portfolio_id": portfolio_id,
        "positions": enriched,
        "summary": {
            "total_cost_basis": total_cost,
            "total_market_value": total_value,
            "total_unrealized_pnl": round(total_value - total_cost, 2),
            "total_return_pct": round((total_value / total_cost - 1) * 100, 2) if total_cost else 0,
            "num_positions": len(enriched),
        },
        "as_of": datetime.now(timezone.utc).isoformat(),
    }, simulated=True)


def calculate_pnl(portfolio_id: str = "default", period: str = "month") -> dict:
    positions = _load_positions(portfolio_id)
    if not positions:
        return tool_error(f"Portfolio not found: {portfolio_id}")
    period_days = {"today": 1, "week": 7, "month": 30, "quarter": 91, "ytd": 210, "year": 365}
    days = period_days.get(period)
    if days is None:
        return tool_error(f"Unknown period: {period}", valid=sorted(period_days))
    sim = MarketSim()
    _, total_cost, value_now = _enrich(positions, sim)
    # value at period start, from the same deterministic walk
    from datetime import timedelta
    then = sim.today - timedelta(days=days)
    value_then = round(sum(p["quantity"] * sim.close_price(p["symbol"], then) for p in positions), 2)
    unrealized = round(value_now - value_then, 2)
    dividends = round(value_now * 0.005 * days / 365, 2)
    return tool_ok({
        "portfolio_id": portfolio_id,
        "period": period,
        "pnl": {
            "unrealized_pnl": unrealized,
            "dividend_income": dividends,
            "net_pnl": round(unrealized + dividends, 2),
        },
        "performance": {
            "period_return_pct": round((value_now / value_then - 1) * 100, 2) if value_then else 0,
            "value_start": value_then,
            "value_end": value_now,
        },
    }, simulated=True)


def get_portfolio_allocation(portfolio_id: str = "default") -> dict:
    positions = _load_positions(portfolio_id)
    if not positions:
        return tool_error(f"Portfolio not found: {portfolio_id}")
    enriched, _, total_value = _enrich(positions, MarketSim())
    by_sector: dict[str, float] = {}
    for pos in enriched:
        sector = SECTOR_MAP.get(pos["symbol"], "Other")
        by_sector[sector] = by_sector.get(sector, 0) + pos["market_value"]
    by_sector_pct = {s: round(v / total_value * 100, 1) for s, v in
                     sorted(by_sector.items(), key=lambda kv: -kv[1])}
    herfindahl = sum((p["market_value"] / total_value) ** 2 for p in enriched)
    return tool_ok({
        "portfolio_id": portfolio_id,
        "by_sector": by_sector_pct,
        "concentration": {
            "top_position_weight_pct": round(max(p["market_value"] for p in enriched) / total_value * 100, 2),
            "herfindahl_index": round(herfindahl, 4),
        },
        "diversification_note": "Computed from live demo positions; sector map covers major tickers.",
    }, simulated=True)


def suggest_rebalancing(portfolio_id: str = "default", target_allocation: str = "{}") -> dict:
    targets, err = parse_json_arg(target_allocation, "target_allocation")
    if err:
        return tool_error(err)
    alloc = get_portfolio_allocation(portfolio_id)
    if "error" in alloc:
        return alloc
    current = alloc["by_sector"]
    positions = _load_positions(portfolio_id)
    _, _, total_value = _enrich(positions, MarketSim())
    trades = []
    for sector, target_pct in targets.items():
        diff = float(target_pct) - current.get(sector, 0.0)
        if abs(diff) > 1:
            trades.append({
                "sector": sector,
                "action": "BUY" if diff > 0 else "SELL",
                "current_pct": current.get(sector, 0.0),
                "target_pct": float(target_pct),
                "change_pct": round(diff, 2),
                "estimated_trade_value": round(abs(total_value * diff / 100), 2),
            })
    trades.sort(key=lambda t: -t["estimated_trade_value"])
    return tool_ok({
        "portfolio_id": portfolio_id,
        "current_allocation": current,
        "target_allocation": targets,
        "suggested_trades": trades,
        "estimated_total_turnover": round(sum(t["estimated_trade_value"] for t in trades), 2),
        "note": "Review tax impact before executing large rebalancing trades.",
    }, simulated=True)


TOOLS = {
    "get_portfolio_positions": get_portfolio_positions,
    "calculate_pnl": calculate_pnl,
    "get_portfolio_allocation": get_portfolio_allocation,
    "suggest_rebalancing": suggest_rebalancing,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
