"""Portfolio management tools for the Trading Assistant."""
import json
import random
from datetime import datetime
from strands import tool


@tool
def get_portfolio_positions(portfolio_id: str) -> str:
    """Get all current positions in a portfolio.

    Args:
        portfolio_id: Portfolio identifier (e.g., 'default', 'retirement', 'growth').

    Returns:
        JSON string with all positions including symbol, quantity, cost basis, current value, and P&L.
    """
    # Simulated portfolio data
    positions = [
        {"symbol": "AAPL", "quantity": 100, "avg_cost": 185.50, "current_price": 245.50},
        {"symbol": "MSFT", "quantity": 50, "avg_cost": 380.20, "current_price": 478.30},
        {"symbol": "GOOGL", "quantity": 75, "avg_cost": 145.00, "current_price": 192.80},
        {"symbol": "AMZN", "quantity": 40, "avg_cost": 178.50, "current_price": 228.15},
        {"symbol": "NVDA", "quantity": 30, "avg_cost": 490.00, "current_price": 875.40},
        {"symbol": "JPM", "quantity": 80, "avg_cost": 195.00, "current_price": 242.70},
    ]

    total_cost = 0
    total_value = 0

    for pos in positions:
        pos["cost_basis"] = round(pos["quantity"] * pos["avg_cost"], 2)
        pos["market_value"] = round(pos["quantity"] * pos["current_price"], 2)
        pos["unrealized_pnl"] = round(pos["market_value"] - pos["cost_basis"], 2)
        pos["unrealized_pnl_pct"] = round((pos["current_price"] / pos["avg_cost"] - 1) * 100, 2)
        total_cost += pos["cost_basis"]
        total_value += pos["market_value"]

    return json.dumps({
        "portfolio_id": portfolio_id,
        "positions": positions,
        "summary": {
            "total_cost_basis": round(total_cost, 2),
            "total_market_value": round(total_value, 2),
            "total_unrealized_pnl": round(total_value - total_cost, 2),
            "total_return_pct": round((total_value / total_cost - 1) * 100, 2),
            "num_positions": len(positions),
        },
        "as_of": datetime.utcnow().isoformat() + "Z",
    })


@tool
def calculate_pnl(portfolio_id: str, period: str) -> str:
    """Calculate profit and loss for a portfolio over a time period.

    Args:
        portfolio_id: Portfolio identifier.
        period: Time period. Options: 'today', 'week', 'month', 'quarter', 'ytd', 'year'.

    Returns:
        JSON string with realized P&L, unrealized P&L, and total return.
    """
    period_multipliers = {
        "today": 0.002, "week": 0.01, "month": 0.04,
        "quarter": 0.08, "ytd": 0.12, "year": 0.15,
    }

    mult = period_multipliers.get(period, 0.01)
    portfolio_value = 250000

    realized = round(portfolio_value * mult * random.uniform(0.3, 0.7), 2)
    unrealized = round(portfolio_value * mult * random.uniform(0.3, 0.7), 2)
    dividends = round(portfolio_value * 0.005 * (mult / 0.15), 2)
    fees = round(abs(realized) * 0.001, 2)

    return json.dumps({
        "portfolio_id": portfolio_id,
        "period": period,
        "pnl": {
            "realized_pnl": realized,
            "unrealized_pnl": unrealized,
            "dividend_income": dividends,
            "fees_commissions": -fees,
            "net_pnl": round(realized + unrealized + dividends - fees, 2),
        },
        "performance": {
            "total_return_pct": round((realized + unrealized) / portfolio_value * 100, 2),
            "benchmark_return_pct": round(mult * 100 * random.uniform(0.5, 1.5), 2),
            "alpha_pct": round(random.uniform(-2, 3), 2),
        },
    })


@tool
def get_portfolio_allocation(portfolio_id: str) -> str:
    """Get portfolio allocation breakdown by sector, asset class, and geography.

    Args:
        portfolio_id: Portfolio identifier.

    Returns:
        JSON with allocation breakdowns and diversification metrics.
    """
    return json.dumps({
        "portfolio_id": portfolio_id,
        "by_sector": {
            "Technology": 42.5,
            "Healthcare": 15.3,
            "Financials": 12.8,
            "Consumer Discretionary": 10.2,
            "Energy": 8.5,
            "Industrials": 6.2,
            "Other": 4.5,
        },
        "by_asset_class": {
            "US Large Cap": 65.0,
            "US Mid Cap": 15.0,
            "International Developed": 10.0,
            "Emerging Markets": 5.0,
            "Fixed Income": 3.0,
            "Cash": 2.0,
        },
        "by_geography": {
            "United States": 80.0,
            "Europe": 10.0,
            "Asia Pacific": 7.0,
            "Other": 3.0,
        },
        "diversification_score": round(random.uniform(60, 85), 1),
        "recommendation": "Portfolio is tech-heavy. Consider adding more exposure to defensive sectors (Healthcare, Utilities) and international markets for better diversification.",
    })


@tool
def suggest_rebalancing(portfolio_id: str, target_allocation: str) -> str:
    """Suggest trades to rebalance portfolio toward a target allocation.

    Args:
        portfolio_id: Portfolio identifier.
        target_allocation: JSON string of target allocation, e.g., '{"Technology": 30, "Healthcare": 20, ...}'

    Returns:
        JSON with suggested trades to achieve target allocation.
    """
    try:
        targets = json.loads(target_allocation)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON for target_allocation"})

    current = {
        "Technology": 42.5, "Healthcare": 15.3, "Financials": 12.8,
        "Consumer Discretionary": 10.2, "Energy": 8.5, "Industrials": 6.2, "Other": 4.5,
    }

    portfolio_value = 250000
    trades = []

    for sector, target_pct in targets.items():
        current_pct = current.get(sector, 0)
        diff_pct = target_pct - current_pct
        trade_value = portfolio_value * diff_pct / 100

        if abs(diff_pct) > 1:
            trades.append({
                "sector": sector,
                "action": "BUY" if diff_pct > 0 else "SELL",
                "current_pct": current_pct,
                "target_pct": target_pct,
                "change_pct": round(diff_pct, 2),
                "estimated_trade_value": round(abs(trade_value), 2),
            })

    return json.dumps({
        "portfolio_id": portfolio_id,
        "current_allocation": current,
        "target_allocation": targets,
        "suggested_trades": sorted(trades, key=lambda x: abs(x["estimated_trade_value"]), reverse=True),
        "estimated_total_turnover": round(sum(t["estimated_trade_value"] for t in trades), 2),
        "estimated_tax_impact": "Review with tax advisor before executing large rebalancing trades.",
    })
