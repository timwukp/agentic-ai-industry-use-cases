"""Trade execution tools for the Trading Assistant."""
import json
import random
import uuid
from datetime import datetime, timedelta
from strands import tool


@tool
def place_order(symbol: str, side: str, quantity: int, order_type: str, limit_price: float) -> str:
    """Place a trading order for a security.

    WARNING: This will submit an order to the market. Ensure all parameters are correct.

    Args:
        symbol: Stock ticker symbol (e.g., 'AAPL').
        side: Order side - 'BUY' or 'SELL'.
        quantity: Number of shares to trade (must be positive integer).
        order_type: Order type - 'MARKET', 'LIMIT', 'STOP', 'STOP_LIMIT'.
        limit_price: Limit price for LIMIT/STOP_LIMIT orders. Use 0 for MARKET orders.

    Returns:
        JSON string with order confirmation including order ID and estimated fill.
    """
    if side.upper() not in ("BUY", "SELL"):
        return json.dumps({"error": "side must be 'BUY' or 'SELL'"})
    if quantity <= 0:
        return json.dumps({"error": "quantity must be a positive integer"})
    if order_type.upper() not in ("MARKET", "LIMIT", "STOP", "STOP_LIMIT"):
        return json.dumps({"error": "Invalid order_type"})

    order_id = f"ORD-{uuid.uuid4().hex[:8].upper()}"
    estimated_price = limit_price if limit_price > 0 else round(random.uniform(100, 500), 2)

    return json.dumps({
        "order_id": order_id,
        "status": "SUBMITTED",
        "symbol": symbol.upper(),
        "side": side.upper(),
        "quantity": quantity,
        "order_type": order_type.upper(),
        "limit_price": limit_price if limit_price > 0 else None,
        "estimated_fill_price": estimated_price,
        "estimated_total": round(estimated_price * quantity, 2),
        "commission": round(quantity * 0.005, 2),
        "submitted_at": datetime.utcnow().isoformat() + "Z",
        "warning": "This is a simulated order. In production, this connects to a real broker API via AgentCore Identity.",
    })


@tool
def cancel_order(order_id: str) -> str:
    """Cancel a pending trading order.

    Args:
        order_id: The order ID returned from place_order (e.g., 'ORD-A1B2C3D4').

    Returns:
        JSON string with cancellation confirmation.
    """
    return json.dumps({
        "order_id": order_id,
        "status": "CANCELLED",
        "cancelled_at": datetime.utcnow().isoformat() + "Z",
        "message": f"Order {order_id} has been successfully cancelled.",
    })


@tool
def get_order_status(order_id: str) -> str:
    """Get the current status of a trading order.

    Args:
        order_id: The order ID to check.

    Returns:
        JSON string with order details and current status.
    """
    statuses = ["SUBMITTED", "PARTIAL_FILL", "FILLED", "CANCELLED"]
    status = random.choice(statuses)
    fill_qty = random.randint(1, 100) if status in ("PARTIAL_FILL", "FILLED") else 0

    return json.dumps({
        "order_id": order_id,
        "status": status,
        "filled_quantity": fill_qty,
        "remaining_quantity": max(0, 100 - fill_qty),
        "avg_fill_price": round(random.uniform(100, 500), 2) if fill_qty > 0 else None,
        "last_updated": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_trade_history(portfolio_id: str, days: int) -> str:
    """Get recent trade history for a portfolio.

    Args:
        portfolio_id: Portfolio identifier.
        days: Number of days of history (max 90).

    Returns:
        JSON string with list of executed trades.
    """
    days = min(days, 90)
    symbols = ["AAPL", "MSFT", "GOOGL", "AMZN", "NVDA", "JPM", "V", "META"]
    trades = []

    for i in range(min(days * 2, 50)):
        trades.append({
            "trade_id": f"TRD-{uuid.uuid4().hex[:8].upper()}",
            "date": (datetime.utcnow() - timedelta(days=random.randint(0, days))).strftime("%Y-%m-%d"),
            "symbol": random.choice(symbols),
            "side": random.choice(["BUY", "SELL"]),
            "quantity": random.randint(10, 200),
            "price": round(random.uniform(100, 500), 2),
            "commission": round(random.uniform(0.5, 5.0), 2),
            "status": "FILLED",
        })

    trades.sort(key=lambda x: x["date"], reverse=True)

    return json.dumps({
        "portfolio_id": portfolio_id,
        "period_days": days,
        "total_trades": len(trades),
        "trades": trades[:20],
        "summary": {
            "total_buy_value": round(sum(t["price"] * t["quantity"] for t in trades if t["side"] == "BUY"), 2),
            "total_sell_value": round(sum(t["price"] * t["quantity"] for t in trades if t["side"] == "SELL"), 2),
            "total_commissions": round(sum(t["commission"] for t in trades), 2),
        },
    })
