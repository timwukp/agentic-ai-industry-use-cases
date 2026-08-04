"""Gateway target: trading — order placement, cancellation, status, history.

Orders are REAL writes to the demo order book (ORDERS_TABLE) and position
mutations (PORTFOLIO_TABLE). Fill prices come from the deterministic simulator.
"""
import uuid
from datetime import datetime, timedelta, timezone

from boto3.dynamodb.conditions import Key

from toolkit import MarketSim, tool_ok, tool_error
from toolkit.dispatch import dispatch
from toolkit.dynamo import table, to_decimal, from_decimal

VALID_SIDES = {"BUY", "SELL"}
VALID_TYPES = {"MARKET", "LIMIT", "STOP", "STOP_LIMIT"}
COMMISSION_PER_SHARE = 0.005


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _apply_fill(portfolio_id: str, symbol: str, side: str, quantity: int, price: float):
    """Mutate the position for a filled order (weighted-average cost on buys)."""
    tbl = table("PORTFOLIO_TABLE")
    key = {"portfolioId": portfolio_id, "sk": f"POSITION#{symbol}"}
    item = tbl.get_item(Key=key).get("Item")
    if side == "BUY":
        if item:
            item = from_decimal(item)
            new_qty = item["quantity"] + quantity
            new_cost = (item["quantity"] * item["avgCost"] + quantity * price) / new_qty
            tbl.put_item(Item=to_decimal({**key, "symbol": symbol, "quantity": new_qty,
                                          "avgCost": round(new_cost, 4)}))
        else:
            tbl.put_item(Item=to_decimal({**key, "symbol": symbol, "quantity": quantity,
                                          "avgCost": price}))
        return None
    if not item:
        return f"No position in {symbol} to sell"
    item = from_decimal(item)
    if item["quantity"] < quantity:
        return f"Insufficient shares: have {item['quantity']}, tried to sell {quantity}"
    remaining = item["quantity"] - quantity
    if remaining == 0:
        tbl.delete_item(Key=key)
    else:
        tbl.put_item(Item=to_decimal({**key, "symbol": symbol, "quantity": remaining,
                                      "avgCost": item["avgCost"]}))
    return None


def place_order(symbol: str, side: str, quantity: int, order_type: str = "MARKET",
                limit_price: float = 0, portfolio_id: str = "default") -> dict:
    symbol, side, order_type = symbol.upper(), side.upper(), order_type.upper()
    quantity = int(quantity)
    if side not in VALID_SIDES:
        return tool_error("side must be 'BUY' or 'SELL'")
    if quantity <= 0:
        return tool_error("quantity must be a positive integer")
    if order_type not in VALID_TYPES:
        return tool_error(f"Invalid order_type: {order_type}", valid=sorted(VALID_TYPES))
    if order_type != "MARKET" and float(limit_price) <= 0:
        return tool_error(f"{order_type} orders require a positive limit_price")

    market_price = MarketSim().close_price(symbol)
    # demo semantics: MARKET fills now at market; LIMIT fills if marketable, else stays OPEN
    fill_price = None
    status = "OPEN"
    if order_type == "MARKET":
        fill_price, status = market_price, "FILLED"
    elif order_type == "LIMIT":
        marketable = (side == "BUY" and float(limit_price) >= market_price) or \
                     (side == "SELL" and float(limit_price) <= market_price)
        if marketable:
            fill_price, status = market_price, "FILLED"

    if status == "FILLED":
        err = _apply_fill(portfolio_id, symbol, side, quantity, fill_price)
        if err:
            return tool_error(err)

    order_id = f"ORD-{uuid.uuid4().hex[:8].upper()}"
    order = {
        "orderId": order_id, "portfolioId": portfolio_id, "symbol": symbol, "side": side,
        "quantity": quantity, "orderType": order_type,
        "limitPrice": float(limit_price) if float(limit_price) > 0 else None,
        "status": status, "fillPrice": fill_price,
        "commission": round(quantity * COMMISSION_PER_SHARE, 2),
        "createdAt": _now(),
    }
    table("ORDERS_TABLE").put_item(Item=to_decimal({k: v for k, v in order.items() if v is not None}))
    return tool_ok({
        "order_id": order_id, "status": status, "symbol": symbol, "side": side,
        "quantity": quantity, "order_type": order_type,
        "limit_price": order["limitPrice"], "fill_price": fill_price,
        "estimated_total": round((fill_price or float(limit_price)) * quantity, 2),
        "commission": order["commission"], "submitted_at": order["createdAt"],
        "note": "Demo order book: fill prices are simulated; position state is real.",
    }, simulated=True)


def cancel_order(order_id: str) -> dict:
    tbl = table("ORDERS_TABLE")
    item = tbl.get_item(Key={"orderId": order_id}).get("Item")
    if not item:
        return tool_error(f"Order not found: {order_id}")
    item = from_decimal(item)
    if item["status"] != "OPEN":
        return tool_error(f"Order {order_id} is {item['status']}; only OPEN orders can be cancelled")
    tbl.update_item(
        Key={"orderId": order_id},
        UpdateExpression="SET #s = :c, cancelledAt = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":c": "CANCELLED", ":t": _now()},
    )
    return tool_ok({"order_id": order_id, "status": "CANCELLED", "cancelled_at": _now()})


def get_order_status(order_id: str) -> dict:
    item = table("ORDERS_TABLE").get_item(Key={"orderId": order_id}).get("Item")
    if not item:
        return tool_error(f"Order not found: {order_id}")
    item = from_decimal(item)
    return tool_ok({
        "order_id": item["orderId"], "status": item["status"], "symbol": item["symbol"],
        "side": item["side"], "quantity": item["quantity"],
        "order_type": item["orderType"], "fill_price": item.get("fillPrice"),
        "created_at": item["createdAt"],
    })


def get_trade_history(portfolio_id: str = "default", days: int = 30) -> dict:
    days = min(int(days), 90)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    resp = table("ORDERS_TABLE").query(
        IndexName="byPortfolio",
        KeyConditionExpression=Key("portfolioId").eq(portfolio_id)
        & Key("createdAt").gte(cutoff),
        ScanIndexForward=False,
    )
    orders = [from_decimal(i) for i in resp.get("Items", [])]
    filled = [o for o in orders if o["status"] == "FILLED"]
    return tool_ok({
        "portfolio_id": portfolio_id,
        "period_days": days,
        "total_orders": len(orders),
        "orders": orders[:50],
        "summary": {
            "total_buy_value": round(sum(o["fillPrice"] * o["quantity"]
                                         for o in filled if o["side"] == "BUY"), 2),
            "total_sell_value": round(sum(o["fillPrice"] * o["quantity"]
                                          for o in filled if o["side"] == "SELL"), 2),
            "total_commissions": round(sum(o.get("commission", 0) for o in orders), 2),
        },
    })


TOOLS = {
    "place_order": place_order,
    "cancel_order": cancel_order,
    "get_order_status": get_order_status,
    "get_trade_history": get_trade_history,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
