"""Gateway target: inventory — stock levels, summaries, transfers, stockout report.

Inventory data is a deterministic simulation seeded from the function inputs
(stable within a calendar day for date-relative fields).
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

CATEGORIES = ["Electronics", "Apparel", "Grocery", "Home & Garden", "Sports"]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def check_inventory(sku: str) -> dict:
    r = _rng("check_inventory", sku.upper())
    warehouses = ["DC-East", "DC-West", "DC-Central"]
    stores = [f"Store-{n}" for n in r.sample(range(100, 200), 3)]

    total_on_hand = r.randint(50, 5000)
    reserved = r.randint(0, total_on_hand // 4)
    avg_daily_sales = r.randint(5, 100)

    location_breakdown = {}
    remaining = total_on_hand
    for loc in warehouses + stores:
        qty = r.randint(0, remaining // 2) if remaining > 0 else 0
        remaining -= qty
        location_breakdown[loc] = qty

    reorder_point = avg_daily_sales * 14  # 2 weeks safety stock

    return tool_ok(
        {
            "sku": sku,
            "product_name": f"Product {sku[-3:]}",
            "category": r.choice(CATEGORIES),
            "inventory": {
                "total_on_hand": total_on_hand,
                "reserved": reserved,
                "available_to_sell": total_on_hand - reserved,
                "in_transit": r.randint(0, 500),
                "on_order": r.randint(0, 1000),
            },
            "by_location": location_breakdown,
            "metrics": {
                "avg_daily_sales": avg_daily_sales,
                "days_of_supply": round(total_on_hand / avg_daily_sales, 1),
                "reorder_point": reorder_point,
                "safety_stock": avg_daily_sales * 7,
                "needs_reorder": total_on_hand < reorder_point,
            },
            "abc_class": r.choice(["A", "A", "B", "B", "B", "C", "C", "C", "C"]),
        },
        simulated=True,
    )


def get_inventory_summary(category: str = "all") -> dict:
    cats = CATEGORIES if category.lower() == "all" else [category.title()]
    cat_data = []
    for cat in cats:
        r = _rng("inventory_summary", cat)
        total_skus = r.randint(200, 2000)
        cat_data.append(
            {
                "category": cat,
                "total_skus": total_skus,
                "in_stock_pct": round(r.uniform(88, 99), 1),
                "stockout_skus": r.randint(1, max(1, int(total_skus * 0.05))),
                "overstock_skus": r.randint(5, max(6, int(total_skus * 0.1))),
                "total_value": round(r.uniform(500000, 5000000), 2),
                "avg_days_of_supply": round(r.uniform(15, 45), 1),
                "inventory_turnover": round(r.uniform(4, 12), 1),
            }
        )
    r = _rng("inventory_alerts", category.lower())

    return tool_ok(
        {
            "filter": category,
            "summary": cat_data,
            "overall": {
                "total_skus": sum(c["total_skus"] for c in cat_data),
                "total_inventory_value": round(
                    sum(c["total_value"] for c in cat_data), 2
                ),
                "avg_in_stock_rate": round(
                    sum(c["in_stock_pct"] for c in cat_data) / len(cat_data), 1
                ),
                "total_stockouts": sum(c["stockout_skus"] for c in cat_data),
                "total_overstock": sum(c["overstock_skus"] for c in cat_data),
            },
            "alerts": [
                {
                    "type": "STOCKOUT_RISK",
                    "severity": "HIGH",
                    "message": f"{r.randint(3, 10)} A-class SKUs below safety stock",
                },
                {
                    "type": "OVERSTOCK",
                    "severity": "MEDIUM",
                    "message": f"${r.randint(50, 200)}K excess inventory in seasonal items",
                },
            ],
        },
        simulated=True,
    )


def transfer_stock(
    sku: str, from_location: str, to_location: str, quantity: int
) -> dict:
    quantity = int(quantity)
    if quantity <= 0:
        return tool_error("quantity must be a positive integer")
    if from_location == to_location:
        return tool_error("from_location and to_location must differ")
    today = _today()
    r = _rng(
        "transfer_stock",
        sku,
        from_location,
        to_location,
        quantity,
        today.strftime("%Y-%m-%d"),
    )

    return tool_ok(
        {
            "transfer_id": f"TRF-{r.randrange(16 ** 8):08X}",
            "status": "INITIATED",
            "sku": sku,
            "from_location": from_location,
            "to_location": to_location,
            "quantity": quantity,
            "estimated_delivery": (today + timedelta(days=r.randint(1, 5))).strftime(
                "%Y-%m-%d"
            ),
            "shipping_method": r.choice(["Ground", "Express", "Same-Day"]),
            "note": "Demo inventory system: transfer execution is simulated.",
        },
        simulated=True,
    )


def get_stockout_report() -> dict:
    today = _today()
    r = _rng("stockout_report", today.strftime("%Y-%m-%d"))
    products = [
        "Wireless Earbuds",
        "Running Shoes",
        "Organic Coffee",
        "Smart Thermostat",
        "Yoga Mat",
        "USB-C Cable",
        "Winter Jacket",
    ]
    stockouts = []
    for _ in range(r.randint(5, 15)):
        daily_revenue = round(r.uniform(50, 2000), 2)
        days_out = r.randint(1, 14)
        on_order = r.random() > 0.3
        stockouts.append(
            {
                "sku": f"SKU-{r.choice(['ELEC', 'APRL', 'GROC', 'HOME', 'SPRT'])}-{r.randint(100, 999)}",
                "product_name": r.choice(products),
                "category": r.choice(
                    ["Electronics", "Apparel", "Grocery", "Home", "Sports"]
                ),
                "abc_class": r.choice(["A", "A", "B"]),
                "days_out_of_stock": days_out,
                "estimated_daily_revenue_loss": daily_revenue,
                "estimated_total_loss": round(daily_revenue * days_out, 2),
                "reorder_status": r.choice(["ON_ORDER", "PENDING", "NOT_ORDERED"]),
                "eta": (
                    (today + timedelta(days=r.randint(2, 14))).strftime("%Y-%m-%d")
                    if on_order
                    else None
                ),
            }
        )
    stockouts.sort(key=lambda s: s["estimated_total_loss"], reverse=True)

    return tool_ok(
        {
            "total_stockouts": len(stockouts),
            "total_revenue_impact": round(
                sum(s["estimated_total_loss"] for s in stockouts), 2
            ),
            "a_class_stockouts": sum(1 for s in stockouts if s["abc_class"] == "A"),
            "items": stockouts,
            "recommendation": (
                "Prioritize A-class items for expedited reorder. "
                "Consider safety stock adjustment."
            ),
        },
        simulated=True,
    )


TOOLS = {
    "check_inventory": check_inventory,
    "get_inventory_summary": get_inventory_summary,
    "transfer_stock": transfer_stock,
    "get_stockout_report": get_stockout_report,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
