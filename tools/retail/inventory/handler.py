"""Gateway target: inventory — stock levels, summaries, transfers, stockout report.

SKU economics and category structure come from the shared toolkit.retail_basis so
the network summary, the ABC breakdown and the stockout report cannot disagree
about how many SKUs the network carries or how many of them are out of stock.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import (
    CATALOG,
    abc_breakdown,
    category_rows,
    network_in_stock_pct,
    sku_basis,
    tool_ok,
    tool_error,
)
from toolkit.dispatch import dispatch

#: Days of cover the reorder point is set to hold.
REORDER_COVER_DAYS = 14
SAFETY_STOCK_DAYS = 7


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def check_inventory(sku: str) -> dict:
    today = _today()
    # Name, category, class and velocity come from the shared SKU basis, so this
    # route and the stockout report describe the same product. Drawn here, a SKU
    # came back as "Product 001 / Electronics" in one route and "Organic Coffee /
    # Grocery" in another.
    basis = sku_basis(sku)
    r = _rng("check_inventory", basis.sku, today.strftime("%Y-%m-%d"))

    # Stock is held as days of cover on the SKU's own velocity, not an absolute
    # count: 5,000 units is a year of a C-class item and a fortnight of an
    # A-class one, and days_of_supply below was drawn from the same free range.
    days_cover = round(r.uniform(4, 70), 1)
    total_on_hand = max(0, round(basis.avg_daily_units * days_cover))
    reserved = round(total_on_hand * r.uniform(0, 0.25))
    reorder_point = basis.avg_daily_units * REORDER_COVER_DAYS

    warehouses = ["DC-East", "DC-West", "DC-Central"]
    stores = [f"Store-{n}" for n in sorted(r.sample(range(100, 200), 3))]
    # Locations must partition the on-hand quantity — halving the remainder at
    # each stop left a third of the stock at no location at all.
    weights = [r.uniform(0.5, 3.0) for _ in warehouses + stores]
    location_breakdown, placed = {}, 0
    for i, loc in enumerate(warehouses + stores):
        qty = (
            total_on_hand - placed
            if i == len(weights) - 1
            else round(total_on_hand * weights[i] / sum(weights))
        )
        qty = max(0, min(qty, total_on_hand - placed))
        location_breakdown[loc] = qty
        placed += qty

    return tool_ok(
        {
            "sku": basis.sku,
            "product_name": basis.name,
            "category": basis.category,
            "inventory": {
                "total_on_hand": total_on_hand,
                "reserved": reserved,
                "available_to_sell": total_on_hand - reserved,
                "in_transit": round(basis.avg_daily_units * r.uniform(0, 5)),
                "on_order": round(basis.avg_daily_units * r.uniform(0, 20)),
            },
            "by_location": location_breakdown,
            "metrics": {
                "avg_daily_sales": basis.avg_daily_units,
                "days_of_supply": days_cover,
                "reorder_point": reorder_point,
                "safety_stock": basis.avg_daily_units * SAFETY_STOCK_DAYS,
                "needs_reorder": total_on_hand < reorder_point,
            },
            "unit_economics": {
                "unit_price": basis.unit_price,
                "unit_cost": basis.unit_cost,
                "gross_margin_pct": basis.gross_margin_pct,
                "daily_revenue": basis.daily_revenue,
            },
            "abc_class": basis.abc_class,
        },
        simulated=True,
    )


def get_inventory_summary(category: str = "all") -> dict:
    day = _today().strftime("%Y-%m-%d")
    rows = category_rows(day, category)
    cat_data = [
        {
            "category": c.category,
            "total_skus": c.total_skus,
            "in_stock_pct": c.in_stock_pct,
            # Every figure below is derived from the row above it: stockouts are
            # the SKU count times the out-of-stock rate, turnover is a year over
            # the days of supply, excess follows the days of supply. Drawn
            # independently, a category reported 90.0% in stock beside 31
            # stockouts on 1,295 SKUs, and 10.2 turns beside 45 days of supply.
            "stockout_skus": c.stockout_skus,
            "overstock_skus": c.overstock_skus,
            "total_value": c.inventory_value,
            "excess_value": c.excess_value,
            "avg_days_of_supply": c.days_of_supply,
            "inventory_turnover": c.turnover,
        }
        for c in rows
    ]
    total_skus = sum(c["total_skus"] for c in cat_data)
    total_stockouts = sum(c["stockout_skus"] for c in cat_data)
    excess_value = sum(c["excess_value"] for c in cat_data)
    # A-class SKUs are the ones with safety stock policies, so the alert counts
    # the A-class share of the network's actual stockouts rather than a free
    # randint that read "9 A-class SKUs" beside a 6-A-class stockout report.
    abc = abc_breakdown(rows)
    a_share = abc["A"]["sku_count"] / total_skus if total_skus else 0
    a_class_stockouts = max(1, round(total_stockouts * a_share * 0.5))

    return tool_ok(
        {
            "filter": category,
            "summary": cat_data,
            "overall": {
                "total_skus": total_skus,
                "total_inventory_value": round(
                    sum(c["total_value"] for c in cat_data), 2
                ),
                # SKU-weighted, so it equals 1 - total_stockouts / total_skus.
                # A plain mean of the category percentages did not.
                "avg_in_stock_rate": network_in_stock_pct(rows),
                "total_stockouts": total_stockouts,
                "total_overstock": sum(c["overstock_skus"] for c in cat_data),
                "total_excess_value": round(excess_value, 2),
            },
            "alerts": [
                {
                    "type": "STOCKOUT_RISK",
                    "severity": "HIGH",
                    "message": (f"{a_class_stockouts} A-class SKUs below safety stock"),
                },
                {
                    "type": "OVERSTOCK",
                    "severity": "MEDIUM",
                    "message": (
                        f"${round(excess_value / 1000):,}K excess inventory "
                        f"across {sum(c['overstock_skus'] for c in cat_data):,} SKUs"
                    ),
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
    """The catalog SKUs that are out of stock today, with revenue at risk.

    These are the named SKUs an operator can act on — a subset of the network's
    total_stockouts, which counts the whole (unlisted) long tail. The response
    says so explicitly: the card used to print this report's row count as
    "Active Stockouts: 11" directly above a category table whose stockout column
    summed to 178.
    """
    today = _today()
    day = today.strftime("%Y-%m-%d")
    r = _rng("stockout_report", day)

    # Draw from the shared catalog, so a row's SKU, name, category and ABC class
    # are the same ones check_inventory reports for that product.
    listed = [sku_basis(sku) for sku, *_ in CATALOG]
    out_of_stock = r.sample(listed, k=r.randint(4, 8))

    stockouts = []
    for basis in out_of_stock:
        days_out = r.randint(1, 14)
        # Lost revenue is this SKU's own daily revenue — the price and velocity
        # check_inventory quotes — not a free draw over (50, 2000) that put a
        # $6 jar of almond butter at $1,900 a day.
        daily_loss = basis.daily_revenue
        # An A-class item out for a week has been escalated; a C-class one may
        # genuinely not be ordered yet. Drawing status freely produced
        # "NOT_ORDERED" A-class items nine days out beside a recommendation to
        # expedite exactly those.
        if basis.abc_class == "A" or days_out > 7:
            reorder_status = "ON_ORDER"
        elif days_out > 3:
            reorder_status = "PENDING"
        else:
            reorder_status = "NOT_ORDERED"
        stockouts.append(
            {
                "sku": basis.sku,
                "product_name": basis.name,
                "category": basis.category,
                "abc_class": basis.abc_class,
                "days_out_of_stock": days_out,
                "estimated_daily_revenue_loss": daily_loss,
                "estimated_total_loss": round(daily_loss * days_out, 2),
                "reorder_status": reorder_status,
                # Only an ON_ORDER item has a confirmed delivery date; drawing
                # the two apart produced "NOT_ORDERED with an ETA next Tuesday".
                "eta": (
                    (today + timedelta(days=r.randint(2, 14))).strftime("%Y-%m-%d")
                    if reorder_status == "ON_ORDER"
                    else None
                ),
            }
        )
    stockouts.sort(key=lambda s: s["estimated_total_loss"], reverse=True)

    network_stockouts = sum(c.stockout_skus for c in category_rows(day))

    return tool_ok(
        {
            "total_stockouts": len(stockouts),
            "network_stockouts": network_stockouts,
            "scope": (
                f"{len(stockouts)} tracked catalog SKUs out of stock, of "
                f"{network_stockouts:,} network-wide"
            ),
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
