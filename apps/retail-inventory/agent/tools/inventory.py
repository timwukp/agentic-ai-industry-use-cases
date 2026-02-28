from strands import tool
import json, random, uuid
from datetime import datetime, timedelta


@tool
def check_inventory(sku: str) -> str:
    """Check real-time inventory levels for a product across all locations.

    Retrieves current stock, reserved units, available-to-sell, and location breakdown.

    Args:
        sku: Product SKU identifier (e.g., 'SKU-ELEC-001', 'SKU-APPRL-042').

    Returns:
        JSON with inventory levels by location, reorder status, and days of supply.
    """
    warehouses = ["DC-East", "DC-West", "DC-Central"]
    stores = [f"Store-{i}" for i in random.sample(range(100, 200), 5)]

    total_on_hand = random.randint(50, 5000)
    reserved = random.randint(0, total_on_hand // 4)
    in_transit = random.randint(0, 500)
    avg_daily_sales = random.randint(5, 100)

    location_breakdown = {}
    remaining = total_on_hand
    for loc in warehouses + stores[:3]:
        qty = random.randint(0, remaining // 2) if remaining > 0 else 0
        remaining -= qty
        location_breakdown[loc] = qty

    days_of_supply = round(total_on_hand / avg_daily_sales, 1) if avg_daily_sales > 0 else 999
    reorder_point = avg_daily_sales * 14  # 2 weeks safety stock

    return json.dumps({
        "sku": sku,
        "product_name": f"Product {sku[-3:]}",
        "category": random.choice(["Electronics", "Apparel", "Home & Garden", "Grocery", "Sports"]),
        "inventory": {
            "total_on_hand": total_on_hand,
            "reserved": reserved,
            "available_to_sell": total_on_hand - reserved,
            "in_transit": in_transit,
            "on_order": random.randint(0, 1000),
        },
        "by_location": location_breakdown,
        "metrics": {
            "avg_daily_sales": avg_daily_sales,
            "days_of_supply": days_of_supply,
            "reorder_point": reorder_point,
            "safety_stock": avg_daily_sales * 7,
            "needs_reorder": total_on_hand < reorder_point,
        },
        "abc_class": random.choice(["A", "A", "B", "B", "B", "C", "C", "C", "C"]),
        "last_updated": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_inventory_summary(category: str) -> str:
    """Get inventory summary metrics for a product category or all categories.

    Args:
        category: Product category ('all', 'electronics', 'apparel', 'grocery', 'home', 'sports').

    Returns:
        JSON with inventory health metrics, stockout risks, and overstock alerts.
    """
    categories = ["Electronics", "Apparel", "Grocery", "Home & Garden", "Sports"] if category.lower() == "all" else [category.title()]

    cat_data = []
    for cat in categories:
        total_skus = random.randint(200, 2000)
        cat_data.append({
            "category": cat,
            "total_skus": total_skus,
            "in_stock_pct": round(random.uniform(88, 99), 1),
            "stockout_skus": random.randint(1, int(total_skus * 0.05)),
            "overstock_skus": random.randint(5, int(total_skus * 0.1)),
            "total_value": round(random.uniform(500000, 5000000), 2),
            "avg_days_of_supply": round(random.uniform(15, 45), 1),
            "inventory_turnover": round(random.uniform(4, 12), 1),
        })

    return json.dumps({
        "filter": category,
        "summary": cat_data,
        "overall": {
            "total_skus": sum(c["total_skus"] for c in cat_data),
            "total_inventory_value": round(sum(c["total_value"] for c in cat_data), 2),
            "avg_in_stock_rate": round(sum(c["in_stock_pct"] for c in cat_data) / len(cat_data), 1),
            "total_stockouts": sum(c["stockout_skus"] for c in cat_data),
            "total_overstock": sum(c["overstock_skus"] for c in cat_data),
        },
        "alerts": [
            {"type": "STOCKOUT_RISK", "message": f"{random.randint(3,10)} A-class SKUs below safety stock", "severity": "HIGH"},
            {"type": "OVERSTOCK", "message": f"${random.randint(50,200)}K excess inventory in seasonal items", "severity": "MEDIUM"},
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def transfer_stock(sku: str, from_location: str, to_location: str, quantity: int) -> str:
    """Initiate an inter-location stock transfer.

    Args:
        sku: Product SKU to transfer.
        from_location: Source warehouse/store ID.
        to_location: Destination warehouse/store ID.
        quantity: Number of units to transfer.

    Returns:
        JSON with transfer confirmation and estimated delivery.
    """
    if quantity <= 0:
        return json.dumps({"error": "Quantity must be positive"})

    transfer_id = f"TRF-{uuid.uuid4().hex[:8].upper()}"

    return json.dumps({
        "transfer_id": transfer_id,
        "status": "INITIATED",
        "sku": sku,
        "from_location": from_location,
        "to_location": to_location,
        "quantity": quantity,
        "estimated_delivery": (datetime.utcnow() + timedelta(days=random.randint(1, 5))).strftime("%Y-%m-%d"),
        "shipping_method": random.choice(["Ground", "Express", "Same-Day"]),
        "created_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_stockout_report() -> str:
    """Get current stockout and low-stock report across all locations.

    Returns:
        JSON with stockout items, low-stock alerts, and revenue impact estimates.
    """
    stockouts = []
    for _ in range(random.randint(5, 15)):
        daily_revenue = round(random.uniform(50, 2000), 2)
        days_out = random.randint(1, 14)
        stockouts.append({
            "sku": f"SKU-{random.choice(['ELEC','APRL','GROC','HOME','SPRT'])}-{random.randint(100, 999)}",
            "product_name": random.choice(["Wireless Earbuds", "Running Shoes", "Organic Coffee", "Smart Thermostat", "Yoga Mat", "USB-C Cable", "Winter Jacket"]),
            "category": random.choice(["Electronics", "Apparel", "Grocery", "Home", "Sports"]),
            "abc_class": random.choice(["A", "A", "B"]),
            "days_out_of_stock": days_out,
            "estimated_daily_revenue_loss": daily_revenue,
            "estimated_total_loss": round(daily_revenue * days_out, 2),
            "reorder_status": random.choice(["ON_ORDER", "PENDING", "NOT_ORDERED"]),
            "eta": (datetime.utcnow() + timedelta(days=random.randint(2, 14))).strftime("%Y-%m-%d") if random.random() > 0.3 else None,
        })

    stockouts.sort(key=lambda s: s["estimated_total_loss"], reverse=True)

    return json.dumps({
        "total_stockouts": len(stockouts),
        "total_revenue_impact": round(sum(s["estimated_total_loss"] for s in stockouts), 2),
        "a_class_stockouts": sum(1 for s in stockouts if s["abc_class"] == "A"),
        "items": stockouts,
        "recommendation": "Prioritize A-class items for expedited reorder. Consider safety stock adjustment.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
