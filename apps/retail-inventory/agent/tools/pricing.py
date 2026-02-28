from strands import tool
import json, random
from datetime import datetime


@tool
def get_pricing_analysis(sku: str) -> str:
    """Get pricing analysis for a product including competitor pricing and margin data.

    Args:
        sku: Product SKU to analyze.

    Returns:
        JSON with current price, competitor prices, margins, and price elasticity.
    """
    our_price = round(random.uniform(10, 500), 2)
    cost = round(our_price * random.uniform(0.4, 0.7), 2)

    competitors = []
    for name in ["Amazon", "Walmart", "Target", "Best Buy", "Costco"]:
        comp_price = round(our_price * random.uniform(0.85, 1.15), 2)
        competitors.append({"name": name, "price": comp_price, "diff_pct": round((comp_price / our_price - 1) * 100, 1)})

    competitors.sort(key=lambda c: c["price"])

    return json.dumps({
        "sku": sku,
        "current_price": our_price,
        "cost": cost,
        "margin": round((our_price - cost) / our_price * 100, 1),
        "margin_dollars": round(our_price - cost, 2),
        "competitor_prices": competitors,
        "market_position": "BELOW_AVERAGE" if our_price < sum(c["price"] for c in competitors) / len(competitors) else "ABOVE_AVERAGE",
        "price_elasticity": round(random.uniform(-2.5, -0.5), 2),
        "recommended_price": round(our_price * random.uniform(0.95, 1.08), 2),
        "price_history": {
            "30_day_avg": round(our_price * random.uniform(0.95, 1.05), 2),
            "90_day_avg": round(our_price * random.uniform(0.90, 1.10), 2),
            "price_changes_30d": random.randint(0, 3),
        },
    })


@tool
def optimize_pricing(sku: str, objective: str) -> str:
    """Calculate optimal pricing based on demand elasticity and business objective.

    Args:
        sku: Product SKU.
        objective: Pricing objective - 'maximize_revenue', 'maximize_margin', 'competitive_match', 'clearance'.

    Returns:
        JSON with optimal price recommendation and projected impact.
    """
    current_price = round(random.uniform(20, 300), 2)
    cost = round(current_price * random.uniform(0.4, 0.65), 2)
    daily_units = random.randint(10, 200)

    price_adjustments = {
        "maximize_revenue": random.uniform(0.95, 1.10),
        "maximize_margin": random.uniform(1.05, 1.20),
        "competitive_match": random.uniform(0.90, 1.00),
        "clearance": random.uniform(0.50, 0.75),
    }

    adj = price_adjustments.get(objective, 1.0)
    optimal_price = round(current_price * adj, 2)
    new_units = round(daily_units * (1 + (current_price - optimal_price) / current_price * 1.5))

    return json.dumps({
        "sku": sku,
        "objective": objective,
        "current": {
            "price": current_price,
            "daily_units": daily_units,
            "daily_revenue": round(current_price * daily_units, 2),
            "daily_margin": round((current_price - cost) * daily_units, 2),
            "margin_pct": round((current_price - cost) / current_price * 100, 1),
        },
        "recommended": {
            "price": optimal_price,
            "price_change_pct": round((optimal_price / current_price - 1) * 100, 1),
            "projected_daily_units": new_units,
            "projected_daily_revenue": round(optimal_price * new_units, 2),
            "projected_daily_margin": round((optimal_price - cost) * new_units, 2),
            "projected_margin_pct": round((optimal_price - cost) / optimal_price * 100, 1),
        },
        "impact": {
            "revenue_change_pct": round((optimal_price * new_units / (current_price * daily_units) - 1) * 100, 1),
            "margin_change_pct": round(((optimal_price - cost) * new_units / ((current_price - cost) * daily_units) - 1) * 100, 1),
        },
    })


@tool
def get_competitive_intelligence() -> str:
    """Get competitive pricing intelligence across all monitored products.

    Returns:
        JSON with price position analysis, competitor trends, and opportunities.
    """
    return json.dumps({
        "monitoring_summary": {
            "total_skus_monitored": random.randint(500, 2000),
            "competitors_tracked": 8,
            "last_scan": datetime.utcnow().isoformat() + "Z",
        },
        "price_position": {
            "below_market_pct": round(random.uniform(20, 40), 1),
            "at_market_pct": round(random.uniform(30, 50), 1),
            "above_market_pct": round(random.uniform(15, 30), 1),
        },
        "opportunities": [
            {"type": "PRICE_INCREASE", "skus": random.randint(20, 80), "potential_margin_gain": round(random.uniform(10000, 100000), 2)},
            {"type": "COMPETITIVE_MATCH", "skus": random.randint(10, 40), "potential_revenue_gain": round(random.uniform(20000, 150000), 2)},
            {"type": "CLEARANCE_NEEDED", "skus": random.randint(5, 20), "inventory_value_at_risk": round(random.uniform(5000, 50000), 2)},
        ],
        "competitor_moves": [
            {"competitor": "Amazon", "action": "Price drops on 45 electronics SKUs", "avg_drop_pct": round(random.uniform(3, 12), 1)},
            {"competitor": "Walmart", "action": "New loyalty pricing on grocery", "impact": "MEDIUM"},
            {"competitor": "Target", "action": "Seasonal markdown started early", "impact": "LOW"},
        ],
    })


@tool
def get_margin_report(category: str) -> str:
    """Get margin analysis report by product category.

    Args:
        category: Product category or 'all'.

    Returns:
        JSON with margin breakdown, trends, and optimization opportunities.
    """
    categories = ["Electronics", "Apparel", "Grocery", "Home & Garden", "Sports"] if category.lower() == "all" else [category.title()]

    report = []
    for cat in categories:
        base_margin = random.uniform(15, 55)
        report.append({
            "category": cat,
            "gross_margin_pct": round(base_margin, 1),
            "net_margin_pct": round(base_margin - random.uniform(5, 15), 1),
            "revenue": round(random.uniform(200000, 2000000), 2),
            "cogs": round(random.uniform(100000, 1500000), 2),
            "margin_trend": round(random.uniform(-3, 5), 1),
            "top_margin_sku": f"SKU-{random.randint(100,999)}",
            "lowest_margin_sku": f"SKU-{random.randint(100,999)}",
            "skus_below_target": random.randint(5, 30),
        })

    return json.dumps({
        "category_filter": category,
        "report": report,
        "overall": {
            "blended_gross_margin": round(sum(r["gross_margin_pct"] for r in report) / len(report), 1),
            "total_revenue": round(sum(r["revenue"] for r in report), 2),
            "margin_improvement_opportunity": round(random.uniform(50000, 300000), 2),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
