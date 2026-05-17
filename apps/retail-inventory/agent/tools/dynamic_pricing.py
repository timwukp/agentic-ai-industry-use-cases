"""Dynamic pricing tools for the Retail Inventory Assistant.

Provides competitor price scanning, optimal price calculation, price impact
simulation, and pricing strategy generation for real-time price optimization.
"""

import json
import random
from datetime import datetime

from strands import tool


@tool
def scan_competitor_prices(sku: str) -> str:
    """Scan competitor pricing for a product.

    Collects and analyzes real-time pricing data from competitor websites,
    marketplaces, and price comparison engines for the specified product.

    Args:
        sku: The SKU or product identifier to scan competitor prices for.

    Returns:
        JSON string with competitor pricing data, price positioning, and market trends.
    """
    our_price = round(random.uniform(15, 300), 2)

    competitors = [
        {"name": "Amazon", "marketplace": True},
        {"name": "Walmart", "marketplace": False},
        {"name": "Target", "marketplace": False},
        {"name": "Best Buy", "marketplace": False},
        {"name": "eBay", "marketplace": True},
        {"name": "Costco", "marketplace": False},
    ]

    scanned_competitors = random.sample(competitors, random.randint(3, 5))
    competitor_prices = []

    for comp in scanned_competitors:
        price = round(our_price * random.uniform(0.8, 1.25), 2)
        competitor_prices.append({
            "competitor": comp["name"],
            "price": price,
            "in_stock": random.choice([True, True, True, False]),
            "shipping_free": random.choice([True, False]),
            "last_price_change_days_ago": random.randint(0, 30),
            "price_vs_ours_pct": round((price / our_price - 1) * 100, 1),
        })

    all_prices = [c["price"] for c in competitor_prices]
    market_low = min(all_prices)
    market_high = max(all_prices)
    market_avg = round(sum(all_prices) / len(all_prices), 2)

    return json.dumps({
        "sku": sku,
        "our_price": our_price,
        "competitor_prices": competitor_prices,
        "market_summary": {
            "lowest_price": market_low,
            "highest_price": market_high,
            "average_price": market_avg,
            "our_position": "BELOW_AVERAGE" if our_price < market_avg else "ABOVE_AVERAGE",
            "price_rank": sum(1 for p in all_prices if p < our_price) + 1,
        },
        "price_trend": {
            "direction": random.choice(["INCREASING", "DECREASING", "STABLE"]),
            "avg_change_7d_pct": round(random.uniform(-5, 5), 1),
        },
        "scanned_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def calculate_optimal_price(sku: str, objective: str) -> str:
    """Calculate optimal price considering inventory, demand, and competition.

    Uses demand elasticity models, competitor pricing, inventory levels, and
    the specified business objective to determine the price that maximizes
    the desired outcome.

    Args:
        sku: The SKU to calculate optimal pricing for.
        objective: The pricing objective (e.g., 'maximize_revenue', 'maximize_margin', 'clear_inventory', 'match_market').

    Returns:
        JSON string with optimal price recommendation, supporting analysis, and projected impact.
    """
    current_price = round(random.uniform(20, 300), 2)
    cost = round(current_price * random.uniform(0.3, 0.6), 2)
    current_margin_pct = round((current_price - cost) / current_price * 100, 1)

    elasticity = round(random.uniform(-2.5, -0.5), 2)
    current_daily_units = random.randint(10, 200)
    inventory_days = random.randint(5, 90)

    objective_adjustments = {
        "maximize_revenue": random.uniform(-0.05, 0.1),
        "maximize_margin": random.uniform(0.05, 0.2),
        "clear_inventory": random.uniform(-0.3, -0.1),
        "match_market": random.uniform(-0.1, 0.05),
    }

    adjustment = objective_adjustments.get(objective, 0)
    optimal_price = round(current_price * (1 + adjustment), 2)
    new_margin_pct = round((optimal_price - cost) / optimal_price * 100, 1)

    price_change_pct = round((optimal_price / current_price - 1) * 100, 1)
    demand_change_pct = round(price_change_pct * elasticity, 1)
    projected_daily_units = max(1, int(current_daily_units * (1 + demand_change_pct / 100)))

    current_daily_revenue = round(current_price * current_daily_units, 2)
    projected_daily_revenue = round(optimal_price * projected_daily_units, 2)

    return json.dumps({
        "sku": sku,
        "objective": objective,
        "current_state": {
            "price": current_price,
            "cost": cost,
            "margin_pct": current_margin_pct,
            "daily_units": current_daily_units,
            "daily_revenue": current_daily_revenue,
            "inventory_days_supply": inventory_days,
        },
        "optimal_price": optimal_price,
        "price_change_pct": price_change_pct,
        "projected_impact": {
            "new_margin_pct": new_margin_pct,
            "demand_change_pct": demand_change_pct,
            "projected_daily_units": projected_daily_units,
            "projected_daily_revenue": projected_daily_revenue,
            "revenue_change_pct": round((projected_daily_revenue / current_daily_revenue - 1) * 100, 1),
        },
        "model_inputs": {
            "price_elasticity": elasticity,
            "competitor_avg_price": round(current_price * random.uniform(0.9, 1.1), 2),
            "demand_trend": random.choice(["GROWING", "STABLE", "DECLINING"]),
        },
        "confidence": round(random.uniform(0.65, 0.95), 2),
        "calculated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def simulate_price_impact(sku: str, new_price: float) -> str:
    """Simulate impact of a price change on demand and revenue.

    Models the expected change in unit sales, revenue, margin, and
    competitive positioning if the price is changed to the specified level.

    Args:
        sku: The SKU to simulate the price change for.
        new_price: The proposed new price point to simulate.

    Returns:
        JSON string with simulated impact on demand, revenue, margin, and market position.
    """
    current_price = round(random.uniform(new_price * 0.7, new_price * 1.4), 2)
    cost = round(current_price * random.uniform(0.3, 0.55), 2)

    price_change_pct = round((new_price / current_price - 1) * 100, 1)
    elasticity = round(random.uniform(-2.0, -0.5), 2)
    demand_change_pct = round(price_change_pct * elasticity, 1)

    current_daily_units = random.randint(20, 300)
    simulated_daily_units = max(1, int(current_daily_units * (1 + demand_change_pct / 100)))

    current_revenue = round(current_price * current_daily_units, 2)
    simulated_revenue = round(new_price * simulated_daily_units, 2)

    current_margin = round((current_price - cost) * current_daily_units, 2)
    simulated_margin = round((new_price - cost) * simulated_daily_units, 2)

    simulation_days = [7, 14, 30]
    projections = {}
    for days in simulation_days:
        projections[f"day_{days}"] = {
            "cumulative_revenue": round(simulated_revenue * days, 2),
            "cumulative_units": simulated_daily_units * days,
            "cumulative_margin": round(simulated_margin * days, 2),
        }

    return json.dumps({
        "sku": sku,
        "simulation_params": {
            "current_price": current_price,
            "new_price": new_price,
            "price_change_pct": price_change_pct,
            "elasticity_used": elasticity,
        },
        "daily_impact": {
            "current_units": current_daily_units,
            "simulated_units": simulated_daily_units,
            "demand_change_pct": demand_change_pct,
            "current_revenue": current_revenue,
            "simulated_revenue": simulated_revenue,
            "revenue_change_pct": round((simulated_revenue / current_revenue - 1) * 100, 1),
            "current_margin": current_margin,
            "simulated_margin": simulated_margin,
            "margin_change_pct": round((simulated_margin / current_margin - 1) * 100, 1) if current_margin else 0,
        },
        "projections": projections,
        "risks": [
            r for r in [
                "Competitor price war risk" if price_change_pct < -10 else None,
                "Margin erosion below threshold" if (new_price - cost) / new_price < 0.2 else None,
                "Demand may not recover if price raised too aggressively" if price_change_pct > 15 else None,
                "Brand perception impact at low price point" if new_price < cost * 1.5 else None,
            ] if r
        ],
        "simulated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_pricing_strategy(category: str) -> str:
    """Generate category-level pricing strategy recommendations.

    Analyzes the entire product category to develop a cohesive pricing
    strategy considering price architecture, competitive dynamics, and
    inventory position.

    Args:
        category: The product category to generate strategy for (e.g., 'Electronics', 'Apparel', 'Home').

    Returns:
        JSON string with pricing strategy recommendations, tier definitions, and implementation plan.
    """
    total_skus = random.randint(50, 500)

    price_tiers = [
        {
            "tier": "Value/Entry",
            "price_range": f"${random.randint(10, 30)}-${random.randint(31, 60)}",
            "sku_count": random.randint(10, int(total_skus * 0.3)),
            "strategy": "Competitive pricing to drive traffic",
            "margin_target_pct": round(random.uniform(15, 25), 1),
        },
        {
            "tier": "Mid-Range",
            "price_range": f"${random.randint(61, 100)}-${random.randint(101, 200)}",
            "sku_count": random.randint(20, int(total_skus * 0.4)),
            "strategy": "Balanced margin and volume",
            "margin_target_pct": round(random.uniform(25, 40), 1),
        },
        {
            "tier": "Premium",
            "price_range": f"${random.randint(201, 300)}-${random.randint(301, 500)}",
            "sku_count": random.randint(5, int(total_skus * 0.2)),
            "strategy": "Margin optimization with brand value positioning",
            "margin_target_pct": round(random.uniform(40, 60), 1),
        },
    ]

    actions = random.sample([
        {
            "action": "Price reduction on slow-moving inventory",
            "affected_skus": random.randint(5, 30),
            "expected_impact": f"+{round(random.uniform(10, 40), 1)}% unit velocity",
        },
        {
            "action": "Bundle pricing for complementary products",
            "affected_skus": random.randint(10, 40),
            "expected_impact": f"+{round(random.uniform(5, 15), 1)}% average order value",
        },
        {
            "action": "Dynamic markdown schedule for seasonal items",
            "affected_skus": random.randint(8, 25),
            "expected_impact": f"{round(random.uniform(10, 30), 1)}% faster inventory clearance",
        },
        {
            "action": "Price increase on inelastic high-demand items",
            "affected_skus": random.randint(5, 15),
            "expected_impact": f"+{round(random.uniform(5, 20), 1)}% gross margin",
        },
        {
            "action": "Price matching automation for key competitive items",
            "affected_skus": random.randint(15, 50),
            "expected_impact": f"-{round(random.uniform(5, 15), 1)}% lost sales to competitors",
        },
    ], random.randint(3, 4))

    return json.dumps({
        "category": category,
        "total_skus_analyzed": total_skus,
        "overall_strategy": random.choice([
            "COMPETITIVE_LEADERSHIP",
            "VALUE_OPTIMIZATION",
            "PREMIUM_POSITIONING",
            "MARKET_PENETRATION",
        ]),
        "price_tiers": price_tiers,
        "recommended_actions": actions,
        "kpis_to_track": [
            "Gross margin percentage",
            "Price index vs. competitors",
            "Unit velocity by tier",
            "Revenue per available SKU",
            "Markdown percentage",
        ],
        "review_cadence": "Weekly for competitive items, monthly for full category",
        "implementation_timeline_weeks": random.randint(2, 6),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })
