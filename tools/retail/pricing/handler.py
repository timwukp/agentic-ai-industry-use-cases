"""Gateway target: pricing — pricing analysis, optimization, competitive intel, margins.

Pricing data is a deterministic simulation seeded from the function inputs.
"""

import hashlib
import random
from datetime import datetime, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

PRICE_OBJECTIVES = {
    "maximize_revenue": (0.95, 1.10),
    "maximize_margin": (1.05, 1.20),
    "competitive_match": (0.90, 1.00),
    "clearance": (0.50, 0.75),
}
COMPETITORS = ["Amazon", "Walmart", "Target", "Best Buy", "Costco"]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def get_pricing_analysis(sku: str) -> dict:
    r = _rng("pricing_analysis", sku.upper())
    our_price = round(r.uniform(10, 500), 2)
    cost = round(our_price * r.uniform(0.4, 0.7), 2)

    competitors = []
    for name in COMPETITORS:
        comp_price = round(our_price * r.uniform(0.85, 1.15), 2)
        competitors.append(
            {
                "name": name,
                "price": comp_price,
                "diff_pct": round((comp_price / our_price - 1) * 100, 1),
            }
        )
    competitors.sort(key=lambda c: c["price"])
    market_avg = sum(c["price"] for c in competitors) / len(competitors)

    return tool_ok(
        {
            "sku": sku,
            "current_price": our_price,
            "cost": cost,
            "margin": round((our_price - cost) / our_price * 100, 1),
            "margin_dollars": round(our_price - cost, 2),
            "competitor_prices": competitors,
            "market_position": (
                "BELOW_AVERAGE" if our_price < market_avg else "ABOVE_AVERAGE"
            ),
            "price_elasticity": round(r.uniform(-2.5, -0.5), 2),
            "recommended_price": round(our_price * r.uniform(0.95, 1.08), 2),
            "price_history": {
                "30_day_avg": round(our_price * r.uniform(0.95, 1.05), 2),
                "90_day_avg": round(our_price * r.uniform(0.90, 1.10), 2),
                "price_changes_30d": r.randint(0, 3),
            },
        },
        simulated=True,
    )


def optimize_pricing(sku: str, objective: str) -> dict:
    objective = objective.lower()
    if objective not in PRICE_OBJECTIVES:
        return tool_error(
            f"Invalid objective: {objective}", valid=sorted(PRICE_OBJECTIVES)
        )
    r = _rng("optimize_pricing", sku.upper(), objective)
    current_price = round(r.uniform(20, 300), 2)
    cost = round(current_price * r.uniform(0.4, 0.65), 2)
    daily_units = r.randint(10, 200)

    adj = r.uniform(*PRICE_OBJECTIVES[objective])
    optimal_price = round(current_price * adj, 2)
    # simple constant-elasticity demand response (elasticity 1.5)
    new_units = max(
        0,
        round(
            daily_units * (1 + (current_price - optimal_price) / current_price * 1.5)
        ),
    )

    return tool_ok(
        {
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
                "projected_margin_pct": round(
                    (optimal_price - cost) / optimal_price * 100, 1
                ),
            },
            "impact": {
                "revenue_change_pct": round(
                    (optimal_price * new_units / (current_price * daily_units) - 1)
                    * 100,
                    1,
                ),
                "margin_change_pct": round(
                    (
                        (optimal_price - cost)
                        * new_units
                        / ((current_price - cost) * daily_units)
                        - 1
                    )
                    * 100,
                    1,
                ),
            },
        },
        simulated=True,
    )


def get_competitive_intelligence() -> dict:
    now = datetime.now(timezone.utc)
    r = _rng("competitive_intel", now.strftime("%Y-%m-%d"))
    return tool_ok(
        {
            "monitoring_summary": {
                "total_skus_monitored": r.randint(500, 2000),
                "competitors_tracked": len(COMPETITORS),
                "last_scan": now.strftime("%Y-%m-%d"),
            },
            "price_position": {
                "below_market_pct": round(r.uniform(20, 40), 1),
                "at_market_pct": round(r.uniform(30, 50), 1),
                "above_market_pct": round(r.uniform(15, 30), 1),
            },
            "opportunities": [
                {
                    "type": "PRICE_INCREASE",
                    "skus": r.randint(20, 80),
                    "potential_margin_gain": round(r.uniform(10000, 100000), 2),
                },
                {
                    "type": "COMPETITIVE_MATCH",
                    "skus": r.randint(10, 40),
                    "potential_revenue_gain": round(r.uniform(20000, 150000), 2),
                },
                {
                    "type": "CLEARANCE_NEEDED",
                    "skus": r.randint(5, 20),
                    "inventory_value_at_risk": round(r.uniform(5000, 50000), 2),
                },
            ],
            "competitor_moves": [
                {
                    "competitor": "Amazon",
                    "action": "Price drops on 45 electronics SKUs",
                    "avg_drop_pct": round(r.uniform(3, 12), 1),
                },
                {
                    "competitor": "Walmart",
                    "action": "New loyalty pricing on grocery",
                    "impact": "MEDIUM",
                },
                {
                    "competitor": "Target",
                    "action": "Seasonal markdown started early",
                    "impact": "LOW",
                },
            ],
        },
        simulated=True,
    )


def get_margin_report(category: str = "all") -> dict:
    cats = (
        ["Electronics", "Apparel", "Grocery", "Home & Garden", "Sports"]
        if category.lower() == "all"
        else [category.title()]
    )
    report = []
    for cat in cats:
        r = _rng("margin_report", cat)
        base_margin = r.uniform(15, 55)
        report.append(
            {
                "category": cat,
                "gross_margin_pct": round(base_margin, 1),
                "net_margin_pct": round(base_margin - r.uniform(5, 15), 1),
                "revenue": round(r.uniform(200000, 2000000), 2),
                "cogs": round(r.uniform(100000, 1500000), 2),
                "margin_trend": round(r.uniform(-3, 5), 1),
                "top_margin_sku": f"SKU-{r.randint(100, 999)}",
                "lowest_margin_sku": f"SKU-{r.randint(100, 999)}",
                "skus_below_target": r.randint(5, 30),
            }
        )
    r = _rng("margin_overall", category.lower())

    return tool_ok(
        {
            "category_filter": category,
            "report": report,
            "overall": {
                "blended_gross_margin": round(
                    sum(x["gross_margin_pct"] for x in report) / len(report), 1
                ),
                "total_revenue": round(sum(x["revenue"] for x in report), 2),
                "margin_improvement_opportunity": round(r.uniform(50000, 300000), 2),
            },
        },
        simulated=True,
    )


TOOLS = {
    "get_pricing_analysis": get_pricing_analysis,
    "optimize_pricing": optimize_pricing,
    "get_competitive_intelligence": get_competitive_intelligence,
    "get_margin_report": get_margin_report,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
