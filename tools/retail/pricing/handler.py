"""Gateway target: pricing — pricing analysis, optimization, competitive intel, margins.

Prices, costs and category economics come from the shared toolkit.retail_basis, so
the price this module analyses is the price check_inventory quotes for the same
SKU, and the margin report reconciles with the inventory it is drawn from. Drawn
locally, one SKU was $214.50 at a 51% margin here and $38.20 at 34% there.
"""

import hashlib
import random
from datetime import datetime, timezone

from toolkit import CATALOG, apportion, category_rows, sku_basis, tool_ok, tool_error
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


def _split_100(weights: list) -> list:
    """Scale `weights` to percentages summing to exactly 100.0, to one decimal.

    Apportioning tenths of a percent and dividing back is exact; normalising and
    rounding each share on its own left the three market positions summing to
    99.9 or 100.1 on the same card.
    """
    total = sum(weights)
    tenths = apportion(1000, [w / total * 100 for w in weights])
    return [t / 10 for t in tenths]


def _elasticity(sku: str) -> float:
    """Price elasticity of demand for one SKU, keyed on the SKU alone.

    A product's demand curve is a property of the product. optimize_pricing used
    a hard-coded 1.5 while the analysis route reported the SKU's elasticity as
    -0.7, so the projected unit response was twice what the elasticity on the
    adjacent card predicted.
    """
    return round(_rng("elasticity", sku.strip().upper()).uniform(-2.5, -0.5), 2)


def get_pricing_analysis(sku: str) -> dict:
    # Price, cost and margin are the SKU's own, so this route agrees with
    # check_inventory's unit_economics and with the EOQ auto_reorder computes.
    basis = sku_basis(sku)
    r = _rng("pricing_analysis", basis.sku)
    our_price = basis.unit_price
    cost = basis.unit_cost

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
    below_market = our_price < market_avg

    # A recommendation has to point the way the market position argues. Drawn
    # from a free (0.95, 1.08) band it told an operator sitting 8% BELOW_AVERAGE
    # to cut the price further, and never held the floor at cost.
    target = round((our_price + market_avg) / 2, 2)
    recommended_price = max(round(cost * 1.15, 2), target)

    return tool_ok(
        {
            "sku": basis.sku,
            "product_name": basis.name,
            "category": basis.category,
            "current_price": our_price,
            "cost": cost,
            "margin": basis.gross_margin_pct,
            "margin_dollars": round(our_price - cost, 2),
            "competitor_prices": competitors,
            "market_avg_price": round(market_avg, 2),
            "market_position": "BELOW_AVERAGE" if below_market else "ABOVE_AVERAGE",
            "price_elasticity": _elasticity(basis.sku),
            "recommended_price": recommended_price,
            "recommended_change_pct": round(
                (recommended_price / our_price - 1) * 100, 1
            ),
            "recommended_margin_pct": round(
                (recommended_price - cost) / recommended_price * 100, 1
            ),
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
    # Price, cost and volume are the SKU's own: an optimizer working from a
    # $214 price when every other card shows $38 recommends a move the operator
    # cannot act on.
    basis = sku_basis(sku)
    r = _rng("optimize_pricing", basis.sku, objective)
    current_price = basis.unit_price
    cost = basis.unit_cost
    daily_units = basis.avg_daily_units

    adj = r.uniform(*PRICE_OBJECTIVES[objective])
    # Never price below cost, whatever the objective asks for: a clearance
    # adjustment of 0.50 on a 42%-margin item produced a negative daily margin
    # presented as a recommendation.
    optimal_price = max(round(cost * 1.02, 2), round(current_price * adj, 2))
    # Constant-elasticity demand response at THIS SKU's elasticity, the same
    # figure get_pricing_analysis reports. Hard-coded at 1.5, the projected unit
    # response contradicted the elasticity shown beside it.
    elasticity = _elasticity(basis.sku)
    new_units = max(
        0,
        round(
            daily_units
            * (1 + (optimal_price - current_price) / current_price * elasticity)
        ),
    )

    return tool_ok(
        {
            "sku": basis.sku,
            "product_name": basis.name,
            "objective": objective,
            "price_elasticity": elasticity,
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
    day = now.strftime("%Y-%m-%d")
    r = _rng("competitive_intel", day)
    rows = category_rows(day)
    # Monitoring covers a share of the network the inventory summary reports, not
    # a free randint that claimed 1,840 SKUs monitored on a 5,501-SKU network one
    # day and 512 the next.
    network_skus = sum(c.total_skus for c in rows)
    monitored = round(network_skus * 0.35)

    # The three positions are the whole monitored set, so they sum to 100.0.
    # Drawn independently over (20,40)/(30,50)/(15,30) they summed to 118.4.
    below_pct, at_pct, above_pct = _split_100(
        [r.uniform(20, 40), r.uniform(30, 50), r.uniform(15, 30)]
    )
    # The SKUs in each opportunity are drawn from the position they belong to: a
    # price increase applies to SKUs priced below market, clearance to overstock.
    below_skus = round(monitored * below_pct / 100)
    above_skus = round(monitored * above_pct / 100)
    overstock_skus = sum(c.overstock_skus for c in rows)
    avg_value_per_sku = (
        sum(c.inventory_value for c in rows) / network_skus if network_skus else 0.0
    )

    increase_skus = max(1, round(below_skus * r.uniform(0.05, 0.15)))
    match_skus = max(1, round(above_skus * r.uniform(0.10, 0.25)))
    clearance_skus = max(1, round(overstock_skus * r.uniform(0.05, 0.15)))

    return tool_ok(
        {
            "monitoring_summary": {
                "total_skus_monitored": monitored,
                "network_skus": network_skus,
                "coverage_pct": (
                    round(monitored / network_skus * 100, 1) if network_skus else 0.0
                ),
                "competitors_tracked": len(COMPETITORS),
                "last_scan": day,
            },
            "price_position": {
                "below_market_pct": below_pct,
                "at_market_pct": at_pct,
                "above_market_pct": above_pct,
                "below_market_skus": below_skus,
                "above_market_skus": above_skus,
            },
            "opportunities": [
                {
                    "type": "PRICE_INCREASE",
                    "skus": increase_skus,
                    # The gain scales with the SKUs it applies to, so a
                    # 6-SKU opportunity cannot outvalue a 60-SKU one. Drawn free
                    # over (10000, 100000) it regularly did.
                    "potential_margin_gain": round(
                        increase_skus * avg_value_per_sku * r.uniform(0.04, 0.10), 2
                    ),
                },
                {
                    "type": "COMPETITIVE_MATCH",
                    "skus": match_skus,
                    "potential_revenue_gain": round(
                        match_skus * avg_value_per_sku * r.uniform(0.08, 0.18), 2
                    ),
                },
                {
                    "type": "CLEARANCE_NEEDED",
                    "skus": clearance_skus,
                    "inventory_value_at_risk": round(
                        clearance_skus * avg_value_per_sku, 2
                    ),
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
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rows = category_rows(day, category)
    report = []
    for c in rows:
        r = _rng("margin_report", c.category)
        # Revenue and COGS come from the same category basis the inventory
        # summary reports, so revenue - cogs really is the gross margin printed
        # beside them. Drawn independently over (200000, 2000000) and
        # (100000, 1500000), a category shipped $412K revenue against $1.34M
        # COGS above a "+38.2% gross margin" tile.
        revenue = c.annual_revenue
        cogs = c.annual_cogs
        # Operating cost as a share of revenue, so net margin stays below gross
        # and cannot go negative on a healthy category.
        opex_pct = r.uniform(5, 15)
        # The best and worst margin SKUs in this category are real catalog
        # entries. Minted as SKU-<randint> they matched nothing an operator could
        # click through to, and were redrawn on every call.
        cat_skus = sorted(
            (sku_basis(sku) for sku, _, cat, _ in CATALOG if cat == c.category),
            key=lambda b: b.gross_margin_pct,
        )
        report.append(
            {
                "category": c.category,
                "gross_margin_pct": c.gross_margin_pct,
                "net_margin_pct": round(c.gross_margin_pct - opex_pct, 1),
                "revenue": revenue,
                "cogs": cogs,
                "gross_profit": round(revenue - cogs, 2),
                "margin_trend": round(r.uniform(-3, 5), 1),
                "top_margin_sku": cat_skus[-1].sku if cat_skus else None,
                "top_margin_sku_pct": (
                    cat_skus[-1].gross_margin_pct if cat_skus else None
                ),
                "lowest_margin_sku": cat_skus[0].sku if cat_skus else None,
                "lowest_margin_sku_pct": (
                    cat_skus[0].gross_margin_pct if cat_skus else None
                ),
                # SKUs below the margin target, as a share of the SKUs this
                # category actually carries — a flat randint(5, 30) read the same
                # on a 400-SKU category as on an 1,800-SKU one.
                "skus_below_target": max(
                    1, round(c.total_skus * r.uniform(0.02, 0.08))
                ),
            }
        )
    total_revenue = round(sum(x["revenue"] for x in report), 2)
    total_cogs = round(sum(x["cogs"] for x in report), 2)
    r = _rng("margin_overall", category.lower())

    return tool_ok(
        {
            "category_filter": category,
            "report": report,
            "overall": {
                # Revenue-weighted, so it equals gross profit over revenue. The
                # plain mean of the category percentages did not, and a small
                # high-margin category dragged the blend above every line item.
                "blended_gross_margin": (
                    round((total_revenue - total_cogs) / total_revenue * 100, 1)
                    if total_revenue
                    else 0.0
                ),
                "total_revenue": total_revenue,
                "total_cogs": total_cogs,
                "total_gross_profit": round(total_revenue - total_cogs, 2),
                # Recovering a slice of the gap to the best-performing category's
                # margin — a number tied to the report rather than a free draw
                # that offered $280K of upside on $412K of revenue.
                "margin_improvement_opportunity": round(
                    total_revenue
                    * (
                        max(x["gross_margin_pct"] for x in report)
                        - min(x["gross_margin_pct"] for x in report)
                    )
                    / 100
                    * r.uniform(0.02, 0.06),
                    2,
                ),
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
