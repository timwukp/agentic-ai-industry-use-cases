"""Gateway target: demand_forecast — forecasting, trends, EOQ reorder, ABC analysis.

Forecast data is a deterministic simulation seeded from the function inputs
(stable within a calendar day). EOQ math is exact.
"""

import hashlib
import math
import random
from datetime import datetime, timedelta, timezone

from toolkit import abc_breakdown, category_rows, sku_basis, tool_ok, tool_error
from toolkit.dispatch import dispatch


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def forecast_demand(sku: str, days_ahead: int = 30) -> dict:
    days_ahead = min(max(1, int(days_ahead)), 90)
    today = _today()
    basis = sku_basis(sku)
    r = _rng("forecast_demand", basis.sku, days_ahead, today.strftime("%Y-%m-%d"))
    # The SKU's own velocity, so the forecast agrees with the days-of-supply and
    # reorder point check_inventory reports for it. Drawn over (10, 200) here, a
    # C-class item forecast at 180 units/day sat beside a 6 units/day average.
    base_demand = float(basis.avg_daily_units)

    forecasts = []
    for i in range(days_ahead):
        date = today + timedelta(days=i + 1)
        dow_factor = (
            1.3 if date.weekday() in (4, 5) else 0.8 if date.weekday() == 0 else 1.0
        )
        seasonal = 1 + 0.2 * math.sin(2 * math.pi * date.timetuple().tm_yday / 365)
        trend = 1 + 0.001 * i
        noise = r.gauss(1, 0.1)
        forecast = max(0, base_demand * dow_factor * seasonal * trend * noise)
        forecasts.append(
            {
                "date": date.strftime("%Y-%m-%d"),
                "predicted_units": round(forecast),
                "lower_bound": round(forecast * 0.7),
                "upper_bound": round(forecast * 1.4),
                "confidence": 0.85,
            }
        )
    total = sum(f["predicted_units"] for f in forecasts)
    avg_daily = total / days_ahead
    # Only the first 14 points are returned, and the chart plots exactly those —
    # so the peak has to be the peak of what is plotted. Taken over all 30 it
    # named a date past the right edge of its own chart.
    shown = forecasts[:14] if days_ahead > 14 else forecasts
    mape = round(r.uniform(5, 15), 1)

    return tool_ok(
        {
            "sku": basis.sku,
            "product_name": basis.name,
            "forecast_period_days": days_ahead,
            "model": "Gradient boosting + seasonal decomposition (demo simulation)",
            "total_predicted_demand": total,
            "avg_daily_demand": round(avg_daily, 1),
            "peak_day": max(shown, key=lambda f: f["predicted_units"])["date"],
            "forecasts": shown,
            "accuracy_metrics": {
                "mape": mape,
                # RMSE is an absolute unit error, so it must scale with the
                # SKU's volume: drawn over (3, 20) beside a 6 units/day item it
                # claimed an error three times the quantity being forecast.
                "rmse": round(avg_daily * mape / 100 * r.uniform(0.9, 1.3), 1),
                "forecast_bias": round(r.uniform(-3, 3), 1),
            },
            "factors": {
                "seasonality": "Moderate - weekend spike pattern",
                # The series applies a +0.1%/day trend above; stating a
                # different figure here would contradict the plotted line.
                "trend": "Slightly upward (+0.1%/day)",
                "promotional_impact": "None currently active",
            },
        },
        simulated=True,
    )


def get_demand_trends(category: str, period: str = "month") -> dict:
    period = period.lower()
    periods_map = {"week": 7, "month": 30, "quarter": 90, "year": 365}
    if period not in periods_map:
        return tool_error(f"Invalid period: {period}", valid=sorted(periods_map))
    days = periods_map[period]
    today = _today()
    r = _rng("demand_trends", category.lower(), period, today.strftime("%Y-%W"))

    # A week-over-week trend has to be a walk, not 12 independent draws: the
    # headline growth percentages below are computed FROM this series, so an
    # independent randint per week produced "units +6.6%" over a line that
    # visibly fell. Units follow a drift plus noise; revenue follows units at a
    # slowly-moving average order value, so the two lines agree.
    num_weeks = min(days // 7, 52)
    weekly_data = []
    units = r.randint(1500, 4000)
    aov = r.uniform(35, 120)
    # Units and AOV drift independently — that is what makes the revenue line
    # worth plotting next to units. With AOV nearly fixed, revenue is a scaled
    # copy of units and the two lines render as one.
    units_drift = r.uniform(-0.03, 0.04)
    # signed magnitude, never ~0: a flat AOV makes revenue an exact scaled copy
    # of units, and the two plotted lines land on top of each other
    aov_drift = r.choice([-1, 1]) * r.uniform(0.004, 0.018)
    for i in range(num_weeks):
        week_start = today - timedelta(weeks=num_weeks - i)
        units = max(400, round(units * (1 + units_drift) * r.uniform(0.92, 1.08)))
        aov = round(max(20.0, aov * (1 + aov_drift) * r.uniform(0.97, 1.03)), 2)
        weekly_data.append(
            {
                "week": week_start.strftime("%Y-W%V"),
                "units_sold": units,
                "revenue": round(units * aov, 2),
                "avg_order_value": aov,
            }
        )

    window = weekly_data[-12:]

    def _growth(key: str) -> float:
        """First-to-last change across the returned window, in percent."""
        if len(window) < 2 or not window[0][key]:
            return 0.0
        return round((window[-1][key] / window[0][key] - 1) * 100, 1)

    return tool_ok(
        {
            "category": category,
            "period": period,
            "trends": {
                "units_growth_pct": _growth("units_sold"),
                "revenue_growth_pct": _growth("revenue"),
                "aov_change_pct": _growth("avg_order_value"),
            },
            "weekly_data": window,
            "top_growing_skus": [
                {
                    "sku": f"SKU-{r.randint(100, 999)}",
                    "growth_pct": round(r.uniform(10, 50), 1),
                }
                for _ in range(5)
            ],
            "declining_skus": [
                {
                    "sku": f"SKU-{r.randint(100, 999)}",
                    "decline_pct": round(r.uniform(-30, -5), 1),
                }
                for _ in range(3)
            ],
            "seasonality_index": round(r.uniform(0.8, 1.3), 2),
        },
        simulated=True,
    )


def auto_reorder(sku: str) -> dict:
    today = _today()
    basis = sku_basis(sku)
    r = _rng("auto_reorder", basis.sku)
    # Velocity and unit cost come from the shared basis: an EOQ computed from a
    # different cost and demand than check_inventory reports for the same SKU is
    # an order quantity the agent cannot justify from the numbers on screen.
    avg_daily = float(basis.avg_daily_units)
    unit_cost = basis.unit_cost
    lead_time_days = r.randint(3, 21)
    ordering_cost = round(r.uniform(25, 100), 2)
    holding_cost_pct = r.uniform(0.15, 0.30)

    annual_demand = avg_daily * 365
    eoq = round(
        math.sqrt(2 * annual_demand * ordering_cost / (unit_cost * holding_cost_pct))
    )
    safety_stock = round(avg_daily * lead_time_days * 0.5)
    reorder_point = round(avg_daily * lead_time_days + safety_stock)

    return tool_ok(
        {
            "sku": basis.sku,
            "product_name": basis.name,
            "recommendation": "REORDER",
            "order_details": {
                "quantity": eoq,
                "unit_cost": unit_cost,
                "total_cost": round(eoq * unit_cost, 2),
                # The vendor that actually serves this category, so the id and
                # the name agree with the supplier directory. Minted from a free
                # randint beside a name from its own list, this recommended
                # "SUP-457 / Pacific Distributors" — an id in no directory.
                "supplier": basis.supplier_id,
                "supplier_name": basis.supplier_name,
            },
            "calculations": {
                "eoq": eoq,
                "safety_stock": safety_stock,
                "reorder_point": reorder_point,
                "avg_daily_demand": round(avg_daily, 1),
                "lead_time_days": lead_time_days,
                "annual_demand": round(annual_demand),
            },
            "cost_analysis": {
                "annual_ordering_cost": round(annual_demand / eoq * ordering_cost, 2),
                "annual_holding_cost": round(eoq / 2 * unit_cost * holding_cost_pct, 2),
                "total_annual_inventory_cost": round(
                    annual_demand / eoq * ordering_cost
                    + eoq / 2 * unit_cost * holding_cost_pct,
                    2,
                ),
            },
            "expected_delivery": (today + timedelta(days=lead_time_days)).strftime(
                "%Y-%m-%d"
            ),
        },
        simulated=True,
    )


def get_abc_analysis() -> dict:
    today = _today()
    day = today.strftime("%Y-%m-%d")
    # The classes are shares of the same network the inventory summary reports.
    # Drawn independently, this card showed 212 + 363 + 512 = 1,087 SKUs directly
    # beside a "Total SKUs 5,501" tile, and put every class "On target" on a day
    # the network was at 94.1% in stock against a 95% goal.
    rows = category_rows(day)
    classification = abc_breakdown(rows)
    return tool_ok(
        {
            "analysis_date": day,
            "total_skus": sum(c.total_skus for c in rows),
            "classification": classification,
            "recommendations": [
                "Increase safety stock for A-class items below 98% fill rate",
                "Review C-class items with turnover < 2x for potential discontinuation",
                "Consolidate B-class items from 3 warehouses to 2 for cost savings",
                "Implement cycle counting for A-class items (weekly vs monthly)",
            ],
        },
        simulated=True,
    )


TOOLS = {
    "forecast_demand": forecast_demand,
    "get_demand_trends": get_demand_trends,
    "auto_reorder": auto_reorder,
    "get_abc_analysis": get_abc_analysis,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
