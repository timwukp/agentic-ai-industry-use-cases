"""Gateway target: demand_forecast — forecasting, trends, EOQ reorder, ABC analysis.

Forecast data is a deterministic simulation seeded from the function inputs
(stable within a calendar day). EOQ math is exact.
"""

import hashlib
import math
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
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
    r = _rng("forecast_demand", sku.upper(), days_ahead, today.strftime("%Y-%m-%d"))
    base_demand = r.uniform(10, 200)

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

    return tool_ok(
        {
            "sku": sku,
            "forecast_period_days": days_ahead,
            "model": "Gradient boosting + seasonal decomposition (demo simulation)",
            "total_predicted_demand": total,
            "avg_daily_demand": round(total / days_ahead, 1),
            "peak_day": max(forecasts, key=lambda f: f["predicted_units"])["date"],
            "forecasts": forecasts[:14] if days_ahead > 14 else forecasts,
            "accuracy_metrics": {
                "mape": round(r.uniform(5, 15), 1),
                "rmse": round(r.uniform(3, 20), 1),
                "forecast_bias": round(r.uniform(-3, 3), 1),
            },
            "factors": {
                "seasonality": "Moderate - weekend spike pattern",
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

    num_weeks = min(days // 7, 52)
    weekly_data = []
    for i in range(num_weeks):
        week_start = today - timedelta(weeks=num_weeks - i)
        weekly_data.append(
            {
                "week": week_start.strftime("%Y-W%V"),
                "units_sold": r.randint(500, 5000),
                "revenue": round(r.uniform(10000, 100000), 2),
                "avg_order_value": round(r.uniform(25, 150), 2),
            }
        )

    return tool_ok(
        {
            "category": category,
            "period": period,
            "trends": {
                "units_growth_pct": round(r.uniform(-5, 20), 1),
                "revenue_growth_pct": round(r.uniform(-3, 25), 1),
                "aov_change_pct": round(r.uniform(-2, 8), 1),
            },
            "weekly_data": weekly_data[-12:],
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
    r = _rng("auto_reorder", sku.upper())
    avg_daily = r.uniform(10, 200)
    lead_time_days = r.randint(3, 21)
    unit_cost = round(r.uniform(5, 200), 2)
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
            "sku": sku,
            "recommendation": "REORDER",
            "order_details": {
                "quantity": eoq,
                "unit_cost": unit_cost,
                "total_cost": round(eoq * unit_cost, 2),
                "supplier": f"SUP-{r.randint(100, 999)}",
                "supplier_name": r.choice(
                    [
                        "GlobalSupply Co",
                        "Pacific Distributors",
                        "Premier Wholesale",
                        "Atlas Trading",
                    ]
                ),
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
    r = _rng("abc_analysis", today.strftime("%Y-%m-%d"))
    return tool_ok(
        {
            "analysis_date": today.strftime("%Y-%m-%d"),
            "classification": {
                "A": {
                    "description": "High value - top 20% of SKUs, 80% of revenue",
                    "sku_count": r.randint(150, 300),
                    "sku_pct": 18.5,
                    "revenue_pct": 79.2,
                    "inventory_value": round(r.uniform(2000000, 5000000), 2),
                    "avg_turnover": round(r.uniform(8, 15), 1),
                    "target_fill_rate": 98.0,
                    "current_fill_rate": round(r.uniform(95, 99), 1),
                },
                "B": {
                    "description": "Medium value - next 30% of SKUs, 15% of revenue",
                    "sku_count": r.randint(300, 600),
                    "sku_pct": 31.2,
                    "revenue_pct": 15.3,
                    "inventory_value": round(r.uniform(500000, 1500000), 2),
                    "avg_turnover": round(r.uniform(5, 8), 1),
                    "target_fill_rate": 95.0,
                    "current_fill_rate": round(r.uniform(90, 97), 1),
                },
                "C": {
                    "description": "Low value - bottom 50% of SKUs, 5% of revenue",
                    "sku_count": r.randint(500, 1000),
                    "sku_pct": 50.3,
                    "revenue_pct": 5.5,
                    "inventory_value": round(r.uniform(100000, 500000), 2),
                    "avg_turnover": round(r.uniform(2, 5), 1),
                    "target_fill_rate": 90.0,
                    "current_fill_rate": round(r.uniform(85, 95), 1),
                },
            },
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
