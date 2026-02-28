from strands import tool
import json, random, math
from datetime import datetime, timedelta


@tool
def forecast_demand(sku: str, days_ahead: int) -> str:
    """Generate demand forecast for a product using ML models.

    Uses historical sales data and seasonal patterns to predict future demand.
    For complex multi-variable forecasting, use the Code Interpreter tool.

    Args:
        sku: Product SKU to forecast.
        days_ahead: Number of days to forecast (7, 14, 30, 60, 90).

    Returns:
        JSON with daily forecasts, confidence intervals, and seasonal factors.
    """
    days_ahead = min(days_ahead, 90)
    base_demand = random.uniform(10, 200)
    forecasts = []

    for i in range(days_ahead):
        date = datetime.utcnow() + timedelta(days=i+1)
        dow_factor = 1.3 if date.weekday() in [4, 5] else 0.8 if date.weekday() == 0 else 1.0
        seasonal = 1 + 0.2 * math.sin(2 * math.pi * date.timetuple().tm_yday / 365)
        trend = 1 + 0.001 * i
        noise = random.gauss(1, 0.1)

        forecast = max(0, base_demand * dow_factor * seasonal * trend * noise)

        forecasts.append({
            "date": date.strftime("%Y-%m-%d"),
            "predicted_units": round(forecast),
            "lower_bound": round(forecast * 0.7),
            "upper_bound": round(forecast * 1.4),
            "confidence": 0.85,
        })

    total = sum(f["predicted_units"] for f in forecasts)

    return json.dumps({
        "sku": sku,
        "forecast_period_days": days_ahead,
        "model": "XGBoost + Seasonal Decomposition",
        "total_predicted_demand": total,
        "avg_daily_demand": round(total / days_ahead, 1),
        "peak_day": max(forecasts, key=lambda f: f["predicted_units"])["date"],
        "forecasts": forecasts[:14] if days_ahead > 14 else forecasts,  # Limit detail output
        "accuracy_metrics": {
            "mape": round(random.uniform(5, 15), 1),
            "rmse": round(random.uniform(3, 20), 1),
            "forecast_bias": round(random.uniform(-3, 3), 1),
        },
        "factors": {
            "seasonality": "Moderate - weekend spike pattern",
            "trend": "Slightly upward (+0.1%/day)",
            "promotional_impact": "None currently active",
        },
    })


@tool
def get_demand_trends(category: str, period: str) -> str:
    """Analyze demand trends for a category over a time period.

    Args:
        category: Product category ('electronics', 'apparel', 'grocery', 'home', 'sports', 'all').
        period: Analysis period ('week', 'month', 'quarter', 'year').

    Returns:
        JSON with trend analysis, growth rates, and seasonal patterns.
    """
    periods_map = {"week": 7, "month": 30, "quarter": 90, "year": 365}
    days = periods_map.get(period, 30)

    weekly_data = []
    for i in range(min(days // 7, 52)):
        week_start = datetime.utcnow() - timedelta(weeks=min(days//7, 52) - i)
        weekly_data.append({
            "week": week_start.strftime("%Y-W%V"),
            "units_sold": random.randint(500, 5000),
            "revenue": round(random.uniform(10000, 100000), 2),
            "avg_order_value": round(random.uniform(25, 150), 2),
        })

    return json.dumps({
        "category": category,
        "period": period,
        "trends": {
            "units_growth_pct": round(random.uniform(-5, 20), 1),
            "revenue_growth_pct": round(random.uniform(-3, 25), 1),
            "aov_change_pct": round(random.uniform(-2, 8), 1),
        },
        "weekly_data": weekly_data[-12:],
        "top_growing_skus": [
            {"sku": f"SKU-{random.randint(100,999)}", "growth_pct": round(random.uniform(10, 50), 1)}
            for _ in range(5)
        ],
        "declining_skus": [
            {"sku": f"SKU-{random.randint(100,999)}", "decline_pct": round(random.uniform(-30, -5), 1)}
            for _ in range(3)
        ],
        "seasonality_index": round(random.uniform(0.8, 1.3), 2),
    })


@tool
def auto_reorder(sku: str) -> str:
    """Calculate and generate automatic reorder recommendation for a product.

    Uses Economic Order Quantity (EOQ) model with safety stock calculations.

    Args:
        sku: Product SKU to calculate reorder for.

    Returns:
        JSON with recommended order quantity, supplier, cost, and delivery timeline.
    """
    avg_daily = random.uniform(10, 200)
    lead_time_days = random.randint(3, 21)
    unit_cost = round(random.uniform(5, 200), 2)
    ordering_cost = round(random.uniform(25, 100), 2)
    holding_cost_pct = random.uniform(0.15, 0.30)

    annual_demand = avg_daily * 365
    eoq = round(math.sqrt(2 * annual_demand * ordering_cost / (unit_cost * holding_cost_pct)))
    safety_stock = round(avg_daily * lead_time_days * 0.5)
    reorder_point = round(avg_daily * lead_time_days + safety_stock)

    return json.dumps({
        "sku": sku,
        "recommendation": "REORDER",
        "order_details": {
            "quantity": eoq,
            "unit_cost": unit_cost,
            "total_cost": round(eoq * unit_cost, 2),
            "supplier": f"SUP-{random.randint(100, 999)}",
            "supplier_name": random.choice(["GlobalSupply Co", "Pacific Distributors", "Premier Wholesale", "Atlas Trading"]),
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
            "total_annual_inventory_cost": round((annual_demand / eoq * ordering_cost) + (eoq / 2 * unit_cost * holding_cost_pct), 2),
        },
        "expected_delivery": (datetime.utcnow() + timedelta(days=lead_time_days)).strftime("%Y-%m-%d"),
    })


@tool
def get_abc_analysis() -> str:
    """Perform ABC analysis on inventory to classify items by value contribution.

    Returns:
        JSON with ABC classification breakdown and optimization recommendations.
    """
    return json.dumps({
        "analysis_date": datetime.utcnow().strftime("%Y-%m-%d"),
        "classification": {
            "A": {
                "description": "High value - top 20% of SKUs, 80% of revenue",
                "sku_count": random.randint(150, 300),
                "sku_pct": 18.5,
                "revenue_pct": 79.2,
                "inventory_value": round(random.uniform(2000000, 5000000), 2),
                "avg_turnover": round(random.uniform(8, 15), 1),
                "target_fill_rate": 98.0,
                "current_fill_rate": round(random.uniform(95, 99), 1),
            },
            "B": {
                "description": "Medium value - next 30% of SKUs, 15% of revenue",
                "sku_count": random.randint(300, 600),
                "sku_pct": 31.2,
                "revenue_pct": 15.3,
                "inventory_value": round(random.uniform(500000, 1500000), 2),
                "avg_turnover": round(random.uniform(5, 8), 1),
                "target_fill_rate": 95.0,
                "current_fill_rate": round(random.uniform(90, 97), 1),
            },
            "C": {
                "description": "Low value - bottom 50% of SKUs, 5% of revenue",
                "sku_count": random.randint(500, 1000),
                "sku_pct": 50.3,
                "revenue_pct": 5.5,
                "inventory_value": round(random.uniform(100000, 500000), 2),
                "avg_turnover": round(random.uniform(2, 5), 1),
                "target_fill_rate": 90.0,
                "current_fill_rate": round(random.uniform(85, 95), 1),
            },
        },
        "recommendations": [
            "Increase safety stock for 12 A-class items below 98% fill rate",
            "Review 45 C-class items with turnover < 2x for potential discontinuation",
            "Consolidate B-class items from 3 warehouses to 2 for cost savings",
            "Implement cycle counting for A-class items (weekly vs monthly)",
        ],
    })
