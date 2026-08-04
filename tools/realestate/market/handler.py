"""Gateway target: market — market conditions, neighborhood analysis, forecast, trends.

Market data is a deterministic simulation seeded from the function inputs
(stable within a calendar day for date-relative fields).
"""
import hashlib
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


def get_market_conditions(zipcode: str) -> dict:
    today = _today()
    r = _rng("market_conditions", zipcode, today.strftime("%Y-%m"))
    median_price = r.randint(250000, 1200000)
    yoy_change = round(r.uniform(-8, 15), 1)
    avg_dom = r.randint(10, 90)
    months_supply = round(r.uniform(0.8, 8.0), 1)

    if months_supply < 3:
        market_type = "Strong Seller's Market"
    elif months_supply < 5:
        market_type = "Seller's Market"
    elif months_supply < 7:
        market_type = "Balanced Market"
    else:
        market_type = "Buyer's Market"

    sale_to_list = round(r.uniform(0.94, 1.06), 3)
    pct_over_asking = (round(r.uniform(10, 60), 1) if sale_to_list > 1.0
                       else round(r.uniform(2, 25), 1))

    return tool_ok({
        "zipcode": zipcode,
        "market_snapshot": {
            "median_sale_price": median_price,
            "median_price_per_sqft": round(r.uniform(150, 600), 2),
            "average_days_on_market": avg_dom,
            "median_days_on_market": avg_dom - r.randint(0, 15),
            "active_listings": r.randint(50, 800),
            "new_listings_30d": r.randint(20, 200),
            "closed_sales_30d": r.randint(15, 150),
            "pending_sales": r.randint(10, 100),
            "months_of_supply": months_supply,
        },
        "price_trends": {
            "year_over_year_pct": yoy_change,
            "month_over_month_pct": round(r.uniform(-3, 4), 1),
            "median_price_12mo_ago": round(median_price / (1 + yoy_change / 100)),
            "price_per_sqft_trend": round(r.uniform(-5, 12), 1),
        },
        "market_indicators": {
            "market_type": market_type,
            "sale_to_list_ratio": sale_to_list,
            "pct_sold_over_asking": pct_over_asking,
            "pct_with_price_reduction": round(r.uniform(10, 50), 1),
            "avg_price_reduction_pct": round(r.uniform(2, 8), 1),
            "absorption_rate": round(r.uniform(15, 85), 1),
        },
        "property_types": {
            "single_family": {"median_price": round(median_price * r.uniform(1.0, 1.3)),
                              "pct_of_sales": round(r.uniform(40, 70), 1)},
            "condo": {"median_price": round(median_price * r.uniform(0.5, 0.85)),
                      "pct_of_sales": round(r.uniform(15, 35), 1)},
            "townhouse": {"median_price": round(median_price * r.uniform(0.7, 0.95)),
                          "pct_of_sales": round(r.uniform(5, 20), 1)},
        },
    }, simulated=True)


def get_neighborhood_analysis(address: str) -> dict:
    r = _rng("neighborhood", address.lower())
    return tool_ok({
        "address": address,
        "scores": {
            "overall_livability": r.randint(55, 95),
            "walk_score": r.randint(15, 98),
            "transit_score": r.randint(5, 95),
            "bike_score": r.randint(10, 90),
        },
        "schools": {
            "average_rating": round(r.uniform(4, 10), 1),
            "nearby_schools": [
                {"name": "Washington Elementary", "type": "Elementary",
                 "rating": round(r.uniform(5, 10), 1),
                 "distance_miles": round(r.uniform(0.2, 2.0), 1)},
                {"name": "Lincoln Middle School", "type": "Middle",
                 "rating": round(r.uniform(5, 10), 1),
                 "distance_miles": round(r.uniform(0.3, 3.0), 1)},
                {"name": "Jefferson High School", "type": "High",
                 "rating": round(r.uniform(4, 10), 1),
                 "distance_miles": round(r.uniform(0.5, 4.0), 1)},
            ],
        },
        "safety": {
            "crime_index": r.randint(15, 85),
            "crime_trend": r.choice(["Decreasing", "Stable", "Slightly Increasing"]),
            "violent_crime_per_1000": round(r.uniform(0.5, 8.0), 1),
            "property_crime_per_1000": round(r.uniform(5, 40), 1),
            "national_comparison": r.choice(["Below Average", "Average", "Above Average"]),
        },
        "demographics": {
            "median_household_income": r.randint(45000, 180000),
            "median_age": round(r.uniform(28, 52), 1),
            "population_density_per_sqmi": r.randint(500, 15000),
            "owner_occupied_pct": round(r.uniform(35, 85), 1),
            "college_educated_pct": round(r.uniform(20, 75), 1),
            "population_growth_5yr_pct": round(r.uniform(-2, 15), 1),
        },
        "amenities": {
            "restaurants_within_1mi": r.randint(5, 80),
            "grocery_stores_within_2mi": r.randint(1, 12),
            "parks_within_1mi": r.randint(1, 8),
            "hospitals_within_5mi": r.randint(1, 5),
            "shopping_centers_within_3mi": r.randint(1, 10),
        },
        "growth_trends": {
            "home_value_growth_1yr_pct": round(r.uniform(-5, 18), 1),
            "home_value_growth_5yr_pct": round(r.uniform(5, 80), 1),
            "new_construction_permits_1yr": r.randint(10, 500),
            "major_developments": r.sample([
                "New transit line extension", "Tech company HQ relocation",
                "Mixed-use development", "Hospital expansion",
                "School district renovation", "New shopping center",
            ], k=r.randint(1, 3)),
        },
    }, simulated=True)


def get_market_forecast(zipcode: str, months: int = 12) -> dict:
    months = min(max(1, int(months)), 36)
    today = _today()
    r = _rng("market_forecast", zipcode, months, today.strftime("%Y-%m"))
    current_median = r.randint(300000, 1000000)
    monthly_trend = r.uniform(-3, 12) / 12

    forecasts = []
    price = float(current_median)
    for m in range(1, months + 1):
        monthly_change = monthly_trend + r.uniform(-1.5, 1.5)
        price = round(price * (1 + monthly_change / 100))
        confidence_spread = 0.02 + m * 0.005
        forecasts.append({
            "month": m,
            "date": (today + timedelta(days=30 * m)).strftime("%Y-%m"),
            "forecasted_median_price": price,
            "confidence_low": round(price * (1 - confidence_spread)),
            "confidence_high": round(price * (1 + confidence_spread)),
            "month_over_month_pct": round(monthly_change, 2),
        })
    total_change = round((forecasts[-1]["forecasted_median_price"] / current_median - 1) * 100, 1)

    return tool_ok({
        "zipcode": zipcode,
        "forecast_horizon_months": months,
        "current_median_price": current_median,
        "forecast": forecasts,
        "summary": {
            "projected_end_price": forecasts[-1]["forecasted_median_price"],
            "total_price_change_pct": total_change,
            "annualized_growth_rate": round(total_change / (months / 12), 1),
            "forecast_confidence": ("High" if months <= 6 else "Moderate" if months <= 18
                                    else "Low"),
        },
        "risk_factors": r.sample([
            "Interest rate volatility",
            "Local employment market shifts",
            "New housing supply pipeline",
            "Regulatory changes (zoning, rent control)",
            "Inflation and construction cost pressures",
            "Remote work migration patterns",
            "Seasonal demand fluctuations",
        ], k=r.randint(2, 4)),
        "positive_drivers": r.sample([
            "Strong job growth in metro area",
            "Limited housing inventory",
            "Population in-migration trends",
            "Infrastructure improvements planned",
            "Low mortgage rate environment",
            "Tech sector expansion nearby",
        ], k=r.randint(2, 3)),
        "disclaimer": ("Forecasts are based on historical trends and current market "
                       "indicators. Actual results may vary significantly."),
    }, simulated=True)


def get_market_trends(zipcode: str, period: str = "1y") -> dict:
    period = period.lower()
    period_map = {"3m": 3, "6m": 6, "1y": 12, "3y": 36, "5y": 60}
    if period not in period_map:
        return tool_error(f"Invalid period: {period}", valid=sorted(period_map))
    period_months = period_map[period]
    today = _today()
    r = _rng("market_trends", zipcode, period, today.strftime("%Y-%m"))

    price = float(r.randint(300000, 900000))
    ppsf = r.uniform(180, 500)
    base_volume = r.randint(30, 200)

    trend_data = []
    for m in range(period_months, 0, -1):
        month_date = today - timedelta(days=30 * m)
        monthly_change = r.uniform(-2, 3)
        price = round(price * (1 + monthly_change / 100))
        ppsf = round(ppsf * (1 + monthly_change / 100), 2)
        volume = max(5, base_volume + r.randint(-30, 30))
        season_mult = 1.0 + 0.15 * (1 if month_date.month in (4, 5, 6, 7) else -0.1)
        volume = round(volume * season_mult)
        trend_data.append({
            "date": month_date.strftime("%Y-%m"),
            "median_sale_price": price,
            "median_price_per_sqft": ppsf,
            "closed_sales": volume,
            "new_listings": volume + r.randint(-10, 20),
            "avg_days_on_market": r.randint(15, 75),
            "sale_to_list_ratio": round(r.uniform(0.95, 1.05), 3),
            "inventory": r.randint(50, 500),
        })

    first_price = trend_data[0]["median_sale_price"]
    last_price = trend_data[-1]["median_sale_price"]
    total_change = round((last_price / first_price - 1) * 100, 1)

    return tool_ok({
        "zipcode": zipcode,
        "period": period,
        "data_points": len(trend_data),
        "trends": trend_data,
        "summary": {
            "start_median_price": first_price,
            "end_median_price": last_price,
            "total_price_change_pct": total_change,
            "annualized_change_pct": round(total_change / (period_months / 12), 1),
            "peak_price": max(d["median_sale_price"] for d in trend_data),
            "trough_price": min(d["median_sale_price"] for d in trend_data),
            "avg_monthly_volume": round(sum(d["closed_sales"] for d in trend_data)
                                        / len(trend_data)),
            "volume_trend": ("Increasing" if trend_data[-1]["closed_sales"]
                             > trend_data[0]["closed_sales"] else "Decreasing"),
        },
    }, simulated=True)


TOOLS = {
    "get_market_conditions": get_market_conditions,
    "get_neighborhood_analysis": get_neighborhood_analysis,
    "get_market_forecast": get_market_forecast,
    "get_market_trends": get_market_trends,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
