from strands import tool
import json, random
from datetime import datetime, timedelta


@tool
def get_market_conditions(zipcode: str) -> str:
    """Get current local real estate market conditions for a zip code.

    Provides a comprehensive snapshot of the local housing market including
    pricing trends, inventory levels, and buyer/seller market indicators.

    Args:
        zipcode: Five-digit US zip code (e.g., '78701', '90210').

    Returns:
        JSON with median price, days on market, inventory, price trends, and market type indicator.
    """
    median_price = random.randint(250000, 1200000)
    median_ppsf = round(random.uniform(150, 600), 2)
    yoy_change = round(random.uniform(-8, 15), 1)
    mom_change = round(random.uniform(-3, 4), 1)
    avg_dom = random.randint(10, 90)
    active_listings = random.randint(50, 800)
    months_supply = round(random.uniform(0.8, 8.0), 1)

    if months_supply < 3:
        market_type = "Strong Seller's Market"
    elif months_supply < 5:
        market_type = "Seller's Market"
    elif months_supply < 7:
        market_type = "Balanced Market"
    else:
        market_type = "Buyer's Market"

    sale_to_list = round(random.uniform(0.94, 1.06), 3)
    pct_over_asking = round(random.uniform(10, 60), 1) if sale_to_list > 1.0 else round(random.uniform(2, 25), 1)

    return json.dumps({
        "zipcode": zipcode,
        "market_snapshot": {
            "median_sale_price": median_price,
            "median_price_per_sqft": median_ppsf,
            "average_days_on_market": avg_dom,
            "median_days_on_market": avg_dom - random.randint(0, 15),
            "active_listings": active_listings,
            "new_listings_30d": random.randint(20, 200),
            "closed_sales_30d": random.randint(15, 150),
            "pending_sales": random.randint(10, 100),
            "months_of_supply": months_supply,
        },
        "price_trends": {
            "year_over_year_pct": yoy_change,
            "month_over_month_pct": mom_change,
            "median_price_12mo_ago": round(median_price / (1 + yoy_change / 100), 0),
            "price_per_sqft_trend": round(random.uniform(-5, 12), 1),
        },
        "market_indicators": {
            "market_type": market_type,
            "sale_to_list_ratio": sale_to_list,
            "pct_sold_over_asking": pct_over_asking,
            "pct_with_price_reduction": round(random.uniform(10, 50), 1),
            "avg_price_reduction_pct": round(random.uniform(2, 8), 1),
            "absorption_rate": round(random.uniform(15, 85), 1),
        },
        "property_types": {
            "single_family": {"median_price": round(median_price * random.uniform(1.0, 1.3), 0), "pct_of_sales": round(random.uniform(40, 70), 1)},
            "condo": {"median_price": round(median_price * random.uniform(0.5, 0.85), 0), "pct_of_sales": round(random.uniform(15, 35), 1)},
            "townhouse": {"median_price": round(median_price * random.uniform(0.7, 0.95), 0), "pct_of_sales": round(random.uniform(5, 20), 1)},
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_neighborhood_analysis(address: str) -> str:
    """Get detailed neighborhood analysis and livability metrics for an address.

    Evaluates schools, safety, walkability, demographics, nearby amenities,
    and neighborhood growth trends.

    Args:
        address: Full property address to analyze the surrounding neighborhood.

    Returns:
        JSON with school ratings, crime stats, walkability, demographics, amenities, and growth trends.
    """
    school_rating = round(random.uniform(4, 10), 1)
    walk_score = random.randint(15, 98)
    transit_score = random.randint(5, 95)
    bike_score = random.randint(10, 90)

    return json.dumps({
        "address": address,
        "scores": {
            "overall_livability": random.randint(55, 95),
            "walk_score": walk_score,
            "transit_score": transit_score,
            "bike_score": bike_score,
        },
        "schools": {
            "average_rating": school_rating,
            "nearby_schools": [
                {"name": "Washington Elementary", "type": "Elementary", "rating": round(random.uniform(5, 10), 1), "distance_miles": round(random.uniform(0.2, 2.0), 1)},
                {"name": "Lincoln Middle School", "type": "Middle", "rating": round(random.uniform(5, 10), 1), "distance_miles": round(random.uniform(0.3, 3.0), 1)},
                {"name": "Jefferson High School", "type": "High", "rating": round(random.uniform(4, 10), 1), "distance_miles": round(random.uniform(0.5, 4.0), 1)},
            ],
        },
        "safety": {
            "crime_index": random.randint(15, 85),
            "crime_trend": random.choice(["Decreasing", "Stable", "Slightly Increasing"]),
            "violent_crime_per_1000": round(random.uniform(0.5, 8.0), 1),
            "property_crime_per_1000": round(random.uniform(5, 40), 1),
            "national_comparison": random.choice(["Below Average", "Average", "Above Average"]),
        },
        "demographics": {
            "median_household_income": random.randint(45000, 180000),
            "median_age": round(random.uniform(28, 52), 1),
            "population_density_per_sqmi": random.randint(500, 15000),
            "owner_occupied_pct": round(random.uniform(35, 85), 1),
            "college_educated_pct": round(random.uniform(20, 75), 1),
            "population_growth_5yr_pct": round(random.uniform(-2, 15), 1),
        },
        "amenities": {
            "restaurants_within_1mi": random.randint(5, 80),
            "grocery_stores_within_2mi": random.randint(1, 12),
            "parks_within_1mi": random.randint(1, 8),
            "hospitals_within_5mi": random.randint(1, 5),
            "shopping_centers_within_3mi": random.randint(1, 10),
        },
        "growth_trends": {
            "home_value_growth_1yr_pct": round(random.uniform(-5, 18), 1),
            "home_value_growth_5yr_pct": round(random.uniform(5, 80), 1),
            "new_construction_permits_1yr": random.randint(10, 500),
            "major_developments": random.sample([
                "New transit line extension", "Tech company HQ relocation",
                "Mixed-use development", "Hospital expansion",
                "School district renovation", "New shopping center",
            ], k=random.randint(1, 3)),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_market_forecast(zipcode: str, months: int) -> str:
    """Forecast home price trends for a zip code over a specified period.

    Uses historical data and market indicators to project future price
    movements with confidence intervals.

    Args:
        zipcode: Five-digit US zip code.
        months: Forecast horizon in months (1-36).

    Returns:
        JSON with monthly price forecasts, confidence intervals, and key risk factors.
    """
    months = min(max(1, months), 36)
    current_median = random.randint(300000, 1000000)
    annual_trend = random.uniform(-3, 12)
    monthly_trend = annual_trend / 12

    forecasts = []
    price = current_median
    for m in range(1, months + 1):
        monthly_change = monthly_trend + random.uniform(-1.5, 1.5)
        price = round(price * (1 + monthly_change / 100), 0)
        confidence_spread = 0.02 + (m * 0.005)
        forecasts.append({
            "month": m,
            "date": (datetime.utcnow() + timedelta(days=30 * m)).strftime("%Y-%m"),
            "forecasted_median_price": price,
            "confidence_low": round(price * (1 - confidence_spread), 0),
            "confidence_high": round(price * (1 + confidence_spread), 0),
            "month_over_month_pct": round(monthly_change, 2),
        })

    total_change = round((forecasts[-1]["forecasted_median_price"] / current_median - 1) * 100, 1)

    return json.dumps({
        "zipcode": zipcode,
        "forecast_horizon_months": months,
        "current_median_price": current_median,
        "forecast": forecasts,
        "summary": {
            "projected_end_price": forecasts[-1]["forecasted_median_price"],
            "total_price_change_pct": total_change,
            "annualized_growth_rate": round(total_change / (months / 12), 1),
            "forecast_confidence": "High" if months <= 6 else "Moderate" if months <= 18 else "Low",
        },
        "risk_factors": random.sample([
            "Interest rate volatility",
            "Local employment market shifts",
            "New housing supply pipeline",
            "Regulatory changes (zoning, rent control)",
            "Inflation and construction cost pressures",
            "Remote work migration patterns",
            "Seasonal demand fluctuations",
        ], k=random.randint(2, 4)),
        "positive_drivers": random.sample([
            "Strong job growth in metro area",
            "Limited housing inventory",
            "Population in-migration trends",
            "Infrastructure improvements planned",
            "Low mortgage rate environment",
            "Tech sector expansion nearby",
        ], k=random.randint(2, 3)),
        "disclaimer": "Forecasts are based on historical trends and current market indicators. Actual results may vary significantly.",
        "generated_date": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_market_trends(zipcode: str, period: str) -> str:
    """Get historical real estate market trends for a zip code.

    Retrieves time-series data for median prices, sales volume, price per
    square foot, and other key metrics over the specified period.

    Args:
        zipcode: Five-digit US zip code.
        period: Time period for trend data ('3m', '6m', '1y', '3y', '5y').

    Returns:
        JSON with historical trends including median price, volume, price/sqft over time.
    """
    period_months = {"3m": 3, "6m": 6, "1y": 12, "3y": 36, "5y": 60}.get(period, 12)

    base_price = random.randint(300000, 900000)
    base_ppsf = random.uniform(180, 500)
    base_volume = random.randint(30, 200)

    trend_data = []
    price = base_price
    ppsf = base_ppsf
    for m in range(period_months, 0, -1):
        date = (datetime.utcnow() - timedelta(days=30 * m)).strftime("%Y-%m")
        monthly_change = random.uniform(-2, 3)
        price = round(price * (1 + monthly_change / 100), 0)
        ppsf = round(ppsf * (1 + monthly_change / 100), 2)
        volume = max(5, base_volume + random.randint(-30, 30))
        season_mult = 1.0 + 0.15 * (1 if (datetime.utcnow() - timedelta(days=30 * m)).month in [4, 5, 6, 7] else -0.1)
        volume = round(volume * season_mult)

        trend_data.append({
            "date": date,
            "median_sale_price": price,
            "median_price_per_sqft": ppsf,
            "closed_sales": volume,
            "new_listings": volume + random.randint(-10, 20),
            "avg_days_on_market": random.randint(15, 75),
            "sale_to_list_ratio": round(random.uniform(0.95, 1.05), 3),
            "inventory": random.randint(50, 500),
        })

    first_price = trend_data[0]["median_sale_price"]
    last_price = trend_data[-1]["median_sale_price"]
    total_change = round((last_price / first_price - 1) * 100, 1) if first_price > 0 else 0

    return json.dumps({
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
            "avg_monthly_volume": round(sum(d["closed_sales"] for d in trend_data) / len(trend_data), 0),
            "volume_trend": "Increasing" if trend_data[-1]["closed_sales"] > trend_data[0]["closed_sales"] else "Decreasing",
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
