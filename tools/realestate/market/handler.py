"""Gateway target: market — market conditions, neighborhood analysis, forecast, trends.

The market's price level, pace and inventory come from the shared
toolkit.market_basis, so the conditions tile, the history chart and the forecast
base are one number. Drawn per route, one screen showed a "Median Sale Price
$440.1K" tile above a history chart plotting $740K-$780K, above a forecast
reading "projected from $777.1K".
"""

import hashlib
import random
from datetime import datetime, timezone

from toolkit import market_basis, month_label, price_history, tool_ok, tool_error
from toolkit.dispatch import dispatch


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


#: Drivers that hold in any market. The supply- and price-side ones are chosen
#: from the basis instead, so a 7.4-month buyer's market is not handed "Limited
#: housing inventory" as a tailwind on the card that calls it oversupplied.
GENERIC_RISKS = (
    "Interest rate volatility",
    "Local employment market shifts",
    "Regulatory changes (zoning, rent control)",
    "Inflation and construction cost pressures",
    "Seasonal demand fluctuations",
)
GENERIC_DRIVERS = (
    "Strong job growth in metro area",
    "Population in-migration trends",
    "Infrastructure improvements planned",
    "Tech sector expansion nearby",
)


def _risk_factors(basis, r: random.Random) -> list:
    """Risks that follow this market's supply and price direction."""
    out = []
    if basis.months_supply >= 6.0:
        out.append(f"Elevated inventory at {basis.months_supply} months of supply")
    if basis.yoy_pct < 0:
        out.append(f"Prices down {abs(basis.yoy_pct)}% year over year")
    out.extend(r.sample(GENERIC_RISKS, k=r.randint(2, 3)))
    return out


def _positive_drivers(basis, r: random.Random) -> list:
    """Tailwinds that follow this market's supply and price direction."""
    out = []
    if basis.months_supply < 4.0:
        out.append(f"Tight inventory at {basis.months_supply} months of supply")
    if basis.yoy_pct > 0:
        out.append(f"Prices up {basis.yoy_pct}% year over year")
    out.extend(r.sample(GENERIC_DRIVERS, k=2))
    return out


def get_market_conditions(zipcode: str) -> dict:
    today = _today()
    month = today.strftime("%Y-%m")
    basis = market_basis(zipcode, month)
    r = _rng("market_conditions", basis.zipcode, month)

    # Every indicator below is derived from months-of-supply and the price level.
    # Drawn beside them, a 1.6-month "Strong Seller's Market" reported a 0.944
    # sale-to-list ratio and a 90-day average time on market.
    sale_to_list = basis.sale_to_list_ratio

    # The three property types split the market's sales, so their shares sum to
    # 100. Drawn over (40,70)/(15,35)/(5,20) they summed to 91.3 one day and
    # 118.7 the next, on a card that reads as a breakdown.
    #
    # Two are drawn and the third is the residual, which makes the sum exact by
    # construction rather than by a normalisation step. The ranges keep the
    # residual comfortably positive: the worst case, 65 + 32, still leaves
    # townhouses 3.0% of sales. An earlier version normalised by
    # `100 / sum(shares)` on top of a `max(5.0, ...)` floor — with these ranges
    # the floor never binds, so that scale factor was always exactly 1.0.
    sf_pct = round(r.uniform(45, 65), 1)
    condo_pct = round(r.uniform(18, 32), 1)
    town_pct = round(100 - sf_pct - condo_pct, 1)

    # Each type's median relative to the market's own median. Drawn as three free
    # multipliers they share-weighted to $468K under a $528K headline median — the
    # card reads as a decomposition of the number above it, and 83 of 300 markets
    # blended more than 5% below their own headline. So the relatives are rescaled
    # to make the share-weighted blend land on the headline: single-family carries
    # a premium, condos a discount, townhouses between them, and the level is the
    # market's.
    relatives = {
        "single_family": (r.uniform(1.05, 1.25), sf_pct),
        "condo": (r.uniform(0.55, 0.8), condo_pct),
        "townhouse": (r.uniform(0.75, 0.95), town_pct),
    }
    blend = sum(rel * pct for rel, pct in relatives.values()) / 100
    type_medians = {
        name: {
            "median_price": round(basis.median_price * rel / blend),
            "pct_of_sales": pct,
        }
        for name, (rel, pct) in relatives.items()
    }

    return tool_ok(
        {
            "zipcode": basis.zipcode,
            "as_of": month,
            "market_snapshot": {
                "median_sale_price": basis.median_price,
                "median_price_per_sqft": basis.median_ppsf,
                # Implied by the two figures above; stated so a reader can see
                # the $/sqft is consistent with the median rather than a separate
                # draw that implied a 730 sqft median home.
                "implied_median_sqft": round(basis.median_price / basis.median_ppsf),
                "average_days_on_market": basis.average_dom,
                # The median is always at or below the mean when a few stale
                # listings drag the tail; drawn as avg - randint(0, 15) it could
                # equal the average exactly.
                "median_days_on_market": max(
                    3, round(basis.average_dom * r.uniform(0.75, 0.92))
                ),
                "active_listings": basis.active_listings,
                "new_listings_30d": basis.new_listings_30d,
                "closed_sales_30d": basis.closed_sales_30d,
                "pending_sales": basis.pending_sales,
                "months_of_supply": basis.months_supply,
            },
            "price_trends": {
                # Twelve months of the same drift the history chart walks, so the
                # tile and the line agree on direction. A free draw put "-2.7%
                # YoY" above a line that rose all year.
                "year_over_year_pct": basis.yoy_pct,
                "month_over_month_pct": round(basis.monthly_drift, 2),
                "median_price_12mo_ago": basis.price_12mo_ago,
                # Price per sqft rides the same price level, so it trends with it.
                "price_per_sqft_trend": basis.yoy_pct,
            },
            "market_indicators": {
                "market_type": basis.market_type,
                "sale_to_list_ratio": sale_to_list,
                "pct_sold_over_asking": basis.pct_sold_over_asking,
                "pct_with_price_reduction": basis.pct_with_price_reduction,
                "avg_price_reduction_pct": round(
                    max(1.5, (1.0 - sale_to_list) * 100 + 2.0), 1
                ),
                "absorption_rate": basis.absorption_rate,
            },
            "property_types": type_medians,
        },
        simulated=True,
    )


def get_neighborhood_analysis(address: str) -> dict:
    r = _rng("neighborhood", address.lower())

    # Density is the variable the rest of the profile follows: a downtown block
    # is walkable, transit-served, renter-heavy and thick with restaurants, and a
    # rural one is none of those. Drawn apart, this card reported walk score 94
    # and transit score 91 at 640 people/sq mi with 3 restaurants within a mile.
    density = r.randint(500, 15000)
    urban = min(1.0, max(0.0, (density - 500) / 12000))

    def _scaled(low: int, high: int, jitter: float = 0.12) -> int:
        """A score that follows how urban the block is, plus a little noise."""
        span = high - low
        return round(
            min(high, max(low, low + span * (urban + r.uniform(-jitter, jitter))))
        )

    walk = _scaled(15, 98)
    transit = _scaled(5, 95)
    bike = _scaled(20, 90)

    schools = [
        ("Washington Elementary", "Elementary", (0.2, 2.0)),
        ("Lincoln Middle School", "Middle", (0.3, 3.0)),
        ("Jefferson High School", "High", (0.5, 4.0)),
    ]
    # Schools cluster where people do, so distances shrink as density rises.
    nearby = [
        {
            "name": name,
            "type": kind,
            "rating": round(r.uniform(5, 10), 1),
            "distance_miles": round(
                max(0.1, lo + (hi - lo) * (1 - urban) * r.uniform(0.7, 1.15)), 1
            ),
        }
        for name, kind, (lo, hi) in schools
    ]

    # One year of appreciation, and five years compounded off it. Drawn as an
    # independent pair, the card showed 14.2% in the last year above 6.1% over
    # five — the one-year figure alone exceeding the five-year total.
    value_growth_1yr = round(r.uniform(-5, 18), 1)
    value_growth_5yr = round(
        ((1 + value_growth_1yr / 100 * r.uniform(0.6, 1.1)) ** 5 - 1) * 100, 1
    )

    violent = round(0.5 + 7.5 * urban * r.uniform(0.6, 1.3), 1)
    property_crime = round(violent * r.uniform(4.5, 7.0), 1)
    # A crime index is what the two rates above measure, so it cannot read "22 —
    # Below Average" beside 7.1 violent crimes per 1,000.
    crime_index = round(min(95, max(10, violent / 8.0 * 80 + r.uniform(-5, 5))))
    growth_5yr = round(r.uniform(-2, 15), 1)

    return tool_ok(
        {
            "address": address,
            "scores": {
                # Livability is the blend of the three scores below plus safety,
                # not a fifth draw that read 91 beside a walk score of 18.
                "overall_livability": round(
                    (walk + transit + bike) / 3 * 0.6 + (100 - crime_index) * 0.4
                ),
                "walk_score": walk,
                "transit_score": transit,
                "bike_score": bike,
            },
            "schools": {
                # The mean of the schools listed beneath it. Drawn separately, the
                # header said 5.2 above three schools rated 8.4, 9.1 and 7.7.
                "average_rating": round(
                    sum(s["rating"] for s in nearby) / len(nearby), 1
                ),
                "nearby_schools": nearby,
            },
            "safety": {
                "crime_index": crime_index,
                # Follows the five-year population growth: a shrinking
                # neighborhood with rising crime is a different story from a
                # booming one, and the two were drawn independently.
                "crime_trend": (
                    "Decreasing"
                    if growth_5yr > 8
                    else "Stable" if growth_5yr > 2 else "Slightly Increasing"
                ),
                "violent_crime_per_1000": violent,
                "property_crime_per_1000": property_crime,
                "national_comparison": (
                    "Below Average"
                    if crime_index < 35
                    else "Average" if crime_index < 65 else "Above Average"
                ),
            },
            "demographics": {
                "median_household_income": r.randint(45000, 180000),
                "median_age": round(r.uniform(28, 52), 1),
                "population_density_per_sqmi": density,
                # Dense blocks are renter-heavy; this ran to 85% owner-occupied
                # at 14,000 people per square mile.
                "owner_occupied_pct": round(85 - 45 * urban * r.uniform(0.8, 1.2), 1),
                "college_educated_pct": round(r.uniform(20, 75), 1),
                "population_growth_5yr_pct": growth_5yr,
            },
            "amenities": {
                # Amenity counts are what density means on the ground.
                "restaurants_within_1mi": max(
                    1, round(5 + 75 * urban * r.uniform(0.7, 1.3))
                ),
                "grocery_stores_within_2mi": max(1, round(1 + 11 * urban)),
                "parks_within_1mi": max(1, round(1 + 7 * urban * r.uniform(0.6, 1.2))),
                "hospitals_within_5mi": max(1, round(1 + 4 * urban)),
                "shopping_centers_within_3mi": max(1, round(1 + 9 * urban)),
            },
            "growth_trends": {
                "home_value_growth_1yr_pct": value_growth_1yr,
                "home_value_growth_5yr_pct": value_growth_5yr,
                # Permits track how fast the population is growing.
                "new_construction_permits_1yr": max(
                    5, round(10 + 490 * max(0.0, growth_5yr) / 15 * r.uniform(0.7, 1.3))
                ),
                "major_developments": r.sample(
                    [
                        "New transit line extension",
                        "Tech company HQ relocation",
                        "Mixed-use development",
                        "Hospital expansion",
                        "School district renovation",
                        "New shopping center",
                    ],
                    k=r.randint(1, 3),
                ),
            },
        },
        simulated=True,
    )


def get_market_forecast(zipcode: str, months: int = 12) -> dict:
    months = min(max(1, int(months)), 36)
    today = _today()
    month = today.strftime("%Y-%m")
    basis = market_basis(zipcode, month)
    r = _rng("market_forecast", basis.zipcode, months, month)
    # The forecast starts where the history ends — that is what makes the two
    # charts joinable. Drawn on its own, the card read "projected from $777.1K"
    # beside a $440.1K median tile.
    current_median = basis.median_price
    # And it continues the trailing drift rather than a fresh (-3, 12) trend that
    # projected +11%/yr for a market whose own history chart fell all year.
    monthly_trend = basis.monthly_drift

    forecasts = []
    price = float(current_median)
    for m in range(1, months + 1):
        # Noise scaled to the drift, so a flat market is not forecast to swing
        # ±1.5%/month: at a 0.1%/month drift the sign of the projection was set
        # by the noise, and month_over_month_pct contradicted the trend stated in
        # the summary.
        monthly_change = monthly_trend + r.gauss(0, 0.35)
        price = round(price * (1 + monthly_change / 100))
        confidence_spread = 0.02 + m * 0.005
        forecasts.append(
            {
                "month": m,
                "date": month_label(today, m),
                "forecasted_median_price": price,
                "confidence_low": round(price * (1 - confidence_spread)),
                "confidence_high": round(price * (1 + confidence_spread)),
                "month_over_month_pct": round(monthly_change, 2),
            }
        )
    total_change = round(
        (forecasts[-1]["forecasted_median_price"] / current_median - 1) * 100, 1
    )

    return tool_ok(
        {
            "zipcode": basis.zipcode,
            "forecast_horizon_months": months,
            "current_median_price": current_median,
            "trailing_yoy_pct": basis.yoy_pct,
            "market_type": basis.market_type,
            "forecast": forecasts,
            "summary": {
                "projected_end_price": forecasts[-1]["forecasted_median_price"],
                "total_price_change_pct": total_change,
                "annualized_growth_rate": round(total_change / (months / 12), 1),
                "forecast_confidence": (
                    "High" if months <= 6 else "Moderate" if months <= 18 else "Low"
                ),
            },
            # The supply-side driver has to match the market this zipcode is in.
            # Sampled freely from one list, a 7.4-month buyer's market was handed
            # "Limited housing inventory" as a positive driver on the same card
            # that called it oversupplied.
            "risk_factors": _risk_factors(basis, r),
            "positive_drivers": _positive_drivers(basis, r),
            "disclaimer": (
                "Forecasts are based on historical trends and current market "
                "indicators. Actual results may vary significantly."
            ),
        },
        simulated=True,
    )


def get_market_trends(zipcode: str, period: str = "1y") -> dict:
    period = period.lower()
    period_map = {"3m": 3, "6m": 6, "1y": 12, "3y": 36, "5y": 60}
    if period not in period_map:
        return tool_error(f"Invalid period: {period}", valid=sorted(period_map))
    period_months = period_map[period]
    today = _today()
    month = today.strftime("%Y-%m")
    basis = market_basis(zipcode, month)

    # Walked backwards from today's median, so the last point of this chart IS
    # the median the conditions tile shows. Walked forwards from an independent
    # start, the endpoint landed wherever the noise took it — which is how a
    # $440.1K tile ended up above a chart topping out at $780K.
    trend_data = price_history(basis, today, period_months)

    first_price = trend_data[0]["median_sale_price"]
    last_price = trend_data[-1]["median_sale_price"]
    total_change = round((last_price / first_price - 1) * 100, 1)

    return tool_ok(
        {
            "zipcode": basis.zipcode,
            "period": period,
            "data_points": len(trend_data),
            "current_median_price": basis.median_price,
            "market_type": basis.market_type,
            "trends": trend_data,
            "summary": {
                "start_median_price": first_price,
                "end_median_price": last_price,
                "total_price_change_pct": total_change,
                "annualized_change_pct": round(total_change / (period_months / 12), 1),
                "peak_price": max(d["median_sale_price"] for d in trend_data),
                "trough_price": min(d["median_sale_price"] for d in trend_data),
                "avg_monthly_volume": round(
                    sum(d["closed_sales"] for d in trend_data) / len(trend_data)
                ),
                "volume_trend": (
                    "Increasing"
                    if trend_data[-1]["closed_sales"] > trend_data[0]["closed_sales"]
                    else "Decreasing"
                ),
            },
        },
        simulated=True,
    )


TOOLS = {
    "get_market_conditions": get_market_conditions,
    "get_neighborhood_analysis": get_neighborhood_analysis,
    "get_market_forecast": get_market_forecast,
    "get_market_trends": get_market_trends,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
