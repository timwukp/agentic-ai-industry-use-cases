from strands import tool
import json, random
from datetime import datetime, timedelta


@tool
def estimate_property_value(address: str, property_type: str, bedrooms: int, bathrooms: int, sqft: int, lot_sqft: int, year_built: int) -> str:
    """Automated Valuation Model (AVM) for estimating property market value.

    Uses comparable sales analysis, market conditions, and property characteristics
    to generate a data-driven value estimate with confidence intervals.

    Args:
        address: Full property address (e.g., '123 Main St, Austin, TX 78701').
        property_type: Type of property ('single_family', 'condo', 'townhouse', 'multi_family', 'land').
        bedrooms: Number of bedrooms.
        bathrooms: Number of bathrooms.
        sqft: Living area in square feet.
        lot_sqft: Lot size in square feet.
        year_built: Year the property was constructed.

    Returns:
        JSON with estimated value, confidence range, comparables used, and methodology breakdown.
    """
    base_price_per_sqft = {
        "single_family": random.uniform(180, 450),
        "condo": random.uniform(200, 550),
        "townhouse": random.uniform(190, 420),
        "multi_family": random.uniform(150, 350),
        "land": random.uniform(5, 50),
    }

    ppsf = base_price_per_sqft.get(property_type, random.uniform(200, 400))
    age = 2026 - year_built
    age_adjustment = max(-0.15, -0.003 * age)
    bed_bath_adjustment = 0.02 * (bedrooms - 3) + 0.03 * (bathrooms - 2)
    lot_adjustment = 0.05 if lot_sqft > 8000 else -0.02 if lot_sqft < 4000 else 0.0
    adjusted_ppsf = ppsf * (1 + age_adjustment + bed_bath_adjustment + lot_adjustment)
    estimated_value = round(adjusted_ppsf * sqft, -3)

    confidence_low = round(estimated_value * random.uniform(0.90, 0.95), -3)
    confidence_high = round(estimated_value * random.uniform(1.05, 1.12), -3)
    confidence_score = round(random.uniform(75, 95), 1)

    comps_used = random.randint(4, 8)
    streets = ["Oak Dr", "Maple Ave", "Elm St", "Cedar Ln", "Pine Rd", "Birch Ct", "Walnut Way", "Spruce Blvd"]
    comparables = []
    for i in range(comps_used):
        comp_sqft = sqft + random.randint(-400, 400)
        comp_ppsf = adjusted_ppsf * random.uniform(0.88, 1.12)
        comp_price = round(comp_ppsf * comp_sqft, -3)
        sale_date = (datetime.utcnow() - timedelta(days=random.randint(15, 180))).strftime("%Y-%m-%d")
        comparables.append({
            "address": f"{random.randint(100, 9999)} {random.choice(streets)}",
            "sale_price": comp_price,
            "sale_date": sale_date,
            "sqft": comp_sqft,
            "beds": bedrooms + random.choice([-1, 0, 0, 1]),
            "baths": bathrooms + random.choice([-1, 0, 0, 1]),
            "price_per_sqft": round(comp_ppsf, 2),
            "distance_miles": round(random.uniform(0.2, 2.5), 2),
        })

    return json.dumps({
        "address": address,
        "property_type": property_type,
        "subject_property": {
            "bedrooms": bedrooms,
            "bathrooms": bathrooms,
            "sqft": sqft,
            "lot_sqft": lot_sqft,
            "year_built": year_built,
        },
        "valuation": {
            "estimated_value": estimated_value,
            "confidence_low": confidence_low,
            "confidence_high": confidence_high,
            "confidence_score": confidence_score,
            "price_per_sqft": round(adjusted_ppsf, 2),
        },
        "methodology": {
            "primary": "Comparable Sales Approach",
            "comparables_used": comps_used,
            "adjustments_applied": [
                {"factor": "Age/Condition", "adjustment_pct": round(age_adjustment * 100, 1)},
                {"factor": "Bed/Bath Count", "adjustment_pct": round(bed_bath_adjustment * 100, 1)},
                {"factor": "Lot Size", "adjustment_pct": round(lot_adjustment * 100, 1)},
            ],
        },
        "comparables": comparables,
        "disclaimer": "This is an automated valuation estimate. A formal appraisal by a licensed appraiser is required for mortgage lending and legal purposes.",
        "valuation_date": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_comparables(address: str, radius_miles: float, max_results: int) -> str:
    """Find comparable property sales near a given address.

    Searches recent sales data for properties with similar characteristics
    within the specified radius, ordered by similarity score.

    Args:
        address: Subject property address to find comparables for.
        radius_miles: Search radius in miles (e.g., 0.5, 1.0, 3.0).
        max_results: Maximum number of comparable properties to return (1-20).

    Returns:
        JSON with list of comparable sales including price, details, and adjustments.
    """
    max_results = min(max(1, max_results), 20)
    streets = ["Oak Dr", "Maple Ave", "Elm St", "Cedar Ln", "Pine Rd", "Birch Ct", "Walnut Way",
               "Spruce Blvd", "Willow Ct", "Aspen Ln", "Magnolia Dr", "Hickory St"]

    base_sqft = random.randint(1200, 3500)
    base_ppsf = random.uniform(180, 500)
    base_beds = random.randint(2, 5)
    base_baths = random.randint(1, 4)

    comparables = []
    for i in range(max_results):
        comp_sqft = base_sqft + random.randint(-600, 600)
        comp_beds = base_beds + random.choice([-1, 0, 0, 0, 1])
        comp_baths = base_baths + random.choice([-1, 0, 0, 1])
        comp_ppsf = base_ppsf * random.uniform(0.85, 1.15)
        sale_price = round(comp_ppsf * comp_sqft, -3)
        distance = round(random.uniform(0.1, radius_miles), 2)
        days_ago = random.randint(10, 365)
        sale_date = (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
        year_built = random.randint(1960, 2024)

        sqft_adj = round((base_sqft - comp_sqft) * base_ppsf * 0.5, 0)
        bed_adj = (base_beds - comp_beds) * random.randint(5000, 15000)
        bath_adj = (base_baths - comp_baths) * random.randint(8000, 20000)
        time_adj = round(sale_price * 0.003 * (days_ago / 30), 0)
        total_adj = sqft_adj + bed_adj + bath_adj + time_adj
        adjusted_price = round(sale_price + total_adj, -3)

        similarity = round(random.uniform(70, 98), 1)

        comparables.append({
            "address": f"{random.randint(100, 9999)} {random.choice(streets)}",
            "sale_price": sale_price,
            "adjusted_price": adjusted_price,
            "sale_date": sale_date,
            "days_on_market": random.randint(5, 120),
            "sqft": comp_sqft,
            "beds": max(1, comp_beds),
            "baths": max(1, comp_baths),
            "lot_sqft": random.randint(3000, 20000),
            "year_built": year_built,
            "price_per_sqft": round(comp_ppsf, 2),
            "distance_miles": distance,
            "property_type": random.choice(["single_family", "single_family", "condo", "townhouse"]),
            "adjustments": {
                "sqft": sqft_adj,
                "bedrooms": bed_adj,
                "bathrooms": bath_adj,
                "time": time_adj,
                "total": total_adj,
            },
            "similarity_score": similarity,
        })

    comparables.sort(key=lambda c: c["similarity_score"], reverse=True)

    return json.dumps({
        "subject_address": address,
        "search_radius_miles": radius_miles,
        "total_found": max_results,
        "comparables": comparables,
        "summary": {
            "median_sale_price": sorted([c["sale_price"] for c in comparables])[len(comparables) // 2],
            "median_price_per_sqft": round(sum(c["price_per_sqft"] for c in comparables) / len(comparables), 2),
            "median_adjusted_price": sorted([c["adjusted_price"] for c in comparables])[len(comparables) // 2],
            "avg_days_on_market": round(sum(c["days_on_market"] for c in comparables) / len(comparables), 0),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_cma_report(address: str) -> str:
    """Generate a Comparative Market Analysis (CMA) report for a property.

    Produces a comprehensive CMA including subject property details, comparable
    properties with adjustments, value reconciliation, and market positioning.

    Args:
        address: Full address of the subject property.

    Returns:
        JSON with detailed CMA report including subject, comparables, adjustments, and value conclusion.
    """
    beds = random.randint(2, 5)
    baths = random.randint(1, 4)
    sqft = random.randint(1200, 4000)
    lot_sqft = random.randint(3500, 25000)
    year_built = random.randint(1950, 2023)
    base_ppsf = random.uniform(200, 500)

    subject = {
        "address": address,
        "beds": beds,
        "baths": baths,
        "sqft": sqft,
        "lot_sqft": lot_sqft,
        "year_built": year_built,
        "property_type": "single_family",
        "condition": random.choice(["Excellent", "Good", "Average", "Fair"]),
        "features": random.sample(["Garage", "Pool", "Updated Kitchen", "Hardwood Floors",
                                    "Central AC", "Fireplace", "Deck/Patio", "New Roof"], k=random.randint(3, 6)),
    }

    streets = ["Oak Dr", "Maple Ave", "Elm St", "Cedar Ln", "Pine Rd", "Birch Ct"]
    comparables = []
    for i in range(5):
        c_sqft = sqft + random.randint(-500, 500)
        c_beds = beds + random.choice([-1, 0, 0, 1])
        c_baths = baths + random.choice([-1, 0, 0, 1])
        c_ppsf = base_ppsf * random.uniform(0.88, 1.12)
        c_price = round(c_ppsf * c_sqft, -3)
        days_ago = random.randint(10, 150)
        c_lot = lot_sqft + random.randint(-3000, 5000)

        adjustments = {
            "sqft": round((sqft - c_sqft) * base_ppsf * 0.5, 0),
            "bedrooms": (beds - max(1, c_beds)) * random.randint(5000, 15000),
            "bathrooms": (baths - max(1, c_baths)) * random.randint(8000, 20000),
            "lot_size": round((lot_sqft - c_lot) * random.uniform(1, 5), 0),
            "age": (year_built - random.randint(1950, 2023)) * random.randint(200, 800),
            "condition": random.choice([-10000, -5000, 0, 5000, 10000]),
            "features": random.randint(-15000, 15000),
        }
        total_adj = sum(adjustments.values())
        adjusted_price = round(c_price + total_adj, -3)

        comparables.append({
            "comp_number": i + 1,
            "address": f"{random.randint(100, 9999)} {random.choice(streets)}",
            "sale_price": c_price,
            "sale_date": (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%d"),
            "status": random.choice(["Sold", "Sold", "Sold", "Pending"]),
            "sqft": c_sqft,
            "beds": max(1, c_beds),
            "baths": max(1, c_baths),
            "lot_sqft": max(1000, c_lot),
            "year_built": random.randint(1950, 2023),
            "price_per_sqft": round(c_ppsf, 2),
            "days_on_market": random.randint(5, 90),
            "adjustments": adjustments,
            "net_adjustment": total_adj,
            "adjusted_price": adjusted_price,
        })

    adjusted_prices = [c["adjusted_price"] for c in comparables]
    value_low = min(adjusted_prices)
    value_high = max(adjusted_prices)
    value_indicated = round(sum(adjusted_prices) / len(adjusted_prices), -3)

    active_listings = []
    for i in range(3):
        a_sqft = sqft + random.randint(-400, 400)
        a_ppsf = base_ppsf * random.uniform(1.0, 1.15)
        active_listings.append({
            "address": f"{random.randint(100, 9999)} {random.choice(streets)}",
            "list_price": round(a_ppsf * a_sqft, -3),
            "sqft": a_sqft,
            "beds": beds + random.choice([-1, 0, 1]),
            "baths": baths + random.choice([0, 0, 1]),
            "days_on_market": random.randint(1, 60),
        })

    return json.dumps({
        "report_type": "Comparative Market Analysis",
        "subject_property": subject,
        "comparable_sales": comparables,
        "active_listings": active_listings,
        "value_conclusion": {
            "indicated_value_range": {"low": value_low, "high": value_high},
            "reconciled_value": value_indicated,
            "price_per_sqft": round(value_indicated / sqft, 2),
            "confidence_level": random.choice(["High", "High", "Moderate"]),
        },
        "market_position": {
            "suggested_list_price": round(value_indicated * random.uniform(1.00, 1.05), -3),
            "competitive_price": round(value_indicated * 0.98, -3),
            "aspirational_price": round(value_indicated * 1.07, -3),
        },
        "prepared_date": datetime.utcnow().strftime("%Y-%m-%d"),
        "disclaimer": "This CMA is for informational purposes only. It is not a formal appraisal. A licensed appraiser should be consulted for lending or legal valuations.",
    })


@tool
def calculate_replacement_cost(property_type: str, sqft: int, quality_grade: str, year_built: int) -> str:
    """Estimate property value using the cost approach (replacement cost method).

    Calculates the cost to rebuild the structure, applies depreciation, and adds
    land value to determine total property value.

    Args:
        property_type: Type of property ('single_family', 'condo', 'townhouse', 'multi_family', 'commercial').
        sqft: Building area in square feet.
        quality_grade: Construction quality ('economy', 'standard', 'good', 'excellent', 'luxury').
        year_built: Year the structure was built.

    Returns:
        JSON with land value, construction cost, depreciation, and total replacement cost estimate.
    """
    cost_per_sqft = {
        "economy": random.uniform(80, 120),
        "standard": random.uniform(120, 180),
        "good": random.uniform(180, 260),
        "excellent": random.uniform(260, 380),
        "luxury": random.uniform(380, 600),
    }

    land_value_per_sqft = {
        "single_family": random.uniform(5, 50),
        "condo": random.uniform(10, 80),
        "townhouse": random.uniform(8, 60),
        "multi_family": random.uniform(15, 70),
        "commercial": random.uniform(20, 120),
    }

    construction_cost_psf = cost_per_sqft.get(quality_grade, random.uniform(150, 250))
    replacement_cost_new = round(construction_cost_psf * sqft, 2)

    age = 2026 - year_built
    effective_age = max(0, age - random.randint(0, min(10, age)))
    useful_life = random.randint(50, 80)
    physical_depreciation_pct = min(70, round((effective_age / useful_life) * 100, 1))
    functional_obsolescence_pct = round(random.uniform(0, 8), 1) if age > 20 else 0
    external_obsolescence_pct = round(random.uniform(0, 5), 1) if random.random() > 0.6 else 0
    total_depreciation_pct = min(80, physical_depreciation_pct + functional_obsolescence_pct + external_obsolescence_pct)
    total_depreciation = round(replacement_cost_new * (total_depreciation_pct / 100), 2)
    depreciated_value = round(replacement_cost_new - total_depreciation, 2)

    lot_sqft = random.randint(3000, 25000)
    land_psf = land_value_per_sqft.get(property_type, random.uniform(10, 50))
    land_value = round(land_psf * lot_sqft, 2)

    site_improvements = round(random.uniform(5000, 40000), 2)

    total_value = round(depreciated_value + land_value + site_improvements, -3)

    return json.dumps({
        "property_type": property_type,
        "quality_grade": quality_grade,
        "sqft": sqft,
        "year_built": year_built,
        "replacement_cost_new": {
            "cost_per_sqft": round(construction_cost_psf, 2),
            "total_construction_cost": replacement_cost_new,
        },
        "depreciation": {
            "effective_age": effective_age,
            "useful_life": useful_life,
            "physical_depreciation_pct": physical_depreciation_pct,
            "functional_obsolescence_pct": functional_obsolescence_pct,
            "external_obsolescence_pct": external_obsolescence_pct,
            "total_depreciation_pct": total_depreciation_pct,
            "total_depreciation_amount": total_depreciation,
        },
        "depreciated_improvement_value": depreciated_value,
        "land_value": {
            "lot_sqft": lot_sqft,
            "price_per_sqft": round(land_psf, 2),
            "total_land_value": land_value,
        },
        "site_improvements": site_improvements,
        "total_estimated_value": total_value,
        "methodology": "Cost Approach - Replacement Cost Method",
        "disclaimer": "Cost approach estimates are most reliable for newer properties and unique structures. Market comparables may provide a more accurate value for typical residential properties.",
        "valuation_date": datetime.utcnow().isoformat() + "Z",
    })
