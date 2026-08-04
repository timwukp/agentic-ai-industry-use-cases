"""Gateway target: valuation — AVM, comparables, CMA report, cost approach.

Valuation data is a deterministic simulation seeded from the function inputs
(stable within a calendar day for date-relative fields).
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

STREETS = ["Oak Dr", "Maple Ave", "Elm St", "Cedar Ln", "Pine Rd", "Birch Ct",
           "Walnut Way", "Spruce Blvd", "Willow Ct", "Aspen Ln", "Magnolia Dr", "Hickory St"]

BASE_PPSF_RANGE = {
    "single_family": (180, 450),
    "condo": (200, 550),
    "townhouse": (190, 420),
    "multi_family": (150, 350),
    "land": (5, 50),
}

COST_PER_SQFT = {
    "economy": (80, 120),
    "standard": (120, 180),
    "good": (180, 260),
    "excellent": (260, 380),
    "luxury": (380, 600),
}

LAND_VALUE_PSF = {
    "single_family": (5, 50),
    "condo": (10, 80),
    "townhouse": (8, 60),
    "multi_family": (15, 70),
    "commercial": (20, 120),
}

AVM_DISCLAIMER = ("This is an automated valuation estimate. A formal appraisal by a "
                  "licensed appraiser is required for mortgage lending and legal purposes.")


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def estimate_property_value(address: str, property_type: str, bedrooms: int,
                            bathrooms: int, sqft: int, lot_sqft: int,
                            year_built: int) -> dict:
    property_type = property_type.lower()
    if property_type not in BASE_PPSF_RANGE:
        return tool_error(f"Invalid property_type: {property_type}",
                          valid=sorted(BASE_PPSF_RANGE))
    bedrooms, bathrooms = int(bedrooms), int(bathrooms)
    sqft, lot_sqft, year_built = int(sqft), int(lot_sqft), int(year_built)
    if sqft <= 0:
        return tool_error("sqft must be positive")

    today = _today()
    r = _rng("avm", address.lower(), property_type, bedrooms, bathrooms, sqft,
             lot_sqft, year_built)
    ppsf = r.uniform(*BASE_PPSF_RANGE[property_type])
    age = today.year - year_built
    age_adjustment = max(-0.15, -0.003 * age)
    bed_bath_adjustment = 0.02 * (bedrooms - 3) + 0.03 * (bathrooms - 2)
    lot_adjustment = 0.05 if lot_sqft > 8000 else -0.02 if lot_sqft < 4000 else 0.0
    adjusted_ppsf = ppsf * (1 + age_adjustment + bed_bath_adjustment + lot_adjustment)
    estimated_value = round(adjusted_ppsf * sqft, -3)

    comparables = []
    for _ in range(r.randint(4, 8)):
        comp_sqft = sqft + r.randint(-400, 400)
        comp_ppsf = adjusted_ppsf * r.uniform(0.88, 1.12)
        comparables.append({
            "address": f"{r.randint(100, 9999)} {r.choice(STREETS)}",
            "sale_price": round(comp_ppsf * comp_sqft, -3),
            "sale_date": (today - timedelta(days=r.randint(15, 180))).strftime("%Y-%m-%d"),
            "sqft": comp_sqft,
            "beds": bedrooms + r.choice([-1, 0, 0, 1]),
            "baths": bathrooms + r.choice([-1, 0, 0, 1]),
            "price_per_sqft": round(comp_ppsf, 2),
            "distance_miles": round(r.uniform(0.2, 2.5), 2),
        })

    return tool_ok({
        "address": address,
        "property_type": property_type,
        "subject_property": {
            "bedrooms": bedrooms, "bathrooms": bathrooms, "sqft": sqft,
            "lot_sqft": lot_sqft, "year_built": year_built,
        },
        "valuation": {
            "estimated_value": estimated_value,
            "confidence_low": round(estimated_value * r.uniform(0.90, 0.95), -3),
            "confidence_high": round(estimated_value * r.uniform(1.05, 1.12), -3),
            "confidence_score": round(r.uniform(75, 95), 1),
            "price_per_sqft": round(adjusted_ppsf, 2),
        },
        "methodology": {
            "primary": "Comparable Sales Approach",
            "comparables_used": len(comparables),
            "adjustments_applied": [
                {"factor": "Age/Condition", "adjustment_pct": round(age_adjustment * 100, 1)},
                {"factor": "Bed/Bath Count", "adjustment_pct": round(bed_bath_adjustment * 100, 1)},
                {"factor": "Lot Size", "adjustment_pct": round(lot_adjustment * 100, 1)},
            ],
        },
        "comparables": comparables,
        "disclaimer": AVM_DISCLAIMER,
    }, simulated=True)


def get_comparables(address: str, radius_miles: float = 1.0, max_results: int = 10) -> dict:
    radius_miles = max(0.1, float(radius_miles))
    max_results = min(max(1, int(max_results)), 20)
    today = _today()
    r = _rng("comparables", address.lower(), radius_miles, max_results)

    base_sqft = r.randint(1200, 3500)
    base_ppsf = r.uniform(180, 500)
    base_beds = r.randint(2, 5)
    base_baths = r.randint(1, 4)

    comparables = []
    for _ in range(max_results):
        comp_sqft = base_sqft + r.randint(-600, 600)
        comp_beds = max(1, base_beds + r.choice([-1, 0, 0, 0, 1]))
        comp_baths = max(1, base_baths + r.choice([-1, 0, 0, 1]))
        comp_ppsf = base_ppsf * r.uniform(0.85, 1.15)
        sale_price = round(comp_ppsf * comp_sqft, -3)
        days_ago = r.randint(10, 365)

        sqft_adj = round((base_sqft - comp_sqft) * base_ppsf * 0.5, 0)
        bed_adj = (base_beds - comp_beds) * r.randint(5000, 15000)
        bath_adj = (base_baths - comp_baths) * r.randint(8000, 20000)
        time_adj = round(sale_price * 0.003 * (days_ago / 30), 0)
        total_adj = sqft_adj + bed_adj + bath_adj + time_adj

        comparables.append({
            "address": f"{r.randint(100, 9999)} {r.choice(STREETS)}",
            "sale_price": sale_price,
            "adjusted_price": round(sale_price + total_adj, -3),
            "sale_date": (today - timedelta(days=days_ago)).strftime("%Y-%m-%d"),
            "days_on_market": r.randint(5, 120),
            "sqft": comp_sqft,
            "beds": comp_beds,
            "baths": comp_baths,
            "lot_sqft": r.randint(3000, 20000),
            "year_built": r.randint(1960, 2024),
            "price_per_sqft": round(comp_ppsf, 2),
            "distance_miles": round(r.uniform(0.1, radius_miles), 2),
            "property_type": r.choice(["single_family", "single_family", "condo", "townhouse"]),
            "adjustments": {
                "sqft": sqft_adj, "bedrooms": bed_adj, "bathrooms": bath_adj,
                "time": time_adj, "total": total_adj,
            },
            "similarity_score": round(r.uniform(70, 98), 1),
        })
    comparables.sort(key=lambda c: c["similarity_score"], reverse=True)

    prices = sorted(c["sale_price"] for c in comparables)
    adj_prices = sorted(c["adjusted_price"] for c in comparables)
    return tool_ok({
        "subject_address": address,
        "search_radius_miles": radius_miles,
        "total_found": len(comparables),
        "comparables": comparables,
        "summary": {
            "median_sale_price": prices[len(prices) // 2],
            "median_price_per_sqft": round(sum(c["price_per_sqft"] for c in comparables)
                                           / len(comparables), 2),
            "median_adjusted_price": adj_prices[len(adj_prices) // 2],
            "avg_days_on_market": round(sum(c["days_on_market"] for c in comparables)
                                        / len(comparables)),
        },
    }, simulated=True)


def generate_cma_report(address: str) -> dict:
    today = _today()
    r = _rng("cma", address.lower())
    beds, baths = r.randint(2, 5), r.randint(1, 4)
    sqft = r.randint(1200, 4000)
    lot_sqft = r.randint(3500, 25000)
    year_built = r.randint(1950, 2023)
    base_ppsf = r.uniform(200, 500)

    subject = {
        "address": address, "beds": beds, "baths": baths, "sqft": sqft,
        "lot_sqft": lot_sqft, "year_built": year_built,
        "property_type": "single_family",
        "condition": r.choice(["Excellent", "Good", "Average", "Fair"]),
        "features": r.sample(["Garage", "Pool", "Updated Kitchen", "Hardwood Floors",
                              "Central AC", "Fireplace", "Deck/Patio", "New Roof"],
                             k=r.randint(3, 6)),
    }

    comparables = []
    for i in range(5):
        c_sqft = sqft + r.randint(-500, 500)
        c_beds = max(1, beds + r.choice([-1, 0, 0, 1]))
        c_baths = max(1, baths + r.choice([-1, 0, 0, 1]))
        c_ppsf = base_ppsf * r.uniform(0.88, 1.12)
        c_price = round(c_ppsf * c_sqft, -3)
        c_lot = max(1000, lot_sqft + r.randint(-3000, 5000))
        adjustments = {
            "sqft": round((sqft - c_sqft) * base_ppsf * 0.5, 0),
            "bedrooms": (beds - c_beds) * r.randint(5000, 15000),
            "bathrooms": (baths - c_baths) * r.randint(8000, 20000),
            "lot_size": round((lot_sqft - c_lot) * r.uniform(1, 5), 0),
            "age": (year_built - r.randint(1950, 2023)) * r.randint(200, 800),
            "condition": r.choice([-10000, -5000, 0, 5000, 10000]),
            "features": r.randint(-15000, 15000),
        }
        total_adj = sum(adjustments.values())
        comparables.append({
            "comp_number": i + 1,
            "address": f"{r.randint(100, 9999)} {r.choice(STREETS)}",
            "sale_price": c_price,
            "sale_date": (today - timedelta(days=r.randint(10, 150))).strftime("%Y-%m-%d"),
            "status": r.choice(["Sold", "Sold", "Sold", "Pending"]),
            "sqft": c_sqft, "beds": c_beds, "baths": c_baths, "lot_sqft": c_lot,
            "price_per_sqft": round(c_ppsf, 2),
            "days_on_market": r.randint(5, 90),
            "adjustments": adjustments,
            "net_adjustment": total_adj,
            "adjusted_price": round(c_price + total_adj, -3),
        })

    adjusted_prices = [c["adjusted_price"] for c in comparables]
    value_indicated = round(sum(adjusted_prices) / len(adjusted_prices), -3)

    active_listings = [{
        "address": f"{r.randint(100, 9999)} {r.choice(STREETS)}",
        "list_price": round(base_ppsf * r.uniform(1.0, 1.15) * (sqft + r.randint(-400, 400)), -3),
        "sqft": sqft + r.randint(-400, 400),
        "beds": beds + r.choice([-1, 0, 1]),
        "baths": baths + r.choice([0, 0, 1]),
        "days_on_market": r.randint(1, 60),
    } for _ in range(3)]

    return tool_ok({
        "report_type": "Comparative Market Analysis",
        "subject_property": subject,
        "comparable_sales": comparables,
        "active_listings": active_listings,
        "value_conclusion": {
            "indicated_value_range": {"low": min(adjusted_prices), "high": max(adjusted_prices)},
            "reconciled_value": value_indicated,
            "price_per_sqft": round(value_indicated / sqft, 2),
            "confidence_level": r.choice(["High", "High", "Moderate"]),
        },
        "market_position": {
            "suggested_list_price": round(value_indicated * r.uniform(1.00, 1.05), -3),
            "competitive_price": round(value_indicated * 0.98, -3),
            "aspirational_price": round(value_indicated * 1.07, -3),
        },
        "prepared_date": today.strftime("%Y-%m-%d"),
        "disclaimer": ("This CMA is for informational purposes only. It is not a formal "
                       "appraisal. A licensed appraiser should be consulted for lending or "
                       "legal valuations."),
    }, simulated=True)


def calculate_replacement_cost(property_type: str, sqft: int, quality_grade: str,
                               year_built: int) -> dict:
    property_type, quality_grade = property_type.lower(), quality_grade.lower()
    if quality_grade not in COST_PER_SQFT:
        return tool_error(f"Invalid quality_grade: {quality_grade}",
                          valid=sorted(COST_PER_SQFT))
    if property_type not in LAND_VALUE_PSF:
        return tool_error(f"Invalid property_type: {property_type}",
                          valid=sorted(LAND_VALUE_PSF))
    sqft, year_built = int(sqft), int(year_built)
    if sqft <= 0:
        return tool_error("sqft must be positive")

    today = _today()
    r = _rng("cost_approach", property_type, sqft, quality_grade, year_built)
    construction_cost_psf = r.uniform(*COST_PER_SQFT[quality_grade])
    replacement_cost_new = round(construction_cost_psf * sqft, 2)

    age = max(0, today.year - year_built)
    effective_age = max(0, age - r.randint(0, min(10, age))) if age else 0
    useful_life = r.randint(50, 80)
    physical_pct = min(70, round(effective_age / useful_life * 100, 1))
    functional_pct = round(r.uniform(0, 8), 1) if age > 20 else 0
    external_pct = round(r.uniform(0, 5), 1) if r.random() > 0.6 else 0
    total_depr_pct = min(80, physical_pct + functional_pct + external_pct)
    total_depreciation = round(replacement_cost_new * total_depr_pct / 100, 2)
    depreciated_value = round(replacement_cost_new - total_depreciation, 2)

    lot_sqft = r.randint(3000, 25000)
    land_psf = r.uniform(*LAND_VALUE_PSF[property_type])
    land_value = round(land_psf * lot_sqft, 2)
    site_improvements = round(r.uniform(5000, 40000), 2)

    return tool_ok({
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
            "physical_depreciation_pct": physical_pct,
            "functional_obsolescence_pct": functional_pct,
            "external_obsolescence_pct": external_pct,
            "total_depreciation_pct": total_depr_pct,
            "total_depreciation_amount": total_depreciation,
        },
        "depreciated_improvement_value": depreciated_value,
        "land_value": {
            "lot_sqft": lot_sqft,
            "price_per_sqft": round(land_psf, 2),
            "total_land_value": land_value,
        },
        "site_improvements": site_improvements,
        "total_estimated_value": round(depreciated_value + land_value + site_improvements, -3),
        "methodology": "Cost Approach - Replacement Cost Method",
        "disclaimer": ("Cost approach estimates are most reliable for newer properties and "
                       "unique structures. Market comparables may provide a more accurate "
                       "value for typical residential properties."),
    }, simulated=True)


TOOLS = {
    "estimate_property_value": estimate_property_value,
    "get_comparables": get_comparables,
    "generate_cma_report": generate_cma_report,
    "calculate_replacement_cost": calculate_replacement_cost,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
