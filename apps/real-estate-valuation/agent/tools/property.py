from strands import tool
import json, random
from datetime import datetime, timedelta


@tool
def get_property_details(address: str) -> str:
    """Get comprehensive property details and records for an address.

    Retrieves full property information including physical characteristics,
    tax history, ownership records, and property features.

    Args:
        address: Full property address (e.g., '456 Oak Dr, Denver, CO 80202').

    Returns:
        JSON with beds, baths, sqft, lot, year, features, tax history, and ownership info.
    """
    beds = random.randint(2, 6)
    baths = random.randint(1, 5)
    sqft = random.randint(1000, 5000)
    lot_sqft = random.randint(3000, 30000)
    year_built = random.randint(1920, 2025)
    stories = random.choice([1, 1, 2, 2, 2, 3])
    garage_spaces = random.choice([0, 1, 2, 2, 3])

    assessed_value = random.randint(200000, 1500000)
    tax_rate = round(random.uniform(0.8, 2.5), 3)
    annual_tax = round(assessed_value * (tax_rate / 100), 2)

    tax_history = []
    value = assessed_value
    for yr in range(2025, 2020, -1):
        tax_history.append({
            "year": yr,
            "assessed_value": value,
            "tax_amount": round(value * (tax_rate / 100), 2),
            "change_pct": round(random.uniform(-3, 10), 1),
        })
        value = round(value / random.uniform(1.01, 1.08), 0)

    purchase_date = (datetime.utcnow() - timedelta(days=random.randint(365, 3650))).strftime("%Y-%m-%d")
    purchase_price = round(assessed_value * random.uniform(0.75, 1.15), 0)

    return json.dumps({
        "address": address,
        "property_type": random.choice(["Single Family", "Condo", "Townhouse", "Multi-Family"]),
        "status": random.choice(["Owner Occupied", "Rental", "Vacant", "Owner Occupied"]),
        "characteristics": {
            "bedrooms": beds,
            "bathrooms": baths,
            "sqft": sqft,
            "lot_sqft": lot_sqft,
            "year_built": year_built,
            "stories": stories,
            "garage_spaces": garage_spaces,
            "construction": random.choice(["Wood Frame", "Brick", "Stucco", "Stone", "Concrete Block"]),
            "roof_type": random.choice(["Asphalt Shingle", "Tile", "Metal", "Slate"]),
            "foundation": random.choice(["Slab", "Crawl Space", "Full Basement", "Partial Basement"]),
            "heating": random.choice(["Forced Air", "Radiant", "Heat Pump", "Baseboard"]),
            "cooling": random.choice(["Central AC", "Window Units", "Mini-Split", "None"]),
        },
        "features": random.sample([
            "Updated Kitchen", "Hardwood Floors", "Granite Countertops",
            "Stainless Steel Appliances", "In-Ground Pool", "Fireplace",
            "Deck/Patio", "Fenced Yard", "Central Vacuum", "Solar Panels",
            "Smart Home System", "Wine Cellar", "Home Office",
            "Walk-in Closets", "Crown Molding", "New Roof (2023)",
        ], k=random.randint(4, 8)),
        "tax_information": {
            "assessed_value": assessed_value,
            "tax_rate_pct": tax_rate,
            "annual_tax": annual_tax,
            "exemptions": random.sample(["Homestead", "Senior", "Veteran", "None"], k=1),
            "tax_history": tax_history,
        },
        "ownership": {
            "owner_name": "Property Owner (Redacted)",
            "ownership_type": random.choice(["Fee Simple", "Joint Tenancy", "Trust", "LLC"]),
            "purchase_date": purchase_date,
            "purchase_price": purchase_price,
            "mortgage_info": {
                "lender": random.choice(["Wells Fargo", "Chase", "Bank of America", "Local Credit Union", "None"]),
                "original_amount": round(purchase_price * random.uniform(0.7, 0.9), 0),
                "estimated_balance": round(purchase_price * random.uniform(0.3, 0.7), 0),
            },
        },
        "parcel_number": f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}",
        "legal_description": f"LOT {random.randint(1, 50)} BLK {random.randint(1, 20)} SUBDIVISION NAME",
        "last_updated": datetime.utcnow().isoformat() + "Z",
    })


@tool
def check_zoning(address: str) -> str:
    """Check zoning classification and permitted uses for a property.

    Retrieves the current zoning designation, allowed land uses, building
    restrictions, setback requirements, and any overlay districts.

    Args:
        address: Full property address to check zoning for.

    Returns:
        JSON with zoning classification, permitted uses, restrictions, and development potential.
    """
    zoning_codes = [
        ("R-1", "Single Family Residential"),
        ("R-2", "Two-Family Residential"),
        ("R-3", "Multi-Family Residential"),
        ("R-4", "High-Density Residential"),
        ("C-1", "Neighborhood Commercial"),
        ("C-2", "General Commercial"),
        ("MU", "Mixed Use"),
        ("PD", "Planned Development"),
    ]

    zone_code, zone_name = random.choice(zoning_codes)
    is_residential = zone_code.startswith("R")

    max_height = random.choice([35, 40, 45, 55, 75]) if is_residential else random.choice([45, 60, 85, 120])
    max_stories = max_height // random.randint(10, 15)
    far = round(random.uniform(0.3, 0.8), 2) if is_residential else round(random.uniform(1.0, 4.0), 2)
    lot_coverage = round(random.uniform(30, 60), 0) if is_residential else round(random.uniform(50, 85), 0)
    min_lot_size = random.choice([5000, 6000, 7500, 8000, 10000]) if is_residential else random.choice([3000, 5000, 10000])

    if is_residential:
        permitted = ["Single-family dwelling", "Home occupation", "Accessory dwelling unit (ADU)", "Community garden"]
        conditional = ["Day care center", "Bed and breakfast", "Religious institution", "Public utility"]
    else:
        permitted = ["Retail", "Restaurant", "Office", "Personal services", "Bank/Financial", "Medical office"]
        conditional = ["Auto repair", "Drive-through", "Liquor store", "Entertainment venue", "Gas station"]

    overlays = random.sample([
        "Historic Preservation District",
        "Flood Zone AE",
        "Transit Oriented Development (TOD)",
        "Design Review Overlay",
        "Hillside Protection",
        "None",
    ], k=1)

    return json.dumps({
        "address": address,
        "zoning": {
            "code": zone_code,
            "description": zone_name,
            "category": "Residential" if is_residential else "Commercial/Mixed Use",
        },
        "permitted_uses": permitted,
        "conditional_uses": conditional,
        "prohibited_uses": random.sample(["Heavy industrial", "Landfill", "Junkyard", "Adult entertainment", "Mining"], k=3),
        "development_standards": {
            "max_height_ft": max_height,
            "max_stories": max_stories,
            "floor_area_ratio": far,
            "max_lot_coverage_pct": lot_coverage,
            "min_lot_size_sqft": min_lot_size,
            "min_front_setback_ft": random.choice([15, 20, 25, 30]),
            "min_side_setback_ft": random.choice([5, 7, 10]),
            "min_rear_setback_ft": random.choice([15, 20, 25]),
            "parking_required": f"{random.choice([1, 1.5, 2])} spaces per unit" if is_residential else f"1 per {random.choice([200, 250, 300])} sqft",
        },
        "overlay_districts": overlays,
        "special_considerations": random.sample([
            "ADU permitted by right",
            "Short-term rental restrictions apply",
            "Design review required for new construction",
            "Environmental review may be required",
            "Historic facade preservation required",
            "No additional restrictions",
        ], k=random.randint(1, 3)),
        "development_potential": {
            "adu_eligible": random.choice([True, True, False]),
            "subdivision_potential": random.choice([True, False, False]),
            "upzoning_trend": random.choice(["Likely", "Possible", "Unlikely"]),
        },
        "last_updated": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_tax_assessment(address: str) -> str:
    """Get property tax assessment history, current taxes, and exemptions.

    Retrieves the assessed value breakdown, tax rate, historical assessments,
    applicable exemptions, and appeal information.

    Args:
        address: Full property address to look up tax assessment.

    Returns:
        JSON with current assessment, tax history, exemptions, and comparable assessments.
    """
    land_value = random.randint(80000, 600000)
    improvement_value = random.randint(150000, 1200000)
    total_assessed = land_value + improvement_value
    market_value = round(total_assessed * random.uniform(1.0, 1.25), 0)
    assessment_ratio = round((total_assessed / market_value) * 100, 1) if market_value > 0 else 100

    base_tax_rate = round(random.uniform(0.8, 2.5), 4)
    special_districts = round(random.uniform(0, 0.5), 4)
    total_tax_rate = round(base_tax_rate + special_districts, 4)
    gross_tax = round(total_assessed * (total_tax_rate / 100), 2)

    exemptions = []
    total_exemption = 0
    if random.random() > 0.4:
        homestead_amt = random.choice([25000, 40000, 50000, 75000])
        exemptions.append({"type": "Homestead", "amount": homestead_amt, "status": "Active"})
        total_exemption += homestead_amt
    if random.random() > 0.8:
        senior_amt = random.choice([10000, 25000, 50000])
        exemptions.append({"type": "Senior Citizen", "amount": senior_amt, "status": "Active"})
        total_exemption += senior_amt

    net_taxable = max(0, total_assessed - total_exemption)
    net_tax = round(net_taxable * (total_tax_rate / 100), 2)

    history = []
    hist_assessed = total_assessed
    for yr in range(2025, 2019, -1):
        change = round(random.uniform(-3, 10), 1)
        hist_tax = round(hist_assessed * (total_tax_rate / 100), 2)
        history.append({
            "year": yr,
            "assessed_value": hist_assessed,
            "tax_amount": hist_tax,
            "change_from_prior_pct": change,
        })
        hist_assessed = round(hist_assessed / (1 + change / 100), 0)

    tax_breakdown = {
        "school_district": round(net_tax * random.uniform(0.40, 0.55), 2),
        "county": round(net_tax * random.uniform(0.15, 0.25), 2),
        "city_municipality": round(net_tax * random.uniform(0.10, 0.20), 2),
        "special_districts": round(net_tax * random.uniform(0.05, 0.15), 2),
    }

    return json.dumps({
        "address": address,
        "current_assessment": {
            "tax_year": 2025,
            "land_value": land_value,
            "improvement_value": improvement_value,
            "total_assessed_value": total_assessed,
            "estimated_market_value": market_value,
            "assessment_ratio_pct": assessment_ratio,
        },
        "tax_calculation": {
            "base_tax_rate_pct": base_tax_rate,
            "special_district_rate_pct": special_districts,
            "total_tax_rate_pct": total_tax_rate,
            "gross_tax": gross_tax,
            "exemptions": exemptions,
            "total_exemption_amount": total_exemption,
            "net_taxable_value": net_taxable,
            "net_annual_tax": net_tax,
            "monthly_tax": round(net_tax / 12, 2),
        },
        "tax_breakdown_by_jurisdiction": tax_breakdown,
        "assessment_history": history,
        "appeal_info": {
            "appeal_deadline": f"2026-04-{random.randint(1, 30):02d}",
            "appeal_process": "File with County Board of Equalization within 30 days of notice",
            "estimated_success_rate_pct": round(random.uniform(25, 55), 0),
            "comparable_assessments": [
                {"address": f"{random.randint(100, 9999)} Nearby St", "assessed_value": round(total_assessed * random.uniform(0.85, 1.15), 0)},
                {"address": f"{random.randint(100, 9999)} Adjacent Ave", "assessed_value": round(total_assessed * random.uniform(0.80, 1.20), 0)},
            ],
        },
        "payment_schedule": {
            "installment_1": {"due_date": "2026-02-28", "amount": round(net_tax / 2, 2)},
            "installment_2": {"due_date": "2026-07-31", "amount": round(net_tax / 2, 2)},
        },
        "last_updated": datetime.utcnow().isoformat() + "Z",
    })


@tool
def search_properties(criteria: str) -> str:
    """Search for property listings matching specified criteria.

    Searches active listings and recent sales based on filters such as
    price range, bedrooms, bathrooms, property type, and location.

    Args:
        criteria: JSON string of search criteria. Format: {"min_price": 300000, "max_price": 600000, "beds_min": 3, "baths_min": 2, "zipcode": "78701", "property_type": "single_family"}.

    Returns:
        JSON with matching property listings, summary statistics, and pagination info.
    """
    try:
        filters = json.loads(criteria) if isinstance(criteria, str) else criteria
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON format for criteria."})

    min_price = filters.get("min_price", 200000)
    max_price = filters.get("max_price", 800000)
    beds_min = filters.get("beds_min", 2)
    baths_min = filters.get("baths_min", 1)
    zipcode = filters.get("zipcode", "00000")
    property_type = filters.get("property_type", "single_family")

    total_results = random.randint(8, 50)
    page_size = min(10, total_results)

    streets = ["Oak Dr", "Maple Ave", "Elm St", "Cedar Ln", "Pine Rd",
               "Birch Ct", "Walnut Way", "Spruce Blvd", "Willow Ct",
               "Magnolia Dr", "Hickory St", "Cherry Ln"]

    listings = []
    for i in range(page_size):
        price = random.randint(min_price, max_price)
        beds = beds_min + random.choice([0, 0, 1, 1, 2])
        baths = baths_min + random.choice([0, 0, 0, 1])
        sqft = random.randint(1000, 4000)
        lot_sqft = random.randint(3000, 20000)
        year_built = random.randint(1950, 2025)
        dom = random.randint(1, 90)

        status = random.choice(["Active", "Active", "Active", "Pending", "Coming Soon"])
        original_price = round(price * random.uniform(1.0, 1.1), 0) if random.random() > 0.5 else price
        price_reduced = original_price != price

        listings.append({
            "listing_id": f"MLS-{random.randint(10000000, 99999999)}",
            "address": f"{random.randint(100, 9999)} {random.choice(streets)}, {zipcode}",
            "list_price": price,
            "original_price": original_price,
            "price_reduced": price_reduced,
            "bedrooms": beds,
            "bathrooms": baths,
            "sqft": sqft,
            "lot_sqft": lot_sqft,
            "year_built": year_built,
            "property_type": property_type.replace("_", " ").title(),
            "status": status,
            "days_on_market": dom,
            "price_per_sqft": round(price / sqft, 2),
            "features": random.sample(["Garage", "Pool", "Updated Kitchen", "Hardwood",
                                        "Fireplace", "Deck", "New Roof", "Solar"], k=random.randint(2, 5)),
            "listing_date": (datetime.utcnow() - timedelta(days=dom)).strftime("%Y-%m-%d"),
        })

    listings.sort(key=lambda l: l["list_price"])

    prices = [l["list_price"] for l in listings]

    return json.dumps({
        "search_criteria": filters,
        "total_results": total_results,
        "page": 1,
        "page_size": page_size,
        "listings": listings,
        "summary": {
            "min_price": min(prices),
            "max_price": max(prices),
            "median_price": sorted(prices)[len(prices) // 2],
            "avg_price_per_sqft": round(sum(l["price_per_sqft"] for l in listings) / len(listings), 2),
            "avg_days_on_market": round(sum(l["days_on_market"] for l in listings) / len(listings), 0),
            "pct_with_price_reduction": round(sum(1 for l in listings if l["price_reduced"]) / len(listings) * 100, 1),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
