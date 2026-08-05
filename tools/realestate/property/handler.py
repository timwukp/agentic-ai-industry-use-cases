"""Gateway target: property — details, zoning, tax assessment, listing search.

Property data is a deterministic simulation seeded from the function inputs
(stable within a calendar day for date-relative fields).
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import (
    market_basis,
    property_basis,
    tool_ok,
    tool_error,
)
from toolkit.dispatch import dispatch
from toolkit.property_basis import STREETS
from toolkit.responses import parse_json_arg

ZONING_CODES = [
    ("R-1", "Single Family Residential"),
    ("R-2", "Two-Family Residential"),
    ("R-3", "Multi-Family Residential"),
    ("R-4", "High-Density Residential"),
    ("C-1", "Neighborhood Commercial"),
    ("C-2", "General Commercial"),
    ("MU", "Mixed Use"),
    ("PD", "Planned Development"),
]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def get_property_details(address: str) -> dict:
    today = _today()
    r = _rng("property_details", address.lower())
    age_year = today.year

    assessed_value = r.randint(200000, 1500000)
    tax_rate = round(r.uniform(0.8, 2.5), 3)

    tax_history = []
    value = assessed_value
    for yr in range(age_year - 1, age_year - 6, -1):
        tax_history.append(
            {
                "year": yr,
                "assessed_value": value,
                "tax_amount": round(value * tax_rate / 100, 2),
                "change_pct": round(r.uniform(-3, 10), 1),
            }
        )
        value = round(value / r.uniform(1.01, 1.08))

    purchase_price = round(assessed_value * r.uniform(0.75, 1.15))

    return tool_ok(
        {
            "address": address,
            "property_type": r.choice(
                ["Single Family", "Condo", "Townhouse", "Multi-Family"]
            ),
            "status": r.choice(
                ["Owner Occupied", "Rental", "Vacant", "Owner Occupied"]
            ),
            "characteristics": {
                "bedrooms": r.randint(2, 6),
                "bathrooms": r.randint(1, 5),
                "sqft": r.randint(1000, 5000),
                "lot_sqft": r.randint(3000, 30000),
                "year_built": r.randint(1920, age_year),
                "stories": r.choice([1, 1, 2, 2, 2, 3]),
                "garage_spaces": r.choice([0, 1, 2, 2, 3]),
                "construction": r.choice(
                    ["Wood Frame", "Brick", "Stucco", "Stone", "Concrete Block"]
                ),
                "roof_type": r.choice(["Asphalt Shingle", "Tile", "Metal", "Slate"]),
                "foundation": r.choice(
                    ["Slab", "Crawl Space", "Full Basement", "Partial Basement"]
                ),
                "heating": r.choice(
                    ["Forced Air", "Radiant", "Heat Pump", "Baseboard"]
                ),
                "cooling": r.choice(
                    ["Central AC", "Window Units", "Mini-Split", "None"]
                ),
            },
            "features": r.sample(
                [
                    "Updated Kitchen",
                    "Hardwood Floors",
                    "Granite Countertops",
                    "Stainless Steel Appliances",
                    "In-Ground Pool",
                    "Fireplace",
                    "Deck/Patio",
                    "Fenced Yard",
                    "Solar Panels",
                    "Smart Home System",
                    "Home Office",
                    "Walk-in Closets",
                ],
                k=r.randint(4, 8),
            ),
            "tax_information": {
                "assessed_value": assessed_value,
                "tax_rate_pct": tax_rate,
                "annual_tax": round(assessed_value * tax_rate / 100, 2),
                "exemptions": [r.choice(["Homestead", "Senior", "Veteran", "None"])],
                "tax_history": tax_history,
            },
            "ownership": {
                "owner_name": "Property Owner (Redacted)",
                "ownership_type": r.choice(
                    ["Fee Simple", "Joint Tenancy", "Trust", "LLC"]
                ),
                "purchase_date": (
                    today - timedelta(days=r.randint(365, 3650))
                ).strftime("%Y-%m-%d"),
                "purchase_price": purchase_price,
            },
            "parcel_number": f"{r.randint(100, 999)}-{r.randint(10, 99)}-{r.randint(1000, 9999)}",
            "legal_description": f"LOT {r.randint(1, 50)} BLK {r.randint(1, 20)} SUBDIVISION NAME",
        },
        simulated=True,
    )


def check_zoning(address: str) -> dict:
    r = _rng("zoning", address.lower())
    zone_code, zone_name = r.choice(ZONING_CODES)
    is_residential = zone_code.startswith("R")

    max_height = (
        r.choice([35, 40, 45, 55, 75])
        if is_residential
        else r.choice([45, 60, 85, 120])
    )

    if is_residential:
        permitted = [
            "Single-family dwelling",
            "Home occupation",
            "Accessory dwelling unit (ADU)",
            "Community garden",
        ]
        conditional = [
            "Day care center",
            "Bed and breakfast",
            "Religious institution",
            "Public utility",
        ]
    else:
        permitted = [
            "Retail",
            "Restaurant",
            "Office",
            "Personal services",
            "Bank/Financial",
            "Medical office",
        ]
        conditional = [
            "Auto repair",
            "Drive-through",
            "Liquor store",
            "Entertainment venue",
            "Gas station",
        ]

    return tool_ok(
        {
            "address": address,
            "zoning": {
                "code": zone_code,
                "description": zone_name,
                "category": "Residential" if is_residential else "Commercial/Mixed Use",
            },
            "permitted_uses": permitted,
            "conditional_uses": conditional,
            "prohibited_uses": r.sample(
                [
                    "Heavy industrial",
                    "Landfill",
                    "Junkyard",
                    "Adult entertainment",
                    "Mining",
                ],
                k=3,
            ),
            "development_standards": {
                "max_height_ft": max_height,
                "max_stories": max_height // r.randint(10, 15),
                "floor_area_ratio": (
                    round(r.uniform(0.3, 0.8), 2)
                    if is_residential
                    else round(r.uniform(1.0, 4.0), 2)
                ),
                "max_lot_coverage_pct": (
                    round(r.uniform(30, 60))
                    if is_residential
                    else round(r.uniform(50, 85))
                ),
                "min_lot_size_sqft": (
                    r.choice([5000, 6000, 7500, 8000, 10000])
                    if is_residential
                    else r.choice([3000, 5000, 10000])
                ),
                "min_front_setback_ft": r.choice([15, 20, 25, 30]),
                "min_side_setback_ft": r.choice([5, 7, 10]),
                "min_rear_setback_ft": r.choice([15, 20, 25]),
                "parking_required": (
                    f"{r.choice([1, 1.5, 2])} spaces per unit"
                    if is_residential
                    else f"1 per {r.choice([200, 250, 300])} sqft"
                ),
            },
            "overlay_districts": [
                r.choice(
                    [
                        "Historic Preservation District",
                        "Flood Zone AE",
                        "Transit Oriented Development (TOD)",
                        "Design Review Overlay",
                        "Hillside Protection",
                        "None",
                    ]
                )
            ],
            "special_considerations": r.sample(
                [
                    "ADU permitted by right",
                    "Short-term rental restrictions apply",
                    "Design review required for new construction",
                    "Environmental review may be required",
                    "Historic facade preservation required",
                    "No additional restrictions",
                ],
                k=r.randint(1, 3),
            ),
            "development_potential": {
                "adu_eligible": r.choice([True, True, False]),
                "subdivision_potential": r.choice([True, False, False]),
                "upzoning_trend": r.choice(["Likely", "Possible", "Unlikely"]),
            },
        },
        simulated=True,
    )


def get_tax_assessment(address: str) -> dict:
    today = _today()
    r = _rng("tax_assessment", address.lower())
    tax_year = today.year - 1

    land_value = r.randint(80000, 600000)
    improvement_value = r.randint(150000, 1200000)
    total_assessed = land_value + improvement_value
    market_value = round(total_assessed * r.uniform(1.0, 1.25))

    base_tax_rate = round(r.uniform(0.8, 2.5), 4)
    special_districts = round(r.uniform(0, 0.5), 4)
    total_tax_rate = round(base_tax_rate + special_districts, 4)
    gross_tax = round(total_assessed * total_tax_rate / 100, 2)

    exemptions = []
    total_exemption = 0
    if r.random() > 0.4:
        amt = r.choice([25000, 40000, 50000, 75000])
        exemptions.append({"type": "Homestead", "amount": amt, "status": "Active"})
        total_exemption += amt
    if r.random() > 0.8:
        amt = r.choice([10000, 25000, 50000])
        exemptions.append({"type": "Senior Citizen", "amount": amt, "status": "Active"})
        total_exemption += amt

    net_taxable = max(0, total_assessed - total_exemption)
    net_tax = round(net_taxable * total_tax_rate / 100, 2)

    history = []
    hist_assessed = total_assessed
    for yr in range(tax_year, tax_year - 6, -1):
        change = round(r.uniform(-3, 10), 1)
        history.append(
            {
                "year": yr,
                "assessed_value": hist_assessed,
                "tax_amount": round(hist_assessed * total_tax_rate / 100, 2),
                "change_from_prior_pct": change,
            }
        )
        hist_assessed = round(hist_assessed / (1 + change / 100))

    return tool_ok(
        {
            "address": address,
            "current_assessment": {
                "tax_year": tax_year,
                "land_value": land_value,
                "improvement_value": improvement_value,
                "total_assessed_value": total_assessed,
                "estimated_market_value": market_value,
                "assessment_ratio_pct": round(total_assessed / market_value * 100, 1),
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
            "tax_breakdown_by_jurisdiction": {
                "school_district": round(net_tax * 0.48, 2),
                "county": round(net_tax * 0.20, 2),
                "city_municipality": round(net_tax * 0.15, 2),
                "special_districts": round(net_tax * 0.10, 2),
            },
            "assessment_history": history,
            "appeal_info": {
                "appeal_deadline": f"{today.year}-04-{r.randint(1, 30):02d}",
                "appeal_process": "File with County Board of Equalization within 30 days of notice",
                "estimated_success_rate_pct": round(r.uniform(25, 55)),
                "comparable_assessments": [
                    {
                        "address": f"{r.randint(100, 9999)} Nearby St",
                        "assessed_value": round(total_assessed * r.uniform(0.85, 1.15)),
                    },
                    {
                        "address": f"{r.randint(100, 9999)} Adjacent Ave",
                        "assessed_value": round(total_assessed * r.uniform(0.80, 1.20)),
                    },
                ],
            },
            "payment_schedule": {
                "installment_1": {
                    "due_date": f"{today.year}-02-28",
                    "amount": round(net_tax / 2, 2),
                },
                "installment_2": {
                    "due_date": f"{today.year}-07-31",
                    "amount": round(net_tax / 2, 2),
                },
            },
        },
        simulated=True,
    )


def search_properties(criteria: str) -> dict:
    filters, err = parse_json_arg(criteria, "criteria")
    if err:
        return tool_error(err)
    if not isinstance(filters, dict):
        return tool_error("criteria must be a JSON object of search filters")

    beds_min = int(filters.get("beds_min", 2))
    baths_min = int(filters.get("baths_min", 1))
    zipcode = str(filters.get("zipcode", "00000"))
    property_type = str(filters.get("property_type", "single_family"))
    today = _today()
    market = market_basis(zipcode, today.strftime("%Y-%m"))

    # Default the price window to this market's own range rather than a flat
    # $200K-$800K. Priced in-market, a $900K-median zipcode matched nothing
    # against that fixed window and the page came back empty on a dashboard whose
    # market tile said 340 homes were for sale.
    min_price = int(filters.get("min_price", round(market.median_price * 0.4)))
    max_price = int(filters.get("max_price", round(market.median_price * 2.0)))
    if min_price > max_price:
        return tool_error("min_price cannot exceed max_price")

    r = _rng(
        "search_properties",
        min_price,
        max_price,
        beds_min,
        baths_min,
        zipcode,
        property_type,
        today.strftime("%Y-%m-%d"),
    )
    page_size = 10

    listings = []
    examined = 0
    # bounded: narrow filters may admit nothing, and an empty page is a valid
    # answer — never spin looking for a match that cannot exist
    for _ in range(page_size * 60):
        if len(listings) == page_size:
            break
        examined += 1
        # Size, rooms and price come from the address-keyed shared basis, so a
        # listing's price agrees with the comps and details routes for the same
        # address. Only listing-specific facts (status, DOM, price cut) are
        # drawn here. See toolkit.property_basis.
        address = f"{r.randint(100, 9999)} {r.choice(STREETS)}, {zipcode}"
        basis = property_basis(
            address, current_year=today.year, market_ppsf=market.median_ppsf
        )
        # the basis is address-derived, so honour the caller's filters by
        # rejecting properties that don't match rather than by overwriting them
        if not min_price <= basis.value <= max_price:
            continue
        if basis.beds < beds_min or basis.baths < baths_min:
            continue
        price = basis.value
        sqft = basis.sqft
        # Days on market centre on the market's own average, so a 1.6-month
        # seller's market does not list homes sitting 88 days unsold. Drawn over
        # (1, 90) it did, beneath a tile reading "26 day average".
        dom = max(1, round(market.average_dom * r.uniform(0.3, 1.8)))
        # A price cut is what a listing that has sat does. Flipped on a coin
        # regardless of DOM, a home listed 3 days ago showed a reduction while
        # the market's own price-cut share said 18%.
        cut_odds = min(0.75, dom / max(1, market.average_dom) * 0.35)
        original_price = (
            round(price * r.uniform(1.02, 1.12)) if r.random() < cut_odds else price
        )
        listings.append(
            {
                "listing_id": f"MLS-{r.randint(10000000, 99999999)}",
                "address": address,
                "list_price": price,
                "original_price": original_price,
                "price_reduced": original_price != price,
                "bedrooms": basis.beds,
                "bathrooms": basis.baths,
                "sqft": sqft,
                "lot_sqft": basis.lot_sqft,
                "year_built": basis.year_built,
                "property_type": property_type.replace("_", " ").title(),
                "status": r.choice(
                    ["Active", "Active", "Active", "Pending", "Coming Soon"]
                ),
                "days_on_market": dom,
                "price_per_sqft": round(price / sqft, 2),
                "features": r.sample(
                    [
                        "Garage",
                        "Pool",
                        "Updated Kitchen",
                        "Hardwood",
                        "Fireplace",
                        "Deck",
                        "New Roof",
                        "Solar",
                    ],
                    k=r.randint(2, 5),
                ),
                "listing_date": (today - timedelta(days=dom)).strftime("%Y-%m-%d"),
            }
        )
    listings.sort(key=lambda x: x["list_price"])
    prices = [x["list_price"] for x in listings]

    # The total is the market's active inventory scaled by the share of sampled
    # addresses these filters actually admitted — so a filter that rejected 9 in
    # 10 candidates cannot report the whole market as matching. Drawn as
    # randint(8, 50) it claimed 41 matches on a market with 12 homes for sale,
    # and reported a full page of results while the page held none.
    hit_rate = len(listings) / examined if examined else 0.0
    total_results = max(len(listings), round(market.active_listings * hit_rate))

    # An empty page is a valid answer for narrow filters — the loop above says so
    # — but min(prices) on it raises ValueError, so the route 500'd instead of
    # returning "no listings match". A `min_price` above the market's top end
    # reproduced it.
    summary = (
        {
            "min_price": min(prices),
            "max_price": max(prices),
            "median_price": sorted(prices)[len(prices) // 2],
            "avg_price_per_sqft": round(
                sum(x["price_per_sqft"] for x in listings) / len(listings), 2
            ),
            "avg_days_on_market": round(
                sum(x["days_on_market"] for x in listings) / len(listings)
            ),
            "pct_with_price_reduction": round(
                sum(1 for x in listings if x["price_reduced"]) / len(listings) * 100,
                1,
            ),
        }
        if listings
        else {
            "min_price": None,
            "max_price": None,
            "median_price": None,
            "avg_price_per_sqft": None,
            "avg_days_on_market": None,
            "pct_with_price_reduction": None,
        }
    )

    return tool_ok(
        {
            "search_criteria": filters,
            "zipcode": zipcode,
            # What the market carries in total, so "12 of 41 matching" reads
            # against a number the market tile also reports.
            "market_active_listings": market.active_listings,
            "market_median_price": market.median_price,
            "market_median_price_per_sqft": market.median_ppsf,
            "total_results": total_results,
            "page": 1,
            "page_size": page_size,
            "listings": listings,
            "summary": summary,
        },
        simulated=True,
    )


TOOLS = {
    "get_property_details": get_property_details,
    "check_zoning": check_zoning,
    "get_tax_assessment": get_tax_assessment,
    "search_properties": search_properties,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
