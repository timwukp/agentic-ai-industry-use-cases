"""Gateway target: valuation — AVM, comparables, CMA report, cost approach.

Valuation data is a deterministic simulation seeded from the function inputs
(stable within a calendar day for date-relative fields).
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import (
    market_basis,
    property_basis,
    rooms_for_sqft,
    round_price,
    tool_ok,
    tool_error,
    zipcode_of,
)
from toolkit.dispatch import dispatch
from toolkit.property_basis import STREETS

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

AVM_DISCLAIMER = (
    "This is an automated valuation estimate. A formal appraisal by a "
    "licensed appraiser is required for mortgage lending and legal purposes."
)


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def _subject(address: str, today: datetime):
    """The subject property, priced in its own market when the address names one.

    Listings carry their zipcode ("1234 Oak Dr, 78701"), so comps for a subject
    picked off the listings table are priced against the same market the listing
    was. Without this, a $421/sqft market produced comps at $205/sqft and the
    indicated value came in at half the asking price on the row above.
    """
    zipcode = zipcode_of(address)
    ppsf = (
        market_basis(zipcode, today.strftime("%Y-%m")).median_ppsf if zipcode else None
    )
    return property_basis(address, current_year=today.year, market_ppsf=ppsf)


def _similarity(subject, comp_sqft, comp_beds, comp_baths, days_ago, distance) -> float:
    """How close a comparable is to the subject, as a 0-100 score.

    Penalties are the four things an appraiser adjusts for: floor area, room
    count, how stale the sale is and how far away it is. A comp matching on
    every dimension scores ~98; one 25% off on size, two rooms out and a year
    old lands in the 60s.
    """
    size_penalty = abs(comp_sqft - subject.sqft) / subject.sqft * 60
    room_penalty = (abs(comp_beds - subject.beds) + abs(comp_baths - subject.baths)) * 3
    recency_penalty = days_ago / 365 * 8
    distance_penalty = min(6.0, distance * 3)
    score = 98 - size_penalty - room_penalty - recency_penalty - distance_penalty
    return round(min(99.0, max(35.0, score)), 1)


def estimate_property_value(
    address: str,
    property_type: str,
    bedrooms: int,
    bathrooms: int,
    sqft: int,
    lot_sqft: int,
    year_built: int,
) -> dict:
    property_type = property_type.lower()
    if property_type not in BASE_PPSF_RANGE:
        return tool_error(
            f"Invalid property_type: {property_type}", valid=sorted(BASE_PPSF_RANGE)
        )
    bedrooms, bathrooms = int(bedrooms), int(bathrooms)
    sqft, lot_sqft, year_built = int(sqft), int(lot_sqft), int(year_built)
    if sqft <= 0:
        return tool_error("sqft must be positive")

    today = _today()
    r = _rng(
        "avm",
        address.lower(),
        property_type,
        bedrooms,
        bathrooms,
        sqft,
        lot_sqft,
        year_built,
    )
    # The caller supplies the physical property, so only the price level is ours
    # to decide — and it belongs to the market the address sits in. Drawn from
    # BASE_PPSF_RANGE regardless of address, this AVM valued a listing at
    # $205/sqft in a market whose own tile read $421/sqft, and the comps route
    # for the same address disagreed with it by a factor of two. The type range
    # remains the fallback for an address that names no market, and scales the
    # market level for types that trade off it (a condo above, land far below).
    # Taken from the address's own basis, not re-drawn around the market median.
    # A second draw around the same market is still a second draw: it put this
    # AVM at $394/sqft while the comps route, drawing low around the same
    # $330/sqft market, described the same address at $277 — a 43% disagreement
    # on one house. The type factor scales that level for property types that
    # trade off single-family (a condo above it, land far below).
    type_low, type_high = BASE_PPSF_RANGE[property_type]
    if zipcode_of(address):
        sf_low, sf_high = BASE_PPSF_RANGE["single_family"]
        ppsf = (
            _subject(address, today).price_per_sqft
            * (type_low + type_high)
            / (sf_low + sf_high)
        )
    else:
        ppsf = r.uniform(type_low, type_high)
    age = today.year - year_built
    age_adjustment = max(-0.15, -0.003 * age)
    bed_bath_adjustment = 0.02 * (bedrooms - 3) + 0.03 * (bathrooms - 2)
    lot_adjustment = 0.05 if lot_sqft > 8000 else -0.02 if lot_sqft < 4000 else 0.0
    adjusted_ppsf = ppsf * (1 + age_adjustment + bed_bath_adjustment + lot_adjustment)
    estimated_value = round_price(adjusted_ppsf * sqft)

    comparables = []
    for _ in range(r.randint(4, 8)):
        # Sized within a quarter of the subject, with room counts derived from
        # each comp's own floor area — a flat +/-400 sqft window on a 1,200 sqft
        # subject produced an 800 sqft comp still carrying the subject's 4 beds.
        span = min(400, max(120, int(sqft * 0.25)))
        comp_sqft = max(300, sqft + r.randint(-span, span))
        comp_beds, comp_baths = rooms_for_sqft(comp_sqft, r)
        comp_ppsf = adjusted_ppsf * r.uniform(0.88, 1.12)
        comparables.append(
            {
                "address": f"{r.randint(100, 9999)} {r.choice(STREETS)}",
                "sale_price": round_price(comp_ppsf * comp_sqft),
                "sale_date": (today - timedelta(days=r.randint(15, 180))).strftime(
                    "%Y-%m-%d"
                ),
                "sqft": comp_sqft,
                "beds": comp_beds,
                "baths": comp_baths,
                "price_per_sqft": round(comp_ppsf, 2),
                "distance_miles": round(r.uniform(0.2, 2.5), 2),
            }
        )

    # Confidence is what the comp set supports: more comps, tighter spread of
    # their per-sqft prices, higher score — and the band is that same dispersion.
    # Drawn independently, the card showed "94.1% confidence" above a
    # +12%/-10% range, and the range was sometimes narrower on 4 comps than on 8.
    comp_ppsfs = [c["price_per_sqft"] for c in comparables]
    dispersion = (max(comp_ppsfs) - min(comp_ppsfs)) / (
        sum(comp_ppsfs) / len(comp_ppsfs)
    )
    spread = round(min(0.14, max(0.03, dispersion / 2 + 0.08 / len(comparables))), 3)
    # Mapped onto the range `spread` actually reaches, measured over 400 addresses:
    # 0.047 to 0.137. A textbook `98 - spread * 260` put every property between
    # 62 and 85 and never once said "high confidence"; this spans 63-94 across
    # the same inputs. The same trap as the supplier rating bands.
    confidence_score = round(min(95.0, max(60.0, 95 - (spread - 0.045) * 347)), 1)

    return tool_ok(
        {
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
                "confidence_low": round_price(estimated_value * (1 - spread)),
                "confidence_high": round_price(estimated_value * (1 + spread)),
                "confidence_score": confidence_score,
                "price_per_sqft": round(adjusted_ppsf, 2),
            },
            "methodology": {
                "primary": "Comparable Sales Approach",
                "comparables_used": len(comparables),
                "adjustments_applied": [
                    {
                        "factor": "Age/Condition",
                        "adjustment_pct": round(age_adjustment * 100, 1),
                    },
                    {
                        "factor": "Bed/Bath Count",
                        "adjustment_pct": round(bed_bath_adjustment * 100, 1),
                    },
                    {
                        "factor": "Lot Size",
                        "adjustment_pct": round(lot_adjustment * 100, 1),
                    },
                ],
            },
            "comparables": comparables,
            "disclaimer": AVM_DISCLAIMER,
        },
        simulated=True,
    )


def get_comparables(
    address: str, radius_miles: float = 1.0, max_results: int = 10
) -> dict:
    radius_miles = max(0.1, float(radius_miles))
    max_results = min(max(1, int(max_results)), 20)
    today = _today()
    r = _rng("comparables", address.lower(), radius_miles, max_results)

    # The subject's size and price basis come from the shared address-keyed
    # basis, priced in the market the address sits in, so comps bracket the same
    # value the listings route shows for this address instead of an
    # independently invented one.
    subject = _subject(address, today)
    base_sqft = subject.sqft
    base_ppsf = subject.price_per_sqft
    base_beds = subject.beds
    base_baths = subject.baths

    comparables = []
    for _ in range(max_results):
        # A comp must be size-plausible against the subject. A flat +/-600 sqft
        # window let a 1,229 sqft subject be compared to a 635 sqft property —
        # half the size, and it then carried a +$98K size adjustment, which an
        # appraiser would never accept. Scale the window (+/-25%, capped) and
        # derive room counts from the comp's own size so a 635 sqft "3 bed"
        # cannot occur.
        span = min(600, max(150, int(base_sqft * 0.25)))
        comp_sqft = base_sqft + r.randint(-span, span)
        comp_beds, comp_baths = rooms_for_sqft(comp_sqft, r)
        comp_ppsf = base_ppsf * r.uniform(0.85, 1.15)
        sale_price = round_price(comp_ppsf * comp_sqft)
        days_ago = r.randint(10, 365)
        distance = round(r.uniform(0.1, radius_miles), 2)

        sqft_adj = int(round((base_sqft - comp_sqft) * base_ppsf * 0.5))
        bed_adj = (base_beds - comp_beds) * r.randint(5000, 15000)
        bath_adj = (base_baths - comp_baths) * r.randint(8000, 20000)
        time_adj = int(round(sale_price * 0.003 * (days_ago / 30)))
        total_adj = sqft_adj + bed_adj + bath_adj + time_adj

        comparables.append(
            {
                "address": f"{r.randint(100, 9999)} {r.choice(STREETS)}",
                "sale_price": sale_price,
                "adjusted_price": round_price(sale_price + total_adj),
                "sale_date": (today - timedelta(days=days_ago)).strftime("%Y-%m-%d"),
                "days_on_market": r.randint(5, 120),
                "sqft": comp_sqft,
                "beds": comp_beds,
                "baths": comp_baths,
                "lot_sqft": r.randint(3000, 20000),
                "year_built": r.randint(1960, 2024),
                "price_per_sqft": round(comp_ppsf, 2),
                "distance_miles": distance,
                "property_type": r.choice(
                    ["single_family", "single_family", "condo", "townhouse"]
                ),
                "adjustments": {
                    "sqft": sqft_adj,
                    "bedrooms": bed_adj,
                    "bathrooms": bath_adj,
                    "time": time_adj,
                    "total": total_adj,
                },
                # Similarity is how close this comp actually is to the subject —
                # size, rooms, recency and distance. Drawn over (70, 98) it
                # awarded 96% to the comp with the largest adjustments in the
                # table and 72% to the one that matched on every dimension, which
                # is visible at a glance since the table sorts by it.
                "similarity_score": _similarity(
                    subject, comp_sqft, comp_beds, comp_baths, days_ago, distance
                ),
            }
        )
    comparables.sort(key=lambda c: c["similarity_score"], reverse=True)

    prices = sorted(c["sale_price"] for c in comparables)
    adj_prices = sorted(c["adjusted_price"] for c in comparables)
    return tool_ok(
        {
            "subject_address": address,
            # The subject the adjustments are measured against — the dashboard
            # showed an "Indicated Value" with nothing on screen saying what
            # property it was the value of.
            "subject_property": {
                "sqft": subject.sqft,
                "beds": subject.beds,
                "baths": subject.baths,
                "year_built": subject.year_built,
                "price_per_sqft": subject.price_per_sqft,
                "indicated_value": subject.value,
            },
            "search_radius_miles": radius_miles,
            "total_found": len(comparables),
            "comparables": comparables,
            "summary": {
                "median_sale_price": prices[len(prices) // 2],
                # The median of the rates in the table, not their mean: the field
                # is named median and the dashboard tile is labelled "Median
                # $/Sq Ft", so a mean here put a number in that tile that no
                # ordering of the six rows beneath it produces — up to $24/sqft
                # away from the true median across 200 addresses.
                "median_price_per_sqft": sorted(
                    c["price_per_sqft"] for c in comparables
                )[len(comparables) // 2],
                "median_adjusted_price": adj_prices[len(adj_prices) // 2],
                "avg_days_on_market": round(
                    sum(c["days_on_market"] for c in comparables) / len(comparables)
                ),
            },
        },
        simulated=True,
    )


def generate_cma_report(address: str) -> dict:
    today = _today()
    r = _rng("cma", address.lower())

    # The subject is the shared basis, not a seventh independent invention of the
    # same address. This route drew its own beds/baths/sqft/lot/year/ppsf, so a
    # CMA reconciled a 3,410 sqft subject at $612K while the comps route
    # described the same address as 1,229 sqft and the listings table priced it
    # at $340K. A CMA that disagrees with the listing it is written for is the
    # one document in this industry that must not.
    basis = _subject(address, today)
    beds, baths = basis.beds, basis.baths
    sqft = basis.sqft
    lot_sqft = basis.lot_sqft
    year_built = basis.year_built
    base_ppsf = basis.price_per_sqft

    # Condition tracks age, since a 1954 house rated "Excellent" beside a 2021
    # one rated "Fair" is the kind of pairing a reviewer stops on. Rank order is
    # kept so a comp's condition adjustment can be signed against the subject's.
    CONDITIONS = ("Fair", "Average", "Good", "Excellent")
    age = max(0, today.year - year_built)
    subject_rank = min(3, max(0, 3 - age // 22 + r.choice([-1, 0, 0, 1])))
    subject_condition = CONDITIONS[subject_rank]

    subject = {
        "address": address,
        "beds": beds,
        "baths": baths,
        "sqft": sqft,
        "lot_sqft": lot_sqft,
        "year_built": year_built,
        "property_type": basis.property_type,
        "condition": subject_condition,
        "features": r.sample(
            [
                "Garage",
                "Pool",
                "Updated Kitchen",
                "Hardwood Floors",
                "Central AC",
                "Fireplace",
                "Deck/Patio",
                "New Roof",
            ],
            k=r.randint(3, 6),
        ),
    }

    comparables = []
    for i in range(5):
        span = min(500, max(150, int(sqft * 0.25)))
        c_sqft = max(300, sqft + r.randint(-span, span))
        # Derived from the comp's own floor area, so the size adjustment and the
        # room adjustment tell the same story about the same house.
        c_beds, c_baths = rooms_for_sqft(c_sqft, r)
        c_ppsf = base_ppsf * r.uniform(0.88, 1.12)
        c_price = round_price(c_ppsf * c_sqft)
        c_lot = max(1000, lot_sqft + r.randint(-3000, 5000))
        c_year = min(today.year, max(1950, year_built + r.randint(-25, 15)))
        c_age = max(0, today.year - c_year)
        c_rank = min(3, max(0, 3 - c_age // 22 + r.choice([-1, 0, 0, 1])))
        adjustments = {
            "sqft": int(round((sqft - c_sqft) * base_ppsf * 0.5)),
            "bedrooms": (beds - c_beds) * r.randint(5000, 15000),
            "bathrooms": (baths - c_baths) * r.randint(8000, 20000),
            "lot_size": int(round((lot_sqft - c_lot) * r.uniform(1, 5))),
            # Against this comp's own year_built, which the row displays. Drawn
            # against an unrelated randint(1950, 2023), a 2019 comp listed beside
            # a 1962 subject collected a +$14K age adjustment — the wrong sign
            # against the two dates printed in its own row.
            "age": (year_built - c_year) * r.randint(200, 800),
            # Signed the same way: the subject being in better condition than the
            # comp adds value to the comp's price, not a free +/-$10K.
            "condition": (subject_rank - c_rank) * r.randint(4000, 9000),
            "features": r.randint(-15000, 15000),
        }
        total_adj = sum(adjustments.values())
        comparables.append(
            {
                "comp_number": i + 1,
                "address": f"{r.randint(100, 9999)} {r.choice(STREETS)}",
                "sale_price": c_price,
                "sale_date": (today - timedelta(days=r.randint(10, 150))).strftime(
                    "%Y-%m-%d"
                ),
                "status": r.choice(["Sold", "Sold", "Sold", "Pending"]),
                "sqft": c_sqft,
                "beds": c_beds,
                "baths": c_baths,
                "lot_sqft": c_lot,
                "year_built": c_year,
                "condition": CONDITIONS[c_rank],
                "price_per_sqft": round(c_ppsf, 2),
                "days_on_market": r.randint(5, 90),
                "adjustments": adjustments,
                "net_adjustment": total_adj,
                "adjusted_price": round_price(c_price + total_adj),
            }
        )

    adjusted_prices = [c["adjusted_price"] for c in comparables]
    value_indicated = round_price(sum(adjusted_prices) / len(adjusted_prices))
    adj_spread_pct = round(
        (max(adjusted_prices) - min(adjusted_prices)) / value_indicated * 100, 1
    )

    # One size per listing, priced off that size. Two independent +/-400 draws
    # gave a row reading "1,412 sqft — $684,000" at a stated $312/sqft, because
    # the price was computed from a floor area the row never showed.
    active_listings = []
    for _ in range(3):
        l_sqft = max(300, sqft + r.randint(-400, 400))
        l_beds, l_baths = rooms_for_sqft(l_sqft, r)
        active_listings.append(
            {
                "address": f"{r.randint(100, 9999)} {r.choice(STREETS)}",
                "list_price": round_price(base_ppsf * r.uniform(1.0, 1.15) * l_sqft),
                "sqft": l_sqft,
                "beds": l_beds,
                "baths": l_baths,
                "days_on_market": r.randint(1, 60),
            }
        )

    return tool_ok(
        {
            "report_type": "Comparative Market Analysis",
            "subject_property": subject,
            "comparable_sales": comparables,
            "active_listings": active_listings,
            "value_conclusion": {
                "indicated_value_range": {
                    "low": min(adjusted_prices),
                    "high": max(adjusted_prices),
                },
                "reconciled_value": value_indicated,
                "price_per_sqft": round(value_indicated / sqft, 2),
                # How tightly the five adjusted prices agree. Chosen at random it
                # reported "High" on a set spanning 38% from low to high.
                "confidence_level": (
                    "High"
                    if adj_spread_pct <= 12
                    else "Moderate" if adj_spread_pct <= 22 else "Low"
                ),
                "adjusted_price_spread_pct": adj_spread_pct,
            },
            "market_position": {
                "suggested_list_price": round_price(
                    value_indicated * r.uniform(1.00, 1.05)
                ),
                "competitive_price": round_price(value_indicated * 0.98),
                "aspirational_price": round_price(value_indicated * 1.07),
            },
            "prepared_date": today.strftime("%Y-%m-%d"),
            "disclaimer": (
                "This CMA is for informational purposes only. It is not a formal "
                "appraisal. A licensed appraiser should be consulted for lending or "
                "legal valuations."
            ),
        },
        simulated=True,
    )


#: Building area as a fraction of lot area, by property type. A condo's share of
#: the land it sits on is a small fraction of its floor area; a detached house
#: sits on two to four times its own footprint. Used to size the lot when the
#: caller does not give one — drawn as randint(3000, 25000) for every type, this
#: route put a 640 sqft condo on a 24,000 sqft lot and valued the dirt at nine
#: times the building.
LOT_RATIO = {
    "single_family": (1.8, 4.5),
    "townhouse": (1.1, 2.0),
    "condo": (0.15, 0.5),
    "multi_family": (0.8, 2.2),
    "commercial": (1.0, 3.0),
}


def calculate_replacement_cost(
    property_type: str,
    sqft: int,
    quality_grade: str,
    year_built: int,
    lot_sqft: int = 0,
) -> dict:
    property_type, quality_grade = property_type.lower(), quality_grade.lower()
    if quality_grade not in COST_PER_SQFT:
        return tool_error(
            f"Invalid quality_grade: {quality_grade}", valid=sorted(COST_PER_SQFT)
        )
    if property_type not in LAND_VALUE_PSF:
        return tool_error(
            f"Invalid property_type: {property_type}", valid=sorted(LAND_VALUE_PSF)
        )
    sqft, year_built, lot_sqft = int(sqft), int(year_built), int(lot_sqft or 0)
    if sqft <= 0:
        return tool_error("sqft must be positive")
    if lot_sqft < 0:
        return tool_error("lot_sqft cannot be negative")

    today = _today()
    r = _rng("cost_approach", property_type, sqft, quality_grade, year_built, lot_sqft)
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

    # Given a lot, use it — the caller usually has the same figure it passed to
    # the AVM for this address. Otherwise size it off the building.
    lot_given = lot_sqft > 0
    if not lot_given:
        lot_low, lot_high = LOT_RATIO[property_type]
        # No floor: a 200 sqft ratio-derived condo lot is the correct answer for a
        # unit in a tower, and a max(500, ...) floor silently replaced the ratio
        # for every small unit — the condo case this branch exists to fix.
        lot_sqft = max(1, round(sqft * r.uniform(lot_low, lot_high)))
    land_psf = r.uniform(*LAND_VALUE_PSF[property_type])
    land_value = round(land_psf * lot_sqft, 2)
    site_improvements = round(r.uniform(5000, 40000), 2)

    return tool_ok(
        {
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
                "lot_sqft_source": "provided" if lot_given else "estimated",
                "price_per_sqft": round(land_psf, 2),
                "total_land_value": land_value,
            },
            "site_improvements": site_improvements,
            "total_estimated_value": round_price(
                depreciated_value + land_value + site_improvements
            ),
            "methodology": "Cost Approach - Replacement Cost Method",
            "disclaimer": (
                "Cost approach estimates are most reliable for newer properties and "
                "unique structures. Market comparables may provide a more accurate "
                "value for typical residential properties."
            ),
        },
        simulated=True,
    )


TOOLS = {
    "estimate_property_value": estimate_property_value,
    "get_comparables": get_comparables,
    "generate_cma_report": generate_cma_report,
    "calculate_replacement_cost": calculate_replacement_cost,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
