"""Address-anchored property basis for the real-estate tools.

Every real-estate tool used to invent its own numbers for a property, so the
same address came back as a $297K listing in one route and a $978K subject in
another. That reads as broken data rather than a simulation.

The fix is a single deterministic basis keyed on the address alone: size, room
count and price per square foot are derived here, and each tool layers only its
own concern on top (listing status and days-on-market, comp adjustments, tax
history). Any tool given the same address therefore agrees on what the property
physically is and roughly what it is worth.

The price level is anchored to the market the address sits in. Drawn over a flat
$180-500/sqft for every zipcode, the listings table averaged $312/sqft directly
beneath a Market Pulse tile reading "$421 / Sq Ft" for the same market — the
listings were not priced in the market they were listed in. Pass
``market_ppsf=`` (from ``toolkit.market_basis``) and the address still decides
where in its market a property falls, but the market decides the level.
"""

import hashlib
import random
import re
from dataclasses import dataclass

STREETS = [
    "Oak Dr",
    "Maple Ave",
    "Elm St",
    "Cedar Ln",
    "Pine Rd",
    "Birch Ct",
    "Walnut Way",
    "Spruce Blvd",
    "Willow Ct",
    "Magnolia Dr",
    "Hickory St",
    "Cherry Ln",
]


def round_price(amount: float) -> int:
    """Round a money amount to the nearest thousand, as an int.

    Not round(x, -3): the two-arg form returns a float, which serialises into
    JSON as "415000.0" and renders as a price with a stray decimal wherever the
    UI shows a raw value.
    """
    return int(round(amount, -3))


@dataclass(frozen=True)
class PropertyBasis:
    """What every tool must agree on for a given address."""

    sqft: int
    beds: int
    baths: int
    price_per_sqft: float
    year_built: int
    lot_sqft: int
    property_type: str

    @property
    def value(self) -> int:
        """Indicative market value, rounded to the nearest thousand."""
        return round_price(self.sqft * self.price_per_sqft)


def rooms_for_sqft(sqft: int, r: random.Random) -> tuple[int, int]:
    """Plausible (beds, baths) for a floor area, with a little jitter.

    Shared so a comparable's room count is derived the same way the subject's
    is — otherwise a 635 sqft "3 bed / 2 bath" comp can turn up next to a
    1,229 sqft subject.
    """
    beds = max(1, min(6, round(sqft / 650) + r.choice([-1, 0, 0, 1])))
    baths = max(1, min(5, round(sqft / 1100) + r.choice([0, 0, 1])))
    return beds, baths


def basis_rng(address: str) -> random.Random:
    """RNG seeded on the normalised address — the shared anchor for all tools."""
    seed = hashlib.sha256(f"property_basis|{address.strip().lower()}".encode())
    return random.Random(int(seed.hexdigest()[:16], 16))


def zipcode_of(address: str) -> str | None:
    """The 5-digit zipcode in an address, if it carries one.

    Listings are addressed "1234 Oak Dr, 78701", so the market a property trades
    in is recoverable from the address itself — no extra plumbing through every
    call site.
    """
    match = re.search(r"\b(\d{5})\b(?!.*\b\d{5}\b)", address)
    return match.group(1) if match else None


def property_basis(
    address: str, *, current_year: int = 2026, market_ppsf: float | None = None
) -> PropertyBasis:
    """What every tool must agree on for one address.

    `market_ppsf` is the market's median price per square foot. Given it, this
    property lands within ±25% of the market level, so a listings table cannot
    average $312/sqft under a market tile reading $421. Without it the basis
    falls back to a wide band, which is what an address outside any known market
    gets.
    """
    r = basis_rng(address)
    sqft = r.randint(1100, 3800)
    beds, baths = rooms_for_sqft(sqft, r)
    ppsf = (
        round(market_ppsf * r.uniform(0.75, 1.25), 2)
        if market_ppsf
        else round(r.uniform(180, 500), 2)
    )
    return PropertyBasis(
        sqft=sqft,
        beds=beds,
        baths=baths,
        price_per_sqft=ppsf,
        year_built=r.randint(1950, current_year),
        lot_sqft=r.randint(3000, 20000),
        property_type=r.choice(
            ["single_family", "single_family", "single_family", "condo", "townhouse"]
        ),
    )
