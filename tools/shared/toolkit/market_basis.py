"""Zipcode-anchored market basis for the real-estate tools.

toolkit.property_basis fixed the *property* side: every tool now agrees on what
a given address physically is. The *market* side had the same defect and no
equivalent anchor, so one screen showed a "Median Sale Price $440.1K" tile above
a price-history chart plotting $740K-$780K, above a forecast reading "projected
from $777.1K" — three independent draws of one zipcode's median price.

This module is the missing anchor. The market's price level, price per square
foot and sales volume are keyed on the zipcode alone; the twelve months of
history are a walk ending at that level, so the headline is the last point of the
chart beneath it rather than a fourth draw. The forecast starts from the same
point the history ends on, which is what makes the two charts joinable.
"""

import hashlib
import math
import random
from dataclasses import dataclass

#: A balanced market carries about six months of supply.
BALANCED_MONTHS_SUPPLY = 6.0


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def month_label(anchor, offset: int) -> str:
    """Calendar-month label `offset` months from `anchor` (negative = past).

    Stepping by ``timedelta(days=30)`` drifts ~5 days a year, which duplicates
    and skips months on a 12-point axis — so shift the month ordinal instead.
    """
    total = (anchor.year * 12 + anchor.month - 1) + offset
    return f"{total // 12:04d}-{total % 12 + 1:02d}"


@dataclass(frozen=True)
class MarketBasis:
    """What every real-estate tool must agree on for a given zipcode."""

    zipcode: str
    #: Median sale price today — the last point of the history series.
    median_price: int
    median_ppsf: float
    #: Compound monthly price drift over the trailing year, in percent.
    monthly_drift: float
    #: Closed sales in a typical month, before seasonality.
    base_volume: int
    months_supply: float
    active_listings: int

    @property
    def market_type(self) -> str:
        if self.months_supply < 3:
            return "Strong Seller's Market"
        if self.months_supply < 5:
            return "Seller's Market"
        if self.months_supply < 7:
            return "Balanced Market"
        return "Buyer's Market"

    @property
    def yoy_pct(self) -> float:
        """Year-over-year change implied by twelve months of the drift.

        Drawn on its own it contradicted the history chart's own endpoints: a
        "-2.7% YoY" tile sat above a line that rose over the same twelve months.
        """
        return round(((1 + self.monthly_drift / 100) ** 12 - 1) * 100, 1)

    @property
    def price_12mo_ago(self) -> int:
        return round(self.median_price / (1 + self.yoy_pct / 100))

    @property
    def sale_to_list_ratio(self) -> float:
        """Tight supply bids sale prices above list; slack supply cuts them.

        Drawn independently of months-of-supply, a 1.6-month "Strong Seller's
        Market" reported a 0.944 sale-to-list ratio — sellers taking 5.6% under
        asking in a market where they hold all the leverage.
        """
        slack = (self.months_supply - BALANCED_MONTHS_SUPPLY) / BALANCED_MONTHS_SUPPLY
        return round(1.0 - slack * 0.05, 3)

    @property
    def pct_sold_over_asking(self) -> float:
        """Follows the sale-to-list ratio: above 1.0, most homes clear over ask."""
        over = (self.sale_to_list_ratio - 1.0) * 100
        return round(min(75.0, max(2.0, 25.0 + over * 12)), 1)

    @property
    def pct_with_price_reduction(self) -> float:
        """Price cuts are what a slack market does, so they track supply."""
        return round(
            min(
                60.0, max(8.0, 30.0 + (self.months_supply - BALANCED_MONTHS_SUPPLY) * 6)
            ),
            1,
        )

    @property
    def average_dom(self) -> int:
        """Days on market: months of supply, converted to days.

        A separate randint put a 90-day average on a 1.6-month market.
        """
        return max(5, round(self.months_supply * 30 * 0.55))

    @property
    def closed_sales_30d(self) -> int:
        return self.base_volume

    @property
    def absorption_rate(self) -> float:
        """Share of inventory that sells in a month — 1 / months of supply."""
        return round(100 / self.months_supply, 1)

    @property
    def new_listings_30d(self) -> int:
        """A market at equilibrium replaces what it sells; supply skews this."""
        return round(self.base_volume * (0.85 + self.months_supply / 20))

    @property
    def pending_sales(self) -> int:
        """Under contract now: roughly a month's closings, scaled by pace."""
        return max(1, round(self.base_volume * 0.7))


def market_basis(zipcode: str, month: str) -> MarketBasis:
    """One market's level and pace, stable within a calendar month.

    Keyed on (zipcode, month): a metro's price level does not move day to day,
    and a dashboard that redrew it nightly would show the market lurching.
    """
    z = str(zipcode).strip()
    r = _rng("market_basis", z, month)
    median_price = round(r.randint(320, 980) * 1000)
    months_supply = round(r.uniform(0.8, 8.0), 1)
    return MarketBasis(
        zipcode=z,
        median_price=median_price,
        # Price per square foot must agree with the median price, since a median
        # home is roughly 1,600-2,600 sqft. Drawn over (150, 600) beside a
        # $440K median, it implied a 730 sqft median home.
        median_ppsf=round(median_price / r.uniform(1600, 2600), 2),
        monthly_drift=round(r.uniform(-0.5, 1.0), 3),
        base_volume=r.randint(20, 150),
        months_supply=months_supply,
        # Inventory is what months-of-supply measures against monthly sales, so
        # it follows from the two rather than being drawn beside them.
        active_listings=max(5, round(r.randint(20, 150) * months_supply)),
    )


def price_history(basis: MarketBasis, anchor, months: int) -> list:
    """A `months`-long span of monthly history ending at the basis price.

    Oldest first, and `months + 1` points: a twelve-month change is measured
    against the point twelve months back, so the series has to *contain* that
    point. Returning twelve points spanned only eleven intervals, which is how a
    "+8.8% YoY" tile sat above its own chart headed "+8.1% over period" — the
    same market over what both called a year.

    Walked *backwards* from today's median so the series' last point IS the
    headline median price. Walking forwards from an independent start left the
    endpoint wherever the noise landed, which is how a $440K tile ended up above
    a chart topping out at $780K.
    """
    r = _rng("price_history", basis.zipcode, months, anchor.strftime("%Y-%m"))
    step = 1 + basis.monthly_drift / 100

    # Month-to-month jitter, divided by its own geometric mean so the steps
    # multiply out to exactly `step ** months`. Without that correction the jitter
    # accumulated and the endpoints drifted off the drift the YoY tile states from
    # the same basis — 6.3 points apart at worst over 400 markets.
    jitters = [r.uniform(0.99, 1.01) for _ in range(months)]
    if jitters:
        geo_mean = math.exp(sum(math.log(j) for j in jitters) / len(jitters))
        jitters = [j / geo_mean for j in jitters]

    prices, ppsf = [basis.median_price], [basis.median_ppsf]
    for jitter in jitters:
        # jitter is applied to the step, so reversing it stays a plausible walk
        back = step * jitter
        prices.append(round(prices[-1] / back))
        ppsf.append(round(ppsf[-1] / back, 2))
    prices.reverse()
    ppsf.reverse()

    series = []
    for i in range(months + 1):
        label = month_label(anchor, -(months - i))
        calendar_month = int(label[-2:])
        # Spring and early summer are the selling season.
        season = 1.15 if calendar_month in (4, 5, 6, 7) else 0.9
        volume = max(5, round(basis.base_volume * season * r.uniform(0.85, 1.15)))
        series.append(
            {
                "date": label,
                "median_sale_price": prices[i],
                "median_price_per_sqft": ppsf[i],
                "closed_sales": volume,
                # A market absorbing more than it lists is tightening; supply
                # decides which side of that this market is on.
                "new_listings": max(
                    1, round(volume * (0.85 + basis.months_supply / 20))
                ),
                "avg_days_on_market": max(
                    5, round(basis.average_dom * r.uniform(0.85, 1.15))
                ),
                "sale_to_list_ratio": round(
                    basis.sale_to_list_ratio * r.uniform(0.995, 1.005), 3
                ),
                "inventory": max(5, round(volume * basis.months_supply)),
            }
        )
    return series
