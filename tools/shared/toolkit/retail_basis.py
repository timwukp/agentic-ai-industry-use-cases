"""Catalog- and category-anchored basis for the retail tools.

Every retail tool used to invent its own numbers, so one screen showed a
5,501-SKU network above an ABC breakdown totalling 1,087 SKUs, and a category
table listing 178 stockouts above an "Active Stockouts: 11" tile. That reads as
broken data rather than a simulation.

The fix mirrors toolkit.asset_basis and toolkit.property_basis. Structural facts
— catalog membership, ABC class, unit economics, how many SKUs a category
carries — are keyed on the SKU or the category alone. Only today's availability
is keyed on the day. Everything else is *computed* from those: a category's
stockout count is its SKU count times its out-of-stock rate, its inventory
turnover is a year over its days of supply, its annual COGS is turns times the
value on hand, and the network figures are the category rows summed.
"""

import hashlib
import random
from dataclasses import dataclass

CATEGORIES = ("Electronics", "Apparel", "Grocery", "Home & Garden", "Sports")

#: (sku, product name, category, ABC class) for the demo catalog.
#:
#: The SKU is fixed rather than generated. It used to carry random digits redrawn
#: every day, so "Wireless Earbuds" shipped as SKU-ELEC-172 in one report and
#: SKU-ELEC-843 in the next, and the dashboard's SKU picker offered SKU-1001,
#: which was in no catalog at all and came back named "Product 001".
CATALOG = (
    ("SKU-ELEC-1001", "Wireless Earbuds", "Electronics", "A"),
    ("SKU-ELEC-1002", "USB-C Cable", "Electronics", "C"),
    ("SKU-ELEC-1003", "Smart Thermostat", "Electronics", "B"),
    ("SKU-APRL-2001", "Winter Jacket", "Apparel", "A"),
    ("SKU-APRL-2002", "Rain Shell", "Apparel", "B"),
    ("SKU-APRL-2003", "Merino Base Layer", "Apparel", "B"),
    ("SKU-GROC-3001", "Organic Coffee", "Grocery", "A"),
    ("SKU-GROC-3002", "Olive Oil 1L", "Grocery", "B"),
    ("SKU-GROC-3003", "Almond Butter", "Grocery", "C"),
    ("SKU-HOME-4001", "Air Purifier", "Home & Garden", "A"),
    ("SKU-HOME-4002", "Cast Iron Skillet", "Home & Garden", "B"),
    ("SKU-HOME-4003", "Linen Duvet", "Home & Garden", "C"),
    ("SKU-SPRT-5001", "Running Shoes", "Sports", "A"),
    ("SKU-SPRT-5002", "Yoga Mat", "Sports", "C"),
    ("SKU-SPRT-5003", "Trail Backpack", "Sports", "B"),
)

CATALOG_BY_SKU = {sku: (name, cat, abc) for sku, name, cat, abc in CATALOG}

#: The supplier roster, id -> name. Shared because auto_reorder names the
#: supplier it would place the order with, and it used to mint an id from a free
#: randint next to a name from its own four-name list — so it recommended
#: "SUP-457 / Pacific Distributors" while the supplier directory listed Pacific
#: Distributors as SUP-101 and had no SUP-457 at all.
SUPPLIERS = {
    "SUP-100": "GlobalSupply Co",
    "SUP-101": "Pacific Distributors",
    "SUP-102": "Premier Wholesale",
    "SUP-103": "Atlas Trading",
    "SUP-104": "Sunrise Manufacturing",
    "SUP-105": "Metro Imports",
    "SUP-106": "Delta Logistics",
    "SUP-107": "Crown Supply Chain",
}

#: The category each supplier serves. Grocery and Sports are single-sourced,
#: which is what makes the risk report's single-source finding a fact about this
#: roster rather than a free die roll.
SUPPLIER_CATEGORY = {
    "SUP-100": "Electronics",
    "SUP-101": "Apparel",
    "SUP-102": "Home & Garden",
    "SUP-103": "Sports",
    "SUP-104": "Grocery",
    "SUP-105": "Electronics",
    "SUP-106": "Home & Garden",
    "SUP-107": "Apparel",
}

#: Which supplier serves each category. A category has a primary vendor; the
#: directory and the reorder recommendation must name the same one.
CATEGORY_SUPPLIER = {
    "Electronics": "SUP-100",
    "Apparel": "SUP-101",
    "Grocery": "SUP-104",
    "Home & Garden": "SUP-102",
    "Sports": "SUP-103",
}

#: How the overall supplier score is composed. The score is *computed* from the
#: metrics printed beside it: drawn on its own, a supplier scored 96.4 overall on
#: 81.2% on-time delivery and a 4,800 ppm defect rate.
SUPPLIER_WEIGHTS = {
    "on_time": 0.30,
    "quality": 0.30,
    "cost": 0.20,
    "responsiveness": 0.20,
}

#: Score thresholds for the supplier rating. Drawn independently of the score, a
#: 94.1-scoring supplier was labelled PROBATIONARY beside a 63.8-scoring
#: PREFERRED one.
#:
#: The bands must sit inside the range the weighted score can actually reach.
#: With the metric bands below that range is 76-99, so 90/80 splits the roster;
#: at a textbook 88/72 nothing would ever be PROBATIONARY.
PREFERRED_SCORE = 90.0
APPROVED_SCORE = 80.0

#: Typical unit price band per category — a $6 jar of almond butter and a $400
#: thermostat must not be drawn from the same distribution.
PRICE_BANDS = {
    "Electronics": (25.0, 400.0),
    "Apparel": (30.0, 250.0),
    "Grocery": (6.0, 40.0),
    "Home & Garden": (20.0, 300.0),
    "Sports": (25.0, 220.0),
}

#: Gross margin band per ABC class. Slow-moving C items carry the fat margins;
#: A-class volume drivers are priced competitively.
MARGIN_BANDS = {"A": (28.0, 42.0), "B": (30.0, 48.0), "C": (32.0, 55.0)}

#: Units a day per ABC class. This is what makes an A-class item A-class, so the
#: velocity follows the classification instead of being drawn beside it.
VELOCITY_BANDS = {"A": (60, 220), "B": (15, 60), "C": (2, 15)}

#: Network share of SKU count, revenue and inventory value per ABC class, and
#: the service level each class is held to. Textbook Pareto split; every report's
#: class figures are these shares applied to the network totals rather than
#: independent draws that summed to a different network.
ABC_SHARES = {
    "A": {
        "description": "High value - top 20% of SKUs, 80% of revenue",
        "sku_pct": 18.5,
        "revenue_pct": 79.2,
        "inventory_pct": 55.0,
        "target_fill_rate": 98.0,
    },
    "B": {
        "description": "Medium value - next 30% of SKUs, 15% of revenue",
        "sku_pct": 31.2,
        "revenue_pct": 15.3,
        "inventory_pct": 30.0,
        "target_fill_rate": 95.0,
    },
    "C": {
        "description": "Low value - bottom 50% of SKUs, 5% of revenue",
        "sku_pct": 50.3,
        "revenue_pct": 5.5,
        "inventory_pct": 15.0,
        "target_fill_rate": 90.0,
    },
}

#: A-class SKUs get the safety stock, so they hold a higher fill rate than the
#: network's in-stock rate and C-class items a lower one.
FILL_OFFSET = {"A": 4.0, "B": 0.0, "C": -4.0}

#: Days of supply above which stock counts as excess. Below it a category has
#: only incidental overstock.
EXCESS_THRESHOLD_DAYS = 45.0


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def apportion(total: int, shares: list) -> list:
    """Split `total` across `shares` (percentages) so the parts sum to `total`.

    Rounding each share on its own leaves the parts off by one from the header
    they sit under. Largest-remainder apportionment is exact for any total.
    """
    exact = [total * s / 100 for s in shares]
    parts = [int(v) for v in exact]
    remainder = total - sum(parts)
    order = sorted(range(len(exact)), key=lambda i: exact[i] % 1, reverse=True)
    for i in order[:remainder]:
        parts[i] += 1
    return parts


@dataclass(frozen=True)
class SkuBasis:
    """What every retail tool must agree on for a given SKU."""

    sku: str
    name: str
    category: str
    abc_class: str
    unit_cost: float
    unit_price: float
    avg_daily_units: int

    @property
    def gross_margin_pct(self) -> float:
        return round((self.unit_price - self.unit_cost) / self.unit_price * 100, 1)

    @property
    def daily_revenue(self) -> float:
        """Revenue this SKU earns in a day when it is in stock."""
        return round(self.unit_price * self.avg_daily_units, 2)

    @property
    def supplier_id(self) -> str:
        """The vendor that supplies this SKU's category."""
        return CATEGORY_SUPPLIER[self.category]

    @property
    def supplier_name(self) -> str:
        return SUPPLIERS[self.supplier_id]


def sku_basis(sku: str) -> SkuBasis:
    """Unit economics for one SKU, stable for the life of the demo.

    Keyed on the SKU alone: a product's price, cost and velocity are properties
    of the product, not of the day it is looked up. An unknown SKU still
    resolves, so an agent asking about SKU-9999 gets a coherent answer.
    """
    key = sku.strip().upper()
    name, category, abc = CATALOG_BY_SKU.get(
        key, (f"Product {key.split('-')[-1]}", "Electronics", "B")
    )
    r = _rng("sku_basis", key)
    unit_price = round(r.uniform(*PRICE_BANDS[category]), 2)
    margin = r.uniform(*MARGIN_BANDS[abc])
    return SkuBasis(
        sku=key,
        name=name,
        category=category,
        abc_class=abc,
        unit_price=unit_price,
        unit_cost=round(unit_price * (1 - margin / 100), 2),
        avg_daily_units=r.randint(*VELOCITY_BANDS[abc]),
    )


@dataclass(frozen=True)
class CategoryBasis:
    """What every retail tool must agree on for a given category, on a day."""

    category: str
    total_skus: int
    in_stock_pct: float
    days_of_supply: float
    inventory_value: float
    gross_margin_pct: float

    @property
    def stockout_skus(self) -> int:
        """SKUs out of stock: the SKU count times the out-of-stock rate.

        Drawn beside the in-stock rate instead, a category reported 90.0% in
        stock next to 31 stockouts on 1,295 SKUs — which is 97.6%.
        """
        return round(self.total_skus * (100 - self.in_stock_pct) / 100)

    @property
    def turnover(self) -> float:
        """Inventory turns a year — a year over the days of supply on hand.

        The two were drawn independently, so a category showed 10.2 turns beside
        45 days of supply, which is 8.1 turns.
        """
        return round(365 / self.days_of_supply, 1)

    @property
    def annual_cogs(self) -> float:
        """Turns times the value on hand: the definition of inventory turnover."""
        return round(self.inventory_value * self.turnover, 2)

    @property
    def annual_revenue(self) -> float:
        """COGS grossed up by the margin, so the margin report reconciles."""
        return round(self.annual_cogs / (1 - self.gross_margin_pct / 100), 2)

    @property
    def overstock_skus(self) -> int:
        """Excess stock follows the days of supply, not a separate die roll."""
        over = (self.days_of_supply - EXCESS_THRESHOLD_DAYS) / EXCESS_THRESHOLD_DAYS
        return round(self.total_skus * min(0.25, max(0.01, over)))

    @property
    def excess_value(self) -> float:
        """Overstocked SKUs at this category's average value per SKU."""
        return round(self.overstock_skus * self.inventory_value / self.total_skus, 2)


#: Each supplier's share of its category's purchasing. Grocery (SUP-104) and
#: Sports (SUP-103) are at 1.0 — genuinely single-sourced, which is what the risk
#: report's single-source finding counts instead of a randint(3, 10).
SUPPLIER_SHARE = {
    "SUP-100": 0.65,
    "SUP-105": 0.35,
    "SUP-101": 0.70,
    "SUP-107": 0.30,
    "SUP-102": 0.60,
    "SUP-106": 0.40,
    "SUP-103": 1.00,
    "SUP-104": 1.00,
}


@dataclass(frozen=True)
class SupplierBasis:
    """What every retail tool must agree on for a given supplier.

    Only the four scored metrics and the lead time are drawn. The overall score,
    the rating, the defect rate, the lead-time variability and the risk grade are
    all computed from them — drawn beside them, a supplier scored 96.4 overall on
    81.2% on-time delivery, and a 94.1-scoring vendor was marked PROBATIONARY
    beside a 63.8-scoring PREFERRED one.
    """

    supplier_id: str
    name: str
    category: str
    on_time_pct: float
    quality_pct: float
    cost_score: float
    responsiveness_score: float
    avg_lead_time_days: float
    orders_per_month: int
    contract_days_remaining: int

    @property
    def overall_score(self) -> float:
        w = SUPPLIER_WEIGHTS
        return round(
            self.on_time_pct * w["on_time"]
            + self.quality_pct * w["quality"]
            + self.cost_score * w["cost"]
            + self.responsiveness_score * w["responsiveness"],
            1,
        )

    @property
    def rating(self) -> str:
        if self.overall_score >= PREFERRED_SCORE:
            return "PREFERRED"
        return "APPROVED" if self.overall_score >= APPROVED_SCORE else "PROBATIONARY"

    @property
    def defect_rate_ppm(self) -> int:
        """Units rejected per million — the complement of the acceptance rate."""
        return round((100 - self.quality_pct) / 100 * 1_000_000)

    @property
    def lead_time_variability_days(self) -> float:
        """A vendor that misses delivery dates is the one with a variable lead
        time; drawn apart, a 99.2%-on-time supplier showed ±4.8 days."""
        return round(
            max(0.2, self.avg_lead_time_days * (100 - self.on_time_pct) / 100 * 0.8), 1
        )

    @property
    def is_single_source(self) -> bool:
        return SUPPLIER_SHARE[self.supplier_id] >= 1.0

    @property
    def contract_status(self) -> str:
        if self.contract_days_remaining <= 60:
            return "RENEWAL_DUE"
        return "NEGOTIATING" if self.contract_days_remaining <= 120 else "ACTIVE"

    @property
    def risk_assessment(self) -> str:
        """Risk follows the score, with single-sourcing as an aggravator."""
        if self.overall_score < APPROVED_SCORE:
            return "HIGH"
        if self.overall_score < PREFERRED_SCORE or self.is_single_source:
            return "MEDIUM"
        return "LOW"

    def annual_spend(self, category_cogs: float) -> float:
        """This vendor's share of what its category buys in a year."""
        return round(category_cogs * SUPPLIER_SHARE[self.supplier_id], 2)


def supplier_basis(supplier_id: str) -> SupplierBasis:
    """One supplier's standing, keyed on the id alone.

    A vendor's name is a property of the vendor. Picked with r.choice from a
    five-name list, get_supplier_performance("SUP-101") answered "Premier
    Wholesale" while the directory listed SUP-101 as Pacific Distributors.
    """
    key = supplier_id.strip().upper()
    known = key in SUPPLIERS
    r = _rng("supplier_basis", key)
    return SupplierBasis(
        supplier_id=key,
        name=SUPPLIERS.get(key, f"Vendor {key}"),
        category=SUPPLIER_CATEGORY.get(key, "Electronics"),
        on_time_pct=round(r.uniform(78.0, 99.4), 1),
        # Acceptance rate, which sets the defect rate in ppm below: 99.0% is
        # 10,000 ppm, already a poor vendor. A (92, 99.5) band implied 80,000 ppm
        # — eight percent of every shipment rejected.
        quality_pct=round(r.uniform(99.0, 99.95), 2),
        cost_score=round(r.uniform(60.0, 98.0), 1),
        responsiveness_score=round(r.uniform(62.0, 99.0), 1),
        avg_lead_time_days=round(r.uniform(5.0, 21.0), 1),
        orders_per_month=r.randint(2, 18),
        contract_days_remaining=r.randint(30, 365) if known else 180,
    )


def supplier_rows() -> list:
    """The whole supplier directory, in roster order."""
    return [supplier_basis(sid) for sid in SUPPLIERS]


def category_basis(category: str, day: str) -> CategoryBasis:
    """One category's position on one day.

    Structure is keyed on the category alone — a network does not gain and lose a
    thousand SKUs overnight, and the dashboard would show the catalog resizing
    between refreshes. Only availability moves day to day.
    """
    s = _rng("category_structure", category)
    total_skus = s.randint(400, 1800)
    d = _rng("category_condition", category, day)
    return CategoryBasis(
        category=category,
        total_skus=total_skus,
        in_stock_pct=round(d.uniform(88.0, 99.4), 1),
        days_of_supply=round(s.uniform(30.0, 90.0), 1),
        inventory_value=round(total_skus * s.uniform(1200.0, 4200.0), 2),
        gross_margin_pct=round(s.uniform(18.0, 48.0), 1),
    )


def category_rows(day: str, category: str = "all") -> list:
    """Category bases for the whole network, or for one named category."""
    wanted = (
        CATEGORIES
        if category.lower() == "all"
        else tuple(c for c in CATEGORIES if c.lower() == category.lower())
        or (category.title(),)
    )
    return [category_basis(c, day) for c in wanted]


def network_in_stock_pct(rows: list) -> float:
    """SKU-weighted in-stock rate.

    A plain mean of the five category percentages ignores that Electronics
    carries four times the SKUs of Grocery, and it did not equal
    1 - total_stockouts / total_skus printed on the same card.
    """
    total = sum(c.total_skus for c in rows)
    if not total:
        return 0.0
    stockouts = sum(c.stockout_skus for c in rows)
    return round((total - stockouts) / total * 100, 1)


def abc_breakdown(rows: list) -> dict:
    """ABC classes as shares of the network the category rows describe.

    The counts are apportioned from the same total_skus the inventory summary
    reports, so the two cards cannot disagree about how large the network is.
    Turnover per class is that class's COGS over the inventory it holds — which
    is why A-class turns fastest rather than merely being drawn higher.
    """
    classes = list(ABC_SHARES)
    total_skus = sum(c.total_skus for c in rows)
    total_value = sum(c.inventory_value for c in rows)
    total_cogs = sum(c.annual_cogs for c in rows)
    in_stock = network_in_stock_pct(rows)
    counts = apportion(total_skus, [ABC_SHARES[c]["sku_pct"] for c in classes])

    out = {}
    for cls, sku_count in zip(classes, counts):
        share = ABC_SHARES[cls]
        value = round(total_value * share["inventory_pct"] / 100, 2)
        cogs = total_cogs * share["revenue_pct"] / 100
        out[cls] = {
            "description": share["description"],
            "sku_count": sku_count,
            "sku_pct": share["sku_pct"],
            "revenue_pct": share["revenue_pct"],
            "inventory_value": value,
            "avg_turnover": round(cogs / value, 1) if value else 0.0,
            "target_fill_rate": share["target_fill_rate"],
            "current_fill_rate": round(
                min(99.5, max(70.0, in_stock + FILL_OFFSET[cls])), 1
            ),
        }
    return out
