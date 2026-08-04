"""Gateway target: supplier — performance, listing, purchase orders, risk report.

The vendor roster, its scored metrics and each vendor's share of its category's
purchasing come from the shared toolkit.retail_basis, so the performance card,
the directory listing and the reorder recommendation name the same supplier for
the same id. Picked with r.choice from a local five-name list,
get_supplier_performance("SUP-101") answered "Premier Wholesale" while the
directory listed SUP-101 as Pacific Distributors.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import (
    APPROVED_SCORE,
    SUPPLIERS,
    category_rows,
    supplier_basis,
    supplier_rows,
    tool_ok,
    tool_error,
)
from toolkit.dispatch import dispatch
from toolkit.responses import parse_json_arg


def _ytd_fraction(today: datetime) -> float:
    """Share of the year elapsed — what turns an annual spend into a YTD one.

    Spend was drawn free over (50000, 2000000), so a vendor taking 100% of
    Grocery's $9.4M of annual COGS reported $87K year to date.
    """
    return today.timetuple().tm_yday / 365


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def _category_cogs(day: str) -> dict:
    """Annual COGS per category — what each category buys in a year."""
    return {c.category: c.annual_cogs for c in category_rows(day)}


def get_supplier_performance(supplier_id: str) -> dict:
    today = _today()
    day = today.strftime("%Y-%m-%d")
    basis = supplier_basis(supplier_id)
    cogs = _category_cogs(day).get(basis.category, 0.0)
    ytd = _ytd_fraction(today)

    return tool_ok(
        {
            "supplier_id": basis.supplier_id,
            "supplier_name": basis.name,
            "category": basis.category,
            # Score and rating are computed from the metrics below, so the card
            # cannot show 96.4 over 81.2% on-time delivery, nor a 94.1-scoring
            # vendor marked PROBATIONARY beside a 63.8-scoring PREFERRED one.
            "overall_score": basis.overall_score,
            "rating": basis.rating,
            "metrics": {
                "on_time_delivery_pct": basis.on_time_pct,
                "quality_acceptance_pct": basis.quality_pct,
                "avg_lead_time_days": basis.avg_lead_time_days,
                "lead_time_variability_days": basis.lead_time_variability_days,
                "cost_competitiveness_score": basis.cost_score,
                "responsiveness_score": basis.responsiveness_score,
                # The complement of the acceptance rate above. Drawn over
                # (50, 5000) beside a 92% acceptance rate — which is 80,000 ppm —
                # the two contradicted each other by a factor of sixteen.
                "defect_rate_ppm": basis.defect_rate_ppm,
            },
            "recent_orders": basis.orders_per_month,
            # This vendor's share of what its category actually buys, prorated to
            # the point in the year we are at.
            "total_spend_ytd": round(basis.annual_spend(cogs) * ytd, 2),
            "single_source": basis.is_single_source,
            # Status follows the days left on the contract, so "RENEWAL_DUE"
            # cannot sit beside an expiry eleven months out.
            "contract_status": basis.contract_status,
            "contract_expiry": (
                today + timedelta(days=basis.contract_days_remaining)
            ).strftime("%Y-%m-%d"),
            "risk_assessment": basis.risk_assessment,
        },
        simulated=True,
    )


def list_suppliers(category: str = "all") -> dict:
    today = _today()
    day = today.strftime("%Y-%m-%d")
    cogs_by_cat = _category_cogs(day)
    ytd = _ytd_fraction(today)
    wanted = category.strip().lower()

    suppliers = [
        {
            "supplier_id": b.supplier_id,
            "name": b.name,
            # The category this vendor actually serves. Picked with r.choice per
            # row, the directory listed Sunrise Manufacturing under "Home" while
            # auto_reorder sent every Grocery order to it.
            "category": b.category,
            "overall_score": b.overall_score,
            "on_time_pct": b.on_time_pct,
            "quality_pct": b.quality_pct,
            "avg_lead_days": b.avg_lead_time_days,
            "status": b.rating,
            "ytd_spend": round(
                b.annual_spend(cogs_by_cat.get(b.category, 0.0)) * ytd, 2
            ),
            "single_source": b.is_single_source,
        }
        for b in supplier_rows()
        if wanted in ("all", "") or b.category.lower() == wanted
    ]
    suppliers.sort(key=lambda s: s["overall_score"], reverse=True)

    return tool_ok(
        {
            "category": category,
            "total_suppliers": len(suppliers),
            "suppliers": suppliers,
            "summary": {
                "preferred_count": sum(
                    1 for s in suppliers if s["status"] == "PREFERRED"
                ),
                "avg_score": (
                    round(
                        sum(s["overall_score"] for s in suppliers) / len(suppliers), 1
                    )
                    if suppliers
                    else 0.0
                ),
                "total_ytd_spend": round(sum(s["ytd_spend"] for s in suppliers), 2),
            },
        },
        simulated=True,
    )


def create_purchase_order(supplier_id: str, items: str) -> dict:
    item_list, err = parse_json_arg(items, "items")
    if err:
        return tool_error(err)
    if not isinstance(item_list, list) or not item_list:
        return tool_error(
            "items must be a non-empty JSON array of "
            '{"sku", "quantity", "unit_price"} objects'
        )
    total = sum(
        float(i.get("quantity", 0)) * float(i.get("unit_price", 0)) for i in item_list
    )
    if total <= 0:
        return tool_error(
            "Order total must be positive; check quantity and unit_price fields"
        )

    today = _today()
    r = _rng("purchase_order", supplier_id, str(item_list), today.strftime("%Y-%m-%d"))
    now = datetime.now(timezone.utc)
    basis = supplier_basis(supplier_id)

    tax = round(total * 0.08, 2)
    shipping = round(total * 0.03, 2)

    return tool_ok(
        {
            "po_id": f"PO-{now.strftime('%Y%m%d')}-{r.randint(10000, 99999)}",
            "status": "CREATED",
            "supplier_id": basis.supplier_id,
            "supplier_name": basis.name,
            "known_supplier": basis.supplier_id in SUPPLIERS,
            "items": item_list,
            "total_amount": round(total, 2),
            "tax_estimate": tax,
            "shipping_estimate": shipping,
            # The parts have to sum to the total: a flat 1.11 multiplier printed a
            # grand total a few cents off the subtotal plus the two estimates
            # listed directly above it.
            "grand_total": round(total + tax + shipping, 2),
            "payment_terms": "Net 30",
            # This vendor's own lead time, so the PO promises what its
            # performance card claims. Drawn over (5, 21), a 6.2-day vendor
            # quoted three weeks.
            "estimated_delivery": (
                today + timedelta(days=round(basis.avg_lead_time_days))
            ).strftime("%Y-%m-%d"),
            "lead_time_days": basis.avg_lead_time_days,
            "note": "Demo procurement system: PO creation is simulated.",
        },
        simulated=True,
    )


def get_supplier_risk_report() -> dict:
    """Supply-chain risk read off the roster, not drawn beside it.

    Every count here is a fact about the vendors list_suppliers returns: the
    single-source count is the vendors at 100% of their category, the watch list
    is the PROBATIONARY ones, and the named top risks describe those same
    vendors. Drawn independently, the report claimed 7 single-source
    dependencies on an 8-vendor roster that had 2, and warned about "apparel
    suppliers" on a day the worst performer was in Grocery.
    """
    today = _today()
    day = today.strftime("%Y-%m-%d")
    r = _rng("supplier_risk", day)
    rows = supplier_rows()
    cats = {c.category: c for c in category_rows(day)}

    single = [b for b in rows if b.is_single_source]
    on_watch = [b for b in rows if b.rating == "PROBATIONARY"]
    # A vendor that misses delivery dates is the one whose lead time is drifting.
    unreliable = sorted(rows, key=lambda b: b.on_time_pct)
    drifting = [b for b in unreliable if b.on_time_pct < 90.0]

    # SKUs and revenue exposed by single-sourcing are those categories' own,
    # so the exposure follows the roster instead of a free (100000, 1000000).
    single_skus = sum(cats[b.category].total_skus for b in single if b.category in cats)
    single_revenue = sum(
        cats[b.category].annual_revenue for b in single if b.category in cats
    )

    top_risks = []
    for b in single:
        c = cats.get(b.category)
        top_risks.append(
            {
                "risk": (
                    f"{b.category} is single-sourced through {b.name} "
                    f"({b.supplier_id})"
                ),
                "severity": "HIGH" if c and c.total_skus > 1000 else "MEDIUM",
                "mitigation": f"Qualify a second {b.category} vendor",
            }
        )
    for b in on_watch:
        top_risks.append(
            {
                "risk": (
                    f"{b.name} is PROBATIONARY at {b.overall_score} "
                    f"({b.on_time_pct}% on-time)"
                ),
                "severity": "HIGH",
                "mitigation": f"Performance review and dual-source {b.category}",
            }
        )
    for b in drifting[:2]:
        if b in single or b in on_watch:
            continue
        top_risks.append(
            {
                "risk": (
                    f"{b.name} lead time varies by "
                    f"±{b.lead_time_variability_days} days"
                ),
                "severity": "MEDIUM",
                "mitigation": f"Raise safety stock on {b.category} SKUs",
            }
        )
    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    top_risks.sort(key=lambda x: severity_rank[x["severity"]])

    high_count = sum(1 for x in top_risks if x["severity"] == "HIGH")
    overall = "HIGH" if high_count >= 3 else "MEDIUM" if high_count else "LOW"

    recommendations = []
    if single:
        recommendations.append(
            f"Dual-source {', '.join(sorted(b.category for b in single))} — "
            f"{single_skus:,} SKUs currently on one vendor"
        )
    if on_watch:
        recommendations.append(
            "Put "
            + ", ".join(b.name for b in on_watch)
            + f" on a 90-day improvement plan (below the {APPROVED_SCORE:.0f} "
            "approval score)"
        )
    if drifting:
        recommendations.append(
            f"Raise safety stock for {len(drifting)} vendors delivering "
            f"under 90% on time"
        )
    recommendations.append("Conduct quarterly supplier financial health reviews")

    return tool_ok(
        {
            "report_date": day,
            # Follows the findings below: a report listing three HIGH risks
            # cannot be headlined "LOW".
            "overall_supply_chain_risk": overall,
            "suppliers_assessed": len(rows),
            "risk_factors": {
                "single_source_dependencies": {
                    "count": len(single),
                    "suppliers": [b.supplier_id for b in single],
                    "categories": [b.category for b in single],
                    "skus_affected": single_skus,
                    "revenue_at_risk": round(single_revenue, 2),
                },
                "geographic_concentration": {
                    # A share of the roster, not a count that exceeded it: the
                    # old draw could report 8 suppliers in risk zones out of 8
                    # while naming 3 in the top_risks text.
                    "high_risk_regions": max(1, round(len(rows) / 4)),
                    "suppliers_in_risk_zones": max(1, round(len(rows) * 0.25)),
                },
                "financial_health": {
                    "suppliers_on_watch": len(on_watch),
                    "watch_list": [b.supplier_id for b in on_watch],
                    "recent_downgrades": min(len(on_watch), 1),
                },
                "lead_time_risk": {
                    "suppliers_with_increasing_lead_times": len(drifting),
                    "avg_lead_time_increase_pct": (
                        round(
                            sum(
                                b.lead_time_variability_days / b.avg_lead_time_days
                                for b in drifting
                            )
                            / len(drifting)
                            * 100,
                            1,
                        )
                        if drifting
                        else 0.0
                    ),
                },
            },
            "top_risks": top_risks,
            "recommendations": recommendations,
            "next_review": (today + timedelta(days=r.randint(20, 40))).strftime(
                "%Y-%m-%d"
            ),
        },
        simulated=True,
    )


TOOLS = {
    "get_supplier_performance": get_supplier_performance,
    "list_suppliers": list_suppliers,
    "create_purchase_order": create_purchase_order,
    "get_supplier_risk_report": get_supplier_risk_report,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
