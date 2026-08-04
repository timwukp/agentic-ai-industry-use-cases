"""Gateway target: supplier — performance, listing, purchase orders, risk report.

Supplier data is a deterministic simulation seeded from the function inputs.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch
from toolkit.responses import parse_json_arg

SUPPLIER_NAMES = [
    "GlobalSupply Co",
    "Pacific Distributors",
    "Premier Wholesale",
    "Atlas Trading",
    "Sunrise Manufacturing",
    "Metro Imports",
    "Delta Logistics",
    "Crown Supply Chain",
]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def get_supplier_performance(supplier_id: str) -> dict:
    r = _rng("supplier_performance", supplier_id.upper())
    today = _today()
    return tool_ok(
        {
            "supplier_id": supplier_id,
            "supplier_name": r.choice(SUPPLIER_NAMES[:5]),
            "overall_score": round(r.uniform(60, 98), 1),
            "rating": r.choice(["PREFERRED", "APPROVED", "PROBATIONARY"]),
            "metrics": {
                "on_time_delivery_pct": round(r.uniform(80, 99), 1),
                "quality_acceptance_pct": round(r.uniform(92, 99.5), 1),
                "avg_lead_time_days": round(r.uniform(5, 21), 1),
                "lead_time_variability_days": round(r.uniform(1, 5), 1),
                "cost_competitiveness_score": round(r.uniform(65, 95), 1),
                "responsiveness_score": round(r.uniform(70, 98), 1),
                "defect_rate_ppm": r.randint(50, 5000),
            },
            "recent_orders": r.randint(5, 50),
            "total_spend_ytd": round(r.uniform(50000, 2000000), 2),
            "contract_status": r.choice(["ACTIVE", "RENEWAL_DUE", "NEGOTIATING"]),
            "contract_expiry": (today + timedelta(days=r.randint(30, 365))).strftime(
                "%Y-%m-%d"
            ),
            "risk_assessment": r.choice(["LOW", "MEDIUM", "HIGH"]),
        },
        simulated=True,
    )


def list_suppliers(category: str = "all") -> dict:
    suppliers = []
    for i, name in enumerate(SUPPLIER_NAMES):
        r = _rng("supplier_row", name, category.lower())
        suppliers.append(
            {
                "supplier_id": f"SUP-{100 + i}",
                "name": name,
                "category": (
                    r.choice(["Electronics", "Apparel", "Grocery", "Home", "Sports"])
                    if category.lower() == "all"
                    else category
                ),
                "overall_score": round(r.uniform(60, 98), 1),
                "on_time_pct": round(r.uniform(80, 99), 1),
                "quality_pct": round(r.uniform(92, 99.5), 1),
                "avg_lead_days": round(r.uniform(5, 21), 1),
                "status": r.choice(
                    ["PREFERRED", "APPROVED", "APPROVED", "PROBATIONARY"]
                ),
                "ytd_spend": round(r.uniform(50000, 2000000), 2),
            }
        )
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
                "avg_score": round(
                    sum(s["overall_score"] for s in suppliers) / len(suppliers), 1
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

    return tool_ok(
        {
            "po_id": f"PO-{now.strftime('%Y%m%d')}-{r.randint(10000, 99999)}",
            "status": "CREATED",
            "supplier_id": supplier_id,
            "items": item_list,
            "total_amount": round(total, 2),
            "tax_estimate": round(total * 0.08, 2),
            "shipping_estimate": round(total * 0.03, 2),
            "grand_total": round(total * 1.11, 2),
            "payment_terms": "Net 30",
            "estimated_delivery": (today + timedelta(days=r.randint(5, 21))).strftime(
                "%Y-%m-%d"
            ),
            "note": "Demo procurement system: PO creation is simulated.",
        },
        simulated=True,
    )


def get_supplier_risk_report() -> dict:
    today = _today()
    r = _rng("supplier_risk", today.strftime("%Y-%m-%d"))
    return tool_ok(
        {
            "report_date": today.strftime("%Y-%m-%d"),
            "overall_supply_chain_risk": r.choice(["LOW", "MEDIUM", "MEDIUM"]),
            "risk_factors": {
                "single_source_dependencies": {
                    "count": r.randint(3, 10),
                    "skus_affected": r.randint(20, 100),
                    "revenue_at_risk": round(r.uniform(100000, 1000000), 2),
                },
                "geographic_concentration": {
                    "high_risk_regions": r.randint(1, 3),
                    "suppliers_in_risk_zones": r.randint(2, 8),
                },
                "financial_health": {
                    "suppliers_on_watch": r.randint(0, 3),
                    "recent_downgrades": r.randint(0, 2),
                },
                "lead_time_risk": {
                    "suppliers_with_increasing_lead_times": r.randint(2, 8),
                    "avg_lead_time_increase_pct": round(r.uniform(5, 25), 1),
                },
            },
            "top_risks": [
                {
                    "risk": "Single-source for critical electronics components",
                    "severity": "HIGH",
                    "mitigation": "Qualify alternate supplier by Q2",
                },
                {
                    "risk": "3 suppliers in weather-risk zone",
                    "severity": "MEDIUM",
                    "mitigation": "Increase safety stock for affected SKUs",
                },
                {
                    "risk": "Lead time increasing for apparel suppliers",
                    "severity": "MEDIUM",
                    "mitigation": "Negotiate expedited shipping options",
                },
            ],
            "recommendations": [
                "Dual-source top 20 revenue-critical SKUs",
                "Increase safety stock by 15% for single-source items",
                "Conduct quarterly supplier financial health reviews",
            ],
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
