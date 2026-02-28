from strands import tool
import json, random
from datetime import datetime, timedelta


@tool
def get_supplier_performance(supplier_id: str) -> str:
    """Get supplier performance scorecard and metrics.

    Args:
        supplier_id: Supplier identifier (e.g., 'SUP-101').

    Returns:
        JSON with on-time delivery, quality, responsiveness, and cost metrics.
    """
    return json.dumps({
        "supplier_id": supplier_id,
        "supplier_name": random.choice(["GlobalSupply Co", "Pacific Distributors", "Premier Wholesale", "Atlas Trading", "Sunrise Manufacturing"]),
        "overall_score": round(random.uniform(60, 98), 1),
        "rating": random.choice(["PREFERRED", "APPROVED", "PROBATIONARY"]),
        "metrics": {
            "on_time_delivery_pct": round(random.uniform(80, 99), 1),
            "quality_acceptance_pct": round(random.uniform(92, 99.5), 1),
            "avg_lead_time_days": round(random.uniform(5, 21), 1),
            "lead_time_variability_days": round(random.uniform(1, 5), 1),
            "cost_competitiveness_score": round(random.uniform(65, 95), 1),
            "responsiveness_score": round(random.uniform(70, 98), 1),
            "defect_rate_ppm": random.randint(50, 5000),
        },
        "recent_orders": random.randint(5, 50),
        "total_spend_ytd": round(random.uniform(50000, 2000000), 2),
        "contract_status": random.choice(["ACTIVE", "RENEWAL_DUE", "NEGOTIATING"]),
        "contract_expiry": (datetime.utcnow() + timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d"),
        "risk_assessment": random.choice(["LOW", "MEDIUM", "HIGH"]),
    })


@tool
def list_suppliers(category: str) -> str:
    """List suppliers with performance rankings for a product category.

    Args:
        category: Product category or 'all' for all suppliers.

    Returns:
        JSON with ranked supplier list and comparison metrics.
    """
    suppliers = []
    names = ["GlobalSupply Co", "Pacific Distributors", "Premier Wholesale", "Atlas Trading",
             "Sunrise Manufacturing", "Metro Imports", "Delta Logistics", "Crown Supply Chain"]

    for i, name in enumerate(names):
        suppliers.append({
            "supplier_id": f"SUP-{100 + i}",
            "name": name,
            "category": random.choice(["Electronics", "Apparel", "Grocery", "Home", "Sports"]) if category.lower() == "all" else category,
            "overall_score": round(random.uniform(60, 98), 1),
            "on_time_pct": round(random.uniform(80, 99), 1),
            "quality_pct": round(random.uniform(92, 99.5), 1),
            "avg_lead_days": round(random.uniform(5, 21), 1),
            "status": random.choice(["PREFERRED", "APPROVED", "APPROVED", "PROBATIONARY"]),
            "ytd_spend": round(random.uniform(50000, 2000000), 2),
        })

    suppliers.sort(key=lambda s: s["overall_score"], reverse=True)

    return json.dumps({
        "category": category,
        "total_suppliers": len(suppliers),
        "suppliers": suppliers,
        "summary": {
            "preferred_count": sum(1 for s in suppliers if s["status"] == "PREFERRED"),
            "avg_score": round(sum(s["overall_score"] for s in suppliers) / len(suppliers), 1),
            "total_ytd_spend": round(sum(s["ytd_spend"] for s in suppliers), 2),
        },
    })


@tool
def create_purchase_order(supplier_id: str, items: str) -> str:
    """Create a purchase order for a supplier.

    Args:
        supplier_id: Supplier identifier.
        items: JSON string of items to order, e.g., '[{"sku": "SKU-001", "quantity": 100, "unit_price": 25.99}]'

    Returns:
        JSON with PO confirmation and delivery estimate.
    """
    try:
        item_list = json.loads(items)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON for items"})

    po_id = f"PO-{datetime.now().strftime('%Y%m%d')}-{random.randint(10000, 99999)}"
    total = sum(item.get("quantity", 0) * item.get("unit_price", 0) for item in item_list)

    return json.dumps({
        "po_id": po_id,
        "status": "CREATED",
        "supplier_id": supplier_id,
        "items": item_list,
        "total_amount": round(total, 2),
        "tax_estimate": round(total * 0.08, 2),
        "shipping_estimate": round(total * 0.03, 2),
        "grand_total": round(total * 1.11, 2),
        "payment_terms": "Net 30",
        "estimated_delivery": (datetime.utcnow() + timedelta(days=random.randint(5, 21))).strftime("%Y-%m-%d"),
        "created_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_supplier_risk_report() -> str:
    """Get supplier risk assessment report identifying supply chain vulnerabilities.

    Returns:
        JSON with risk analysis, single-source dependencies, and mitigation recommendations.
    """
    return json.dumps({
        "report_date": datetime.utcnow().strftime("%Y-%m-%d"),
        "overall_supply_chain_risk": random.choice(["LOW", "MEDIUM", "MEDIUM"]),
        "risk_factors": {
            "single_source_dependencies": {
                "count": random.randint(3, 10),
                "skus_affected": random.randint(20, 100),
                "revenue_at_risk": round(random.uniform(100000, 1000000), 2),
            },
            "geographic_concentration": {
                "high_risk_regions": random.randint(1, 3),
                "suppliers_in_risk_zones": random.randint(2, 8),
            },
            "financial_health": {
                "suppliers_on_watch": random.randint(0, 3),
                "recent_downgrades": random.randint(0, 2),
            },
            "lead_time_risk": {
                "suppliers_with_increasing_lead_times": random.randint(2, 8),
                "avg_lead_time_increase_pct": round(random.uniform(5, 25), 1),
            },
        },
        "top_risks": [
            {"risk": "Single-source for critical electronics components", "severity": "HIGH", "mitigation": "Qualify alternate supplier by Q2"},
            {"risk": "3 suppliers in weather-risk zone", "severity": "MEDIUM", "mitigation": "Increase safety stock for affected SKUs"},
            {"risk": "Lead time increasing for apparel suppliers", "severity": "MEDIUM", "mitigation": "Negotiate expedited shipping options"},
        ],
        "recommendations": [
            "Dual-source top 20 revenue-critical SKUs",
            "Increase safety stock by 15% for single-source items",
            "Conduct quarterly supplier financial health reviews",
        ],
    })
