from strands import tool
import json, random, uuid
from datetime import datetime, timedelta


@tool
def check_spare_parts(part_number: str) -> str:
    """Check spare part availability, stock levels, and warehouse locations.

    Args:
        part_number: Part number identifier (e.g., 'BRG-6205', 'SEL-3500', 'FLT-0047').

    Returns:
        JSON with stock levels by location, reorder status, lead time, and alternative parts.
    """
    warehouses = [
        {"location": "Main Stores", "code": "WH-MAIN"},
        {"location": "Line-Side Stock A", "code": "WH-LSA"},
        {"location": "Line-Side Stock B", "code": "WH-LSB"},
        {"location": "Regional Distribution Center", "code": "WH-RDC"},
    ]

    total_stock = random.randint(0, 50)
    remaining = total_stock
    stock_by_location = []
    for wh in warehouses:
        qty = random.randint(0, remaining) if remaining > 0 else 0
        remaining -= qty
        if qty > 0:
            stock_by_location.append({
                "location": wh["location"],
                "location_code": wh["code"],
                "quantity": qty,
                "bin_number": f"BIN-{random.choice('ABCDEF')}{random.randint(1,20):02d}-{random.randint(1,5)}",
            })

    unit_cost = round(random.uniform(5, 500), 2)
    reorder_point = random.randint(3, 10)
    lead_time_days = random.randint(1, 30)

    part_categories = {
        "BRG": {"category": "Bearings", "description": f"Ball bearing {random.choice(['6205-2RS', '6308-ZZ', '7206-BEP', 'NU210-ECJ'])}"},
        "SEL": {"category": "Seals", "description": f"Mechanical seal {random.randint(20,80)}mm"},
        "FLT": {"category": "Filters", "description": f"Hydraulic filter element {random.choice(['10', '25', '40'])} micron"},
        "BLT": {"category": "Belts", "description": f"V-belt {random.choice(['A', 'B', 'C'])}{random.randint(40,120)}"},
        "LUB": {"category": "Lubricants", "description": f"Synthetic grease {random.choice(['EP2', 'EP0', 'ISO VG 68'])}"},
        "VLV": {"category": "Valves", "description": f"Solenoid valve {random.choice(['2-way', '3-way'])} {random.choice(['1/4', '1/2', '3/4'])}in"},
    }

    prefix = part_number.split("-")[0] if "-" in part_number else "BRG"
    part_info = part_categories.get(prefix, {"category": "General", "description": f"Spare part {part_number}"})

    alternatives = []
    if random.random() > 0.4:
        alternatives.append({
            "part_number": f"{prefix}-{random.randint(1000,9999)}",
            "description": f"Compatible alternative - {random.choice(['OEM equivalent', 'aftermarket', 'upgraded version'])}",
            "unit_cost": round(unit_cost * random.uniform(0.7, 1.3), 2),
            "in_stock": random.choice([True, True, False]),
        })

    return json.dumps({
        "part_number": part_number,
        "description": part_info["description"],
        "category": part_info["category"],
        "manufacturer": random.choice(["SKF", "FAG/Schaeffler", "NSK", "Timken", "Parker", "Festo", "Gates", "Mobil"]),
        "unit_cost": unit_cost,
        "total_stock": total_stock,
        "stock_by_location": stock_by_location,
        "reorder_info": {
            "reorder_point": reorder_point,
            "economic_order_qty": random.randint(5, 25),
            "needs_reorder": total_stock <= reorder_point,
            "lead_time_days": lead_time_days,
            "preferred_supplier": random.choice(["Industrial Parts Direct", "MRO Supply Corp", "OEM Distributor", "BearingWorld"]),
        },
        "criticality": random.choice(["CRITICAL", "ESSENTIAL", "STANDARD"]),
        "alternative_parts": alternatives,
        "usage_rate": {
            "avg_monthly_consumption": round(random.uniform(0.5, 8), 1),
            "last_12_months_used": random.randint(2, 50),
        },
        "last_updated": datetime.utcnow().isoformat() + "Z",
    })


@tool
def order_spare_parts(part_number: str, quantity: int) -> str:
    """Create a spare parts purchase order.

    Args:
        part_number: Part number to order (e.g., 'BRG-6205').
        quantity: Number of units to order.

    Returns:
        JSON with order confirmation, estimated delivery, and cost breakdown.
    """
    if quantity <= 0:
        return json.dumps({"error": "Quantity must be positive"})

    order_id = f"SPO-{uuid.uuid4().hex[:8].upper()}"
    unit_cost = round(random.uniform(5, 500), 2)
    lead_time_days = random.randint(1, 21)

    subtotal = round(unit_cost * quantity, 2)
    shipping = round(subtotal * random.uniform(0.03, 0.10), 2)

    return json.dumps({
        "order_id": order_id,
        "status": "ORDER_PLACED",
        "part_number": part_number,
        "quantity": quantity,
        "unit_cost": unit_cost,
        "cost_breakdown": {
            "subtotal": subtotal,
            "shipping": shipping,
            "tax": round(subtotal * 0.08, 2),
            "total": round(subtotal + shipping + subtotal * 0.08, 2),
        },
        "supplier": {
            "name": random.choice(["Industrial Parts Direct", "MRO Supply Corp", "OEM Distributor", "BearingWorld"]),
            "supplier_id": f"SUP-{random.randint(100, 999)}",
            "contact": f"orders@{random.choice(['indparts', 'mrosupply', 'oemdist', 'bearingworld'])}.com",
        },
        "delivery": {
            "lead_time_days": lead_time_days,
            "estimated_delivery": (datetime.utcnow() + timedelta(days=lead_time_days)).strftime("%Y-%m-%d"),
            "shipping_method": random.choice(["Standard Ground", "Expedited", "Next-Day Air"]),
            "delivery_location": random.choice(["Main Stores (WH-MAIN)", "Line-Side Stock A (WH-LSA)"]),
        },
        "approval": {
            "status": "AUTO_APPROVED" if subtotal < 1000 else "PENDING_APPROVAL",
            "approver": "Auto" if subtotal < 1000 else "Maintenance Manager",
            "threshold": 1000.00,
        },
        "created_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_parts_forecast(equipment_id: str) -> str:
    """Predict spare parts needed based on equipment maintenance predictions.

    Cross-references failure predictions, maintenance schedules, and historical
    consumption to forecast parts demand for the next 90 days.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001').

    Returns:
        JSON with forecasted parts needs, current stock status, and procurement recommendations.
    """
    forecasted_parts = [
        {
            "part_number": f"BRG-{random.randint(1000, 9999)}",
            "description": "Deep groove ball bearing 6205-2RS",
            "category": "Bearings",
            "forecast_reason": "Predictive: vibration trend indicates bearing wear",
            "needed_by": (datetime.utcnow() + timedelta(days=random.randint(7, 45))).strftime("%Y-%m-%d"),
            "quantity_needed": random.randint(1, 4),
            "current_stock": random.randint(0, 5),
            "unit_cost": round(random.uniform(15, 120), 2),
            "confidence": round(random.uniform(0.7, 0.95), 2),
        },
        {
            "part_number": f"SEL-{random.randint(1000, 9999)}",
            "description": "Mechanical shaft seal 35mm",
            "category": "Seals",
            "forecast_reason": "Scheduled: preventive maintenance due",
            "needed_by": (datetime.utcnow() + timedelta(days=random.randint(14, 60))).strftime("%Y-%m-%d"),
            "quantity_needed": random.randint(1, 2),
            "current_stock": random.randint(0, 3),
            "unit_cost": round(random.uniform(25, 180), 2),
            "confidence": round(random.uniform(0.8, 0.98), 2),
        },
        {
            "part_number": f"LUB-{random.randint(1000, 9999)}",
            "description": "Synthetic bearing grease EP2 400g",
            "category": "Lubricants",
            "forecast_reason": "Scheduled: lubrication interval approaching",
            "needed_by": (datetime.utcnow() + timedelta(days=random.randint(5, 30))).strftime("%Y-%m-%d"),
            "quantity_needed": random.randint(1, 3),
            "current_stock": random.randint(0, 6),
            "unit_cost": round(random.uniform(8, 35), 2),
            "confidence": round(random.uniform(0.85, 0.99), 2),
        },
        {
            "part_number": f"FLT-{random.randint(1000, 9999)}",
            "description": "Hydraulic filter element 10 micron",
            "category": "Filters",
            "forecast_reason": "Usage-based: filter life approaching limit",
            "needed_by": (datetime.utcnow() + timedelta(days=random.randint(10, 40))).strftime("%Y-%m-%d"),
            "quantity_needed": random.randint(1, 2),
            "current_stock": random.randint(0, 4),
            "unit_cost": round(random.uniform(20, 90), 2),
            "confidence": round(random.uniform(0.75, 0.95), 2),
        },
        {
            "part_number": f"BLT-{random.randint(1000, 9999)}",
            "description": "V-belt B68",
            "category": "Belts",
            "forecast_reason": "Preventive: belt replacement interval due",
            "needed_by": (datetime.utcnow() + timedelta(days=random.randint(20, 75))).strftime("%Y-%m-%d"),
            "quantity_needed": random.randint(1, 3),
            "current_stock": random.randint(0, 3),
            "unit_cost": round(random.uniform(10, 45), 2),
            "confidence": round(random.uniform(0.8, 0.95), 2),
        },
    ]

    for part in forecasted_parts:
        part["stock_sufficient"] = part["current_stock"] >= part["quantity_needed"]
        part["order_needed"] = not part["stock_sufficient"]
        if part["order_needed"]:
            part["order_quantity"] = part["quantity_needed"] - part["current_stock"] + random.randint(1, 3)

    total_cost = sum(p["quantity_needed"] * p["unit_cost"] for p in forecasted_parts)
    order_needed = [p for p in forecasted_parts if p["order_needed"]]

    return json.dumps({
        "equipment_id": equipment_id,
        "forecast_period_days": 90,
        "total_parts_forecasted": len(forecasted_parts),
        "parts": forecasted_parts,
        "procurement_summary": {
            "parts_in_stock": sum(1 for p in forecasted_parts if p["stock_sufficient"]),
            "parts_to_order": len(order_needed),
            "estimated_total_cost": round(total_cost, 2),
            "urgent_orders": sum(1 for p in order_needed if (datetime.strptime(p["needed_by"], "%Y-%m-%d") - datetime.utcnow()).days < 14),
        },
        "recommendation": f"Order {len(order_needed)} parts immediately to avoid maintenance delays. Total estimated cost: ${round(total_cost, 2):,.2f}",
        "forecasted_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_parts_inventory_report() -> str:
    """Get overall spare parts inventory status and health report.

    Returns:
        JSON with inventory value, stockout risks, excess inventory, and KPIs.
    """
    categories = [
        {"name": "Bearings", "prefix": "BRG"},
        {"name": "Seals & Gaskets", "prefix": "SEL"},
        {"name": "Filters", "prefix": "FLT"},
        {"name": "Belts & Hoses", "prefix": "BLT"},
        {"name": "Lubricants", "prefix": "LUB"},
        {"name": "Electrical Components", "prefix": "ELC"},
        {"name": "Valves & Fittings", "prefix": "VLV"},
        {"name": "Instrumentation", "prefix": "INS"},
    ]

    category_data = []
    for cat in categories:
        total_skus = random.randint(20, 200)
        total_value = round(random.uniform(5000, 150000), 2)
        stockout_count = random.randint(0, int(total_skus * 0.08))
        excess_count = random.randint(0, int(total_skus * 0.15))

        category_data.append({
            "category": cat["name"],
            "total_part_numbers": total_skus,
            "total_inventory_value": total_value,
            "stockout_items": stockout_count,
            "below_reorder_point": random.randint(stockout_count, stockout_count + 10),
            "excess_stock_items": excess_count,
            "excess_stock_value": round(total_value * excess_count / total_skus * random.uniform(1.5, 3), 2),
            "avg_turnover_ratio": round(random.uniform(1.5, 8.0), 1),
            "service_level_pct": round(random.uniform(88, 99), 1),
        })

    total_value = sum(c["total_inventory_value"] for c in category_data)
    total_stockouts = sum(c["stockout_items"] for c in category_data)
    total_parts = sum(c["total_part_numbers"] for c in category_data)
    total_excess_value = sum(c["excess_stock_value"] for c in category_data)

    return json.dumps({
        "report_date": datetime.utcnow().strftime("%Y-%m-%d"),
        "inventory_summary": {
            "total_part_numbers": total_parts,
            "total_inventory_value": round(total_value, 2),
            "total_stockout_items": total_stockouts,
            "total_excess_value": round(total_excess_value, 2),
            "overall_service_level_pct": round(sum(c["service_level_pct"] for c in category_data) / len(category_data), 1),
            "inventory_accuracy_pct": round(random.uniform(94, 99.5), 1),
        },
        "by_category": category_data,
        "critical_stockouts": [
            {"part_number": f"BRG-{random.randint(1000,9999)}", "description": "Critical bearing for CNC spindle", "equipment_affected": "EQ-CNC-001, EQ-CNC-002", "days_out_of_stock": random.randint(1, 14)},
            {"part_number": f"SEL-{random.randint(1000,9999)}", "description": "Hydraulic pump seal", "equipment_affected": "EQ-PUMP-001", "days_out_of_stock": random.randint(1, 7)},
        ] if total_stockouts > 0 else [],
        "kpis": {
            "inventory_turnover_ratio": round(random.uniform(2.5, 6.0), 1),
            "fill_rate_pct": round(random.uniform(90, 98), 1),
            "dead_stock_pct": round(random.uniform(2, 10), 1),
            "carrying_cost_pct": round(random.uniform(15, 25), 1),
            "avg_days_to_fulfill": round(random.uniform(0.5, 5), 1),
        },
        "recommendations": [
            f"Reorder {total_stockouts} critical parts immediately to restore service levels",
            f"Review {sum(c['excess_stock_items'] for c in category_data)} excess items for potential return or redistribution (${round(total_excess_value, 2):,.2f} tied up)",
            "Implement consignment stocking for high-value, low-turnover bearings",
            "Set up vendor-managed inventory for filters and lubricants",
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
