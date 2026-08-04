"""Gateway target: parts — spare part stock, ordering, forecasting, inventory report.

Parts data is a deterministic simulation seeded from the function inputs
(stable within a calendar day).
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

WAREHOUSES = [
    {"location": "Main Stores", "code": "WH-MAIN"},
    {"location": "Line-Side Stock A", "code": "WH-LSA"},
    {"location": "Line-Side Stock B", "code": "WH-LSB"},
    {"location": "Regional Distribution Center", "code": "WH-RDC"},
]

PART_CATEGORIES = {
    "BRG": {"category": "Bearings", "description": "Deep groove ball bearing 6205-2RS"},
    "SEL": {"category": "Seals", "description": "Mechanical shaft seal 35mm"},
    "FLT": {"category": "Filters", "description": "Hydraulic filter element 10 micron"},
    "BLT": {"category": "Belts", "description": "V-belt B68"},
    "LUB": {"category": "Lubricants", "description": "Synthetic grease EP2 400g"},
    "VLV": {"category": "Valves", "description": "Solenoid valve 2-way 1/2in"},
}

SUPPLIERS = [
    "Industrial Parts Direct",
    "MRO Supply Corp",
    "OEM Distributor",
    "BearingWorld",
]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def check_spare_parts(part_number: str) -> dict:
    part_number = part_number.upper()
    r = _rng("check_spare_parts", part_number)
    prefix = part_number.split("-")[0] if "-" in part_number else "BRG"
    part_info = PART_CATEGORIES.get(
        prefix, {"category": "General", "description": f"Spare part {part_number}"}
    )

    total_stock = r.randint(0, 50)
    remaining = total_stock
    stock_by_location = []
    for wh in WAREHOUSES:
        qty = r.randint(0, remaining) if remaining > 0 else 0
        remaining -= qty
        if qty > 0:
            stock_by_location.append(
                {
                    "location": wh["location"],
                    "location_code": wh["code"],
                    "quantity": qty,
                    "bin_number": f"BIN-{r.choice('ABCDEF')}{r.randint(1, 20):02d}-{r.randint(1, 5)}",
                }
            )

    unit_cost = round(r.uniform(5, 500), 2)
    reorder_point = r.randint(3, 10)

    alternatives = []
    if r.random() > 0.4:
        alternatives.append(
            {
                "part_number": f"{prefix}-{r.randint(1000, 9999)}",
                "description": f"Compatible alternative - "
                f"{r.choice(['OEM equivalent', 'aftermarket', 'upgraded version'])}",
                "unit_cost": round(unit_cost * r.uniform(0.7, 1.3), 2),
                "in_stock": r.choice([True, True, False]),
            }
        )

    return tool_ok(
        {
            "part_number": part_number,
            "description": part_info["description"],
            "category": part_info["category"],
            "manufacturer": r.choice(
                [
                    "SKF",
                    "FAG/Schaeffler",
                    "NSK",
                    "Timken",
                    "Parker",
                    "Festo",
                    "Gates",
                    "Mobil",
                ]
            ),
            "unit_cost": unit_cost,
            "total_stock": total_stock,
            "stock_by_location": stock_by_location,
            "reorder_info": {
                "reorder_point": reorder_point,
                "economic_order_qty": r.randint(5, 25),
                "needs_reorder": total_stock <= reorder_point,
                "lead_time_days": r.randint(1, 30),
                "preferred_supplier": r.choice(SUPPLIERS),
            },
            "criticality": r.choice(["CRITICAL", "ESSENTIAL", "STANDARD"]),
            "alternative_parts": alternatives,
            "usage_rate": {
                "avg_monthly_consumption": round(r.uniform(0.5, 8), 1),
                "last_12_months_used": r.randint(2, 50),
            },
        },
        simulated=True,
    )


def order_spare_parts(part_number: str, quantity: int) -> dict:
    quantity = int(quantity)
    if quantity <= 0:
        return tool_error("quantity must be a positive integer")
    today = _today()
    r = _rng(
        "order_spare_parts", part_number.upper(), quantity, today.strftime("%Y-%m-%d")
    )

    unit_cost = round(r.uniform(5, 500), 2)
    lead_time_days = r.randint(1, 21)
    subtotal = round(unit_cost * quantity, 2)
    shipping = round(subtotal * r.uniform(0.03, 0.10), 2)
    supplier_name = r.choice(SUPPLIERS)

    return tool_ok(
        {
            "order_id": f"SPO-{r.randrange(16 ** 8):08X}",
            "status": "ORDER_PLACED",
            "part_number": part_number.upper(),
            "quantity": quantity,
            "unit_cost": unit_cost,
            "cost_breakdown": {
                "subtotal": subtotal,
                "shipping": shipping,
                "tax": round(subtotal * 0.08, 2),
                "total": round(subtotal + shipping + subtotal * 0.08, 2),
            },
            "supplier": {
                "name": supplier_name,
                "supplier_id": f"SUP-{r.randint(100, 999)}",
            },
            "delivery": {
                "lead_time_days": lead_time_days,
                "estimated_delivery": (today + timedelta(days=lead_time_days)).strftime(
                    "%Y-%m-%d"
                ),
                "shipping_method": r.choice(
                    ["Standard Ground", "Expedited", "Next-Day Air"]
                ),
                "delivery_location": r.choice(
                    ["Main Stores (WH-MAIN)", "Line-Side Stock A (WH-LSA)"]
                ),
            },
            "approval": {
                "status": "AUTO_APPROVED" if subtotal < 1000 else "PENDING_APPROVAL",
                "approver": "Auto" if subtotal < 1000 else "Maintenance Manager",
                "threshold": 1000.00,
            },
            "note": "Demo procurement system: order placement is simulated.",
        },
        simulated=True,
    )


def get_parts_forecast(equipment_id: str) -> dict:
    today = _today()
    r = _rng("parts_forecast", equipment_id.upper(), today.strftime("%Y-%m-%d"))
    forecast_specs = [
        (
            "BRG",
            "Deep groove ball bearing 6205-2RS",
            "Bearings",
            "Predictive: vibration trend indicates bearing wear",
            (7, 45),
            (15, 120),
        ),
        (
            "SEL",
            "Mechanical shaft seal 35mm",
            "Seals",
            "Scheduled: preventive maintenance due",
            (14, 60),
            (25, 180),
        ),
        (
            "LUB",
            "Synthetic bearing grease EP2 400g",
            "Lubricants",
            "Scheduled: lubrication interval approaching",
            (5, 30),
            (8, 35),
        ),
        (
            "FLT",
            "Hydraulic filter element 10 micron",
            "Filters",
            "Usage-based: filter life approaching limit",
            (10, 40),
            (20, 90),
        ),
        (
            "BLT",
            "V-belt B68",
            "Belts",
            "Preventive: belt replacement interval due",
            (20, 75),
            (10, 45),
        ),
    ]

    forecasted_parts = []
    for prefix, desc, cat, reason, needed_range, cost_range in forecast_specs:
        qty_needed = r.randint(1, 4)
        current_stock = r.randint(0, 5)
        part = {
            "part_number": f"{prefix}-{r.randint(1000, 9999)}",
            "description": desc,
            "category": cat,
            "forecast_reason": reason,
            "needed_by": (today + timedelta(days=r.randint(*needed_range))).strftime(
                "%Y-%m-%d"
            ),
            "quantity_needed": qty_needed,
            "current_stock": current_stock,
            "unit_cost": round(r.uniform(*cost_range), 2),
            "confidence": round(r.uniform(0.7, 0.98), 2),
            "stock_sufficient": current_stock >= qty_needed,
        }
        part["order_needed"] = not part["stock_sufficient"]
        if part["order_needed"]:
            part["order_quantity"] = qty_needed - current_stock + r.randint(1, 3)
        forecasted_parts.append(part)

    total_cost = sum(p["quantity_needed"] * p["unit_cost"] for p in forecasted_parts)
    order_needed = [p for p in forecasted_parts if p["order_needed"]]
    urgent = sum(
        1
        for p in order_needed
        if (
            datetime.strptime(p["needed_by"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            - today
        ).days
        < 14
    )

    return tool_ok(
        {
            "equipment_id": equipment_id,
            "forecast_period_days": 90,
            "total_parts_forecasted": len(forecasted_parts),
            "parts": forecasted_parts,
            "procurement_summary": {
                "parts_in_stock": sum(
                    1 for p in forecasted_parts if p["stock_sufficient"]
                ),
                "parts_to_order": len(order_needed),
                "estimated_total_cost": round(total_cost, 2),
                "urgent_orders": urgent,
            },
            "recommendation": (
                f"Order {len(order_needed)} parts to avoid maintenance delays. "
                f"Total estimated cost: ${round(total_cost, 2):,.2f}"
            ),
        },
        simulated=True,
    )


def get_parts_inventory_report() -> dict:
    today = _today()
    categories = [
        {"name": "Bearings"},
        {"name": "Seals & Gaskets"},
        {"name": "Filters"},
        {"name": "Belts & Hoses"},
        {"name": "Lubricants"},
        {"name": "Electrical Components"},
        {"name": "Valves & Fittings"},
        {"name": "Instrumentation"},
    ]

    category_data = []
    for cat in categories:
        r = _rng("parts_category", cat["name"], today.strftime("%Y-%m-%d"))
        total_skus = r.randint(20, 200)
        total_value = round(r.uniform(5000, 150000), 2)
        stockout_count = r.randint(0, int(total_skus * 0.08))
        excess_count = r.randint(0, int(total_skus * 0.15))
        category_data.append(
            {
                "category": cat["name"],
                "total_part_numbers": total_skus,
                "total_inventory_value": total_value,
                "stockout_items": stockout_count,
                "below_reorder_point": r.randint(stockout_count, stockout_count + 10),
                "excess_stock_items": excess_count,
                "excess_stock_value": round(
                    total_value * excess_count / total_skus * r.uniform(1.5, 3), 2
                ),
                "avg_turnover_ratio": round(r.uniform(1.5, 8.0), 1),
                "service_level_pct": round(r.uniform(88, 99), 1),
            }
        )

    r = _rng("parts_report", today.strftime("%Y-%m-%d"))
    total_value = sum(c["total_inventory_value"] for c in category_data)
    total_stockouts = sum(c["stockout_items"] for c in category_data)
    total_excess_value = sum(c["excess_stock_value"] for c in category_data)

    return tool_ok(
        {
            "report_date": today.strftime("%Y-%m-%d"),
            "inventory_summary": {
                "total_part_numbers": sum(
                    c["total_part_numbers"] for c in category_data
                ),
                "total_inventory_value": round(total_value, 2),
                "total_stockout_items": total_stockouts,
                "total_excess_value": round(total_excess_value, 2),
                "overall_service_level_pct": round(
                    sum(c["service_level_pct"] for c in category_data)
                    / len(category_data),
                    1,
                ),
                "inventory_accuracy_pct": round(r.uniform(94, 99.5), 1),
            },
            "by_category": category_data,
            "critical_stockouts": (
                [
                    {
                        "part_number": f"BRG-{r.randint(1000, 9999)}",
                        "description": "Critical bearing for CNC spindle",
                        "equipment_affected": "EQ-CNC-001, EQ-CNC-002",
                        "days_out_of_stock": r.randint(1, 14),
                    },
                    {
                        "part_number": f"SEL-{r.randint(1000, 9999)}",
                        "description": "Hydraulic pump seal",
                        "equipment_affected": "EQ-PUMP-001",
                        "days_out_of_stock": r.randint(1, 7),
                    },
                ]
                if total_stockouts > 0
                else []
            ),
            "kpis": {
                "inventory_turnover_ratio": round(r.uniform(2.5, 6.0), 1),
                "fill_rate_pct": round(r.uniform(90, 98), 1),
                "dead_stock_pct": round(r.uniform(2, 10), 1),
                "carrying_cost_pct": round(r.uniform(15, 25), 1),
                "avg_days_to_fulfill": round(r.uniform(0.5, 5), 1),
            },
            "recommendations": [
                f"Reorder {total_stockouts} critical parts immediately to restore service levels",
                f"Review {sum(c['excess_stock_items'] for c in category_data)} excess items for "
                f"potential return or redistribution (${round(total_excess_value, 2):,.2f} tied up)",
                "Implement consignment stocking for high-value, low-turnover bearings",
                "Set up vendor-managed inventory for filters and lubricants",
            ],
        },
        simulated=True,
    )


TOOLS = {
    "check_spare_parts": check_spare_parts,
    "order_spare_parts": order_spare_parts,
    "get_parts_forecast": get_parts_forecast,
    "get_parts_inventory_report": get_parts_inventory_report,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
