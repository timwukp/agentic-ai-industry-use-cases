"""Omnichannel inventory tools for the Retail Inventory Assistant.

Provides inventory conflict resolution, order routing optimization,
inventory reservation, and cross-channel stock synchronization.
"""

import json
import random
from datetime import datetime, timedelta

from strands import tool


@tool
def resolve_inventory_conflict(sku: str, channels: str) -> str:
    """Resolve inventory allocation conflicts across sales channels.

    When multiple channels compete for limited inventory, this tool determines
    optimal allocation based on demand priority, margin contribution, and
    fulfillment commitments.

    Args:
        sku: The SKU identifier experiencing allocation conflicts.
        channels: Comma-separated list of channels competing (e.g., 'online,store,marketplace,wholesale').

    Returns:
        JSON string with resolution strategy, allocation per channel, and justification.
    """
    channel_list = [c.strip() for c in channels.split(",")]
    total_available = random.randint(50, 500)
    total_demand = random.randint(int(total_available * 1.2), int(total_available * 3))

    allocations = []
    remaining = total_available
    for i, channel in enumerate(channel_list):
        if i == len(channel_list) - 1:
            allocated = remaining
        else:
            allocated = random.randint(0, remaining)
            remaining -= allocated

        channel_demand = random.randint(int(total_demand / len(channel_list) * 0.5),
                                        int(total_demand / len(channel_list) * 1.5))
        allocations.append({
            "channel": channel,
            "demand": channel_demand,
            "allocated": allocated,
            "fill_rate_pct": round(allocated / channel_demand * 100, 1) if channel_demand > 0 else 0,
            "priority_score": round(random.uniform(0.3, 1.0), 2),
            "margin_contribution_pct": round(random.uniform(15, 45), 1),
        })

    return json.dumps({
        "sku": sku,
        "total_available_units": total_available,
        "total_demand_units": total_demand,
        "shortage_units": total_demand - total_available,
        "resolution_strategy": random.choice([
            "PRIORITY_BASED", "PROPORTIONAL", "MARGIN_OPTIMIZED", "COMMITMENT_FIRST"
        ]),
        "allocations": allocations,
        "conflict_resolution_notes": random.choice([
            "Online channel prioritized due to higher margin and faster velocity",
            "Store allocation maintained to prevent stockout on committed displays",
            "Marketplace allocation reduced due to flexible fulfillment window",
            "Proportional allocation applied across all channels",
        ]),
        "next_replenishment_date": (datetime.utcnow() + timedelta(days=random.randint(2, 14))).strftime("%Y-%m-%d"),
        "resolved_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def optimize_order_routing(order_id: str) -> str:
    """Determine optimal fulfillment node for an order.

    Evaluates available fulfillment locations based on inventory availability,
    shipping cost, delivery speed, and current workload to route the order
    to the best fulfillment point.

    Args:
        order_id: The order identifier to route for fulfillment.

    Returns:
        JSON string with optimal routing decision, alternatives, and cost/speed comparison.
    """
    fulfillment_nodes = [
        {"node_id": "DC-EAST", "type": "Distribution Center", "location": "New Jersey"},
        {"node_id": "DC-WEST", "type": "Distribution Center", "location": "California"},
        {"node_id": "DC-CENTRAL", "type": "Distribution Center", "location": "Texas"},
        {"node_id": "STORE-142", "type": "Ship from Store", "location": "Chicago, IL"},
        {"node_id": "STORE-287", "type": "Ship from Store", "location": "Atlanta, GA"},
        {"node_id": "3PL-PARTNER", "type": "Third Party Logistics", "location": "Tennessee"},
    ]

    candidates = random.sample(fulfillment_nodes, random.randint(3, 5))

    scored_candidates = []
    for node in candidates:
        cost = round(random.uniform(3, 15), 2)
        days = random.randint(1, 5)
        availability = random.choice([True, True, True, False])
        workload_pct = round(random.uniform(40, 95), 1)

        score = round(
            (1 / cost) * 10 + (1 / days) * 5 + (1 if availability else 0) * 20 + (100 - workload_pct) / 100 * 5,
            2
        )

        scored_candidates.append({
            "node_id": node["node_id"],
            "type": node["type"],
            "location": node["location"],
            "shipping_cost": cost,
            "estimated_delivery_days": days,
            "inventory_available": availability,
            "current_workload_pct": workload_pct,
            "routing_score": score,
        })

    scored_candidates.sort(key=lambda x: x["routing_score"], reverse=True)
    optimal = scored_candidates[0]

    return json.dumps({
        "order_id": order_id,
        "optimal_node": {
            "node_id": optimal["node_id"],
            "type": optimal["type"],
            "location": optimal["location"],
            "estimated_delivery_days": optimal["estimated_delivery_days"],
            "shipping_cost": optimal["shipping_cost"],
        },
        "alternatives": scored_candidates[1:3],
        "routing_factors": {
            "inventory_availability_weight": 0.40,
            "shipping_cost_weight": 0.25,
            "delivery_speed_weight": 0.20,
            "workload_balance_weight": 0.15,
        },
        "split_shipment_required": random.choice([True, False, False, False]),
        "routed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def reserve_inventory(sku: str, channel: str, quantity: int) -> str:
    """Reserve inventory for high-probability sales on a specific channel.

    Creates a soft reservation to prevent overselling on high-demand items
    while maintaining availability visibility across other channels.

    Args:
        sku: The SKU to reserve inventory for.
        channel: The sales channel requesting the reservation.
        quantity: The number of units to reserve.

    Returns:
        JSON string with reservation confirmation, available balance, and expiration details.
    """
    current_stock = random.randint(quantity, quantity * 5)
    already_reserved = random.randint(0, int(current_stock * 0.4))
    available_to_reserve = current_stock - already_reserved

    reservation_success = quantity <= available_to_reserve
    reserved_qty = quantity if reservation_success else available_to_reserve

    reservation_id = f"RES-{datetime.now().strftime('%Y%m%d%H%M')}-{random.randint(1000, 9999)}"
    expiry_hours = random.choice([2, 4, 8, 12, 24])

    return json.dumps({
        "reservation_id": reservation_id if reservation_success else None,
        "sku": sku,
        "channel": channel,
        "status": "CONFIRMED" if reservation_success else "PARTIAL",
        "requested_quantity": quantity,
        "reserved_quantity": reserved_qty,
        "inventory_snapshot": {
            "total_stock": current_stock,
            "previously_reserved": already_reserved,
            "available_before_request": available_to_reserve,
            "available_after_request": available_to_reserve - reserved_qty,
        },
        "reservation_details": {
            "expires_at": (datetime.utcnow() + timedelta(hours=expiry_hours)).isoformat() + "Z",
            "expiry_hours": expiry_hours,
            "auto_release": True,
            "priority_level": random.choice(["STANDARD", "HIGH", "CRITICAL"]),
        },
        "reserved_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def sync_channel_stock(sku: str) -> str:
    """Synchronize stock levels across all sales channels for a SKU.

    Reconciles inventory counts across all channels, identifies discrepancies,
    and updates each channel with the correct available-to-sell quantity.

    Args:
        sku: The SKU to synchronize stock levels for.

    Returns:
        JSON string with synchronization results, discrepancies found, and updated stock levels.
    """
    total_physical_stock = random.randint(100, 2000)

    channels = [
        {"channel": "Online Store", "channel_id": "WEB"},
        {"channel": "Marketplace A", "channel_id": "MKT-A"},
        {"channel": "Marketplace B", "channel_id": "MKT-B"},
        {"channel": "Store POS Network", "channel_id": "POS"},
        {"channel": "Wholesale Portal", "channel_id": "WHL"},
    ]

    channel_stocks = []
    total_listed = 0
    discrepancies = 0

    for ch in channels:
        listed_qty = random.randint(0, int(total_physical_stock * 0.5))
        actual_available = random.randint(0, int(total_physical_stock * 0.4))
        has_discrepancy = listed_qty != actual_available

        if has_discrepancy:
            discrepancies += 1

        channel_stocks.append({
            "channel": ch["channel"],
            "channel_id": ch["channel_id"],
            "listed_quantity": listed_qty,
            "corrected_quantity": actual_available,
            "discrepancy": listed_qty - actual_available,
            "status": "CORRECTED" if has_discrepancy else "IN_SYNC",
        })
        total_listed += listed_qty

    safety_stock = random.randint(10, 50)
    available_to_sell = max(0, total_physical_stock - safety_stock)

    return json.dumps({
        "sku": sku,
        "sync_status": "COMPLETED",
        "physical_stock": total_physical_stock,
        "safety_stock_reserved": safety_stock,
        "available_to_sell": available_to_sell,
        "channels_synced": len(channels),
        "discrepancies_found": discrepancies,
        "channel_details": channel_stocks,
        "oversell_risk": total_listed > available_to_sell,
        "last_physical_count": (datetime.utcnow() - timedelta(hours=random.randint(1, 48))).isoformat() + "Z",
        "synced_at": datetime.utcnow().isoformat() + "Z",
    })
