"""Supply chain resilience tools for the Manufacturing Maintenance Assistant.

Provides disruption impact assessment, alternative supplier sourcing, shortage
scenario simulation, and contingency plan generation for supply chain management.
"""

import json
import random
from datetime import datetime, timedelta

from strands import tool


@tool
def assess_disruption_impact(event_type: str, region: str) -> str:
    """Assess the impact of a supply chain disruption event.

    Evaluates how a disruption event in a specific region will affect
    material availability, production schedules, and downstream deliveries.

    Args:
        event_type: Type of disruption (e.g., 'natural_disaster', 'port_closure', 'supplier_bankruptcy', 'geopolitical').
        region: Geographic region affected (e.g., 'East Asia', 'Europe', 'North America', 'Southeast Asia').

    Returns:
        JSON string with disruption impact assessment including severity and affected operations.
    """
    severity = random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    affected_materials = random.sample([
        {"material": "Semiconductor chips", "supply_risk": "CRITICAL", "current_stock_days": random.randint(5, 45)},
        {"material": "Rare earth metals", "supply_risk": "HIGH", "current_stock_days": random.randint(10, 60)},
        {"material": "Specialty chemicals", "supply_risk": "MEDIUM", "current_stock_days": random.randint(15, 90)},
        {"material": "Steel alloy components", "supply_risk": "MEDIUM", "current_stock_days": random.randint(20, 60)},
        {"material": "Electronic assemblies", "supply_risk": "HIGH", "current_stock_days": random.randint(7, 30)},
        {"material": "Polymer resins", "supply_risk": "LOW", "current_stock_days": random.randint(30, 120)},
        {"material": "Precision bearings", "supply_risk": "MEDIUM", "current_stock_days": random.randint(15, 45)},
    ], random.randint(3, 5))

    production_impact = {
        "lines_affected": random.randint(1, 8),
        "total_lines": random.randint(8, 20),
        "estimated_capacity_loss_pct": round(random.uniform(5, 60), 1),
        "first_impact_date": (datetime.utcnow() + timedelta(days=random.randint(3, 30))).strftime("%Y-%m-%d"),
        "estimated_duration_weeks": random.randint(2, 26),
    }

    financial_impact = {
        "estimated_revenue_at_risk": round(random.uniform(500000, 25000000), 2),
        "expediting_costs": round(random.uniform(50000, 2000000), 2),
        "penalty_clauses_at_risk": round(random.uniform(100000, 5000000), 2),
    }

    return json.dumps({
        "event_type": event_type,
        "region": region,
        "severity": severity,
        "affected_materials": affected_materials,
        "production_impact": production_impact,
        "financial_impact": financial_impact,
        "customer_delivery_risk": {
            "orders_at_risk": random.randint(10, 200),
            "customers_affected": random.randint(5, 50),
            "earliest_delivery_delay_days": random.randint(3, 45),
        },
        "recommended_actions": [
            "Activate alternative supplier agreements",
            "Assess safety stock reallocation across sites",
            "Communicate proactively with at-risk customers",
            "Evaluate air freight vs. production schedule adjustment",
        ],
        "assessed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def find_alternative_suppliers(material: str, urgency: str) -> str:
    """Find and rank alternative suppliers for a material.

    Searches qualified supplier databases and identifies potential alternates
    ranked by lead time, quality certification, capacity, and cost.

    Args:
        material: The material or component requiring alternative supply.
        urgency: The urgency level (e.g., 'IMMEDIATE', 'SHORT_TERM', 'LONG_TERM').

    Returns:
        JSON string with ranked alternative suppliers and qualification status.
    """
    regions = ["North America", "Europe", "East Asia", "Southeast Asia", "South America"]

    suppliers = []
    num_alternatives = random.randint(3, 6)
    for i in range(num_alternatives):
        lead_time_weeks = random.randint(2, 16)
        quality_cert = random.choice([True, True, True, False])
        capacity_available_pct = round(random.uniform(10, 80), 1)
        price_premium_pct = round(random.uniform(-5, 35), 1)

        score = round(
            (1 / lead_time_weeks) * 30
            + (1 if quality_cert else 0) * 25
            + capacity_available_pct / 100 * 25
            + max(0, (20 - price_premium_pct)) / 20 * 20,
            1
        )

        suppliers.append({
            "supplier_name": f"Supplier {chr(65 + i)} ({random.choice(regions)})",
            "qualification_status": random.choice(["QUALIFIED", "QUALIFIED", "PENDING_QUALIFICATION", "NEW"]),
            "lead_time_weeks": lead_time_weeks,
            "quality_certified": quality_cert,
            "certifications": random.sample(["ISO 9001", "IATF 16949", "AS9100", "ISO 14001"], random.randint(1, 3)),
            "available_capacity_pct": capacity_available_pct,
            "price_premium_pct": price_premium_pct,
            "min_order_quantity": random.randint(100, 5000),
            "overall_score": score,
        })

    suppliers.sort(key=lambda x: x["overall_score"], reverse=True)

    qualification_needed = [s for s in suppliers if s["qualification_status"] != "QUALIFIED"]

    return json.dumps({
        "material": material,
        "urgency": urgency,
        "alternatives_found": num_alternatives,
        "suppliers": suppliers,
        "top_recommendation": suppliers[0]["supplier_name"],
        "qualification_requirements": {
            "suppliers_needing_qualification": len(qualification_needed),
            "estimated_qualification_weeks": random.randint(4, 16),
            "fast_track_available": urgency == "IMMEDIATE",
        },
        "risk_assessment": {
            "single_source_risk": "HIGH" if num_alternatives < 3 else "MEDIUM",
            "geographic_concentration": random.choice(["DIVERSIFIED", "CONCENTRATED"]),
        },
        "searched_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def simulate_shortage_scenario(material: str, duration_days: int) -> str:
    """Simulate production impact of a material shortage.

    Models the cascading effects of a material shortage over the specified
    duration, including production line stoppages, partial builds, and
    downstream delivery impacts.

    Args:
        material: The material experiencing or expected to experience shortage.
        duration_days: The expected shortage duration in days.

    Returns:
        JSON string with simulation results showing production and financial impact over time.
    """
    daily_usage = random.randint(50, 5000)
    current_inventory = random.randint(daily_usage * 2, daily_usage * 30)
    days_of_stock = int(current_inventory / daily_usage)

    weekly_impact = []
    weeks = max(1, duration_days // 7)
    remaining_inventory = current_inventory

    for week in range(1, min(weeks + 1, 13)):
        week_usage = daily_usage * 7
        if remaining_inventory >= week_usage:
            production_pct = 100
            remaining_inventory -= week_usage
        elif remaining_inventory > 0:
            production_pct = round(remaining_inventory / week_usage * 100, 1)
            remaining_inventory = 0
        else:
            production_pct = 0

        weekly_impact.append({
            "week": week,
            "production_capacity_pct": production_pct,
            "units_produced": int(daily_usage * 7 * production_pct / 100),
            "units_lost": int(daily_usage * 7 * (100 - production_pct) / 100),
            "remaining_inventory": max(0, remaining_inventory),
        })

    total_units_lost = sum(w["units_lost"] for w in weekly_impact)
    unit_value = round(random.uniform(50, 2000), 2)
    revenue_impact = round(total_units_lost * unit_value, 2)

    return json.dumps({
        "material": material,
        "shortage_duration_days": duration_days,
        "current_state": {
            "daily_usage_units": daily_usage,
            "current_inventory_units": current_inventory,
            "days_of_stock_remaining": days_of_stock,
            "stockout_date": (datetime.utcnow() + timedelta(days=days_of_stock)).strftime("%Y-%m-%d"),
        },
        "simulation_results": {
            "weekly_impact": weekly_impact,
            "total_units_lost": total_units_lost,
            "peak_impact_week": max(weekly_impact, key=lambda w: w["units_lost"])["week"],
            "full_recovery_week": weeks + random.randint(1, 4),
        },
        "financial_impact": {
            "revenue_at_risk": revenue_impact,
            "unit_value": unit_value,
            "expediting_cost_estimate": round(revenue_impact * random.uniform(0.05, 0.15), 2),
            "customer_penalty_risk": round(revenue_impact * random.uniform(0.02, 0.1), 2),
        },
        "mitigation_options": [
            {"option": "Air freight from alternate supplier", "cost": round(random.uniform(50000, 500000), 2),
             "time_to_implement_days": random.randint(3, 10)},
            {"option": "Partial substitution with qualified alternate", "cost": round(random.uniform(20000, 200000), 2),
             "time_to_implement_days": random.randint(7, 21)},
            {"option": "Production schedule resequencing", "cost": round(random.uniform(10000, 50000), 2),
             "time_to_implement_days": random.randint(1, 5)},
        ],
        "simulated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_contingency_plan(disruption_id: str) -> str:
    """Generate a supply chain contingency plan for an active disruption.

    Creates a structured response plan with immediate, short-term, and
    long-term actions to mitigate the disruption's impact on operations.

    Args:
        disruption_id: The disruption event identifier to generate a plan for.

    Returns:
        JSON string with contingency plan including phased actions and resource requirements.
    """
    plan_id = f"CTP-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    immediate_actions = random.sample([
        {"action": "Activate safety stock reserves", "owner": "Supply Chain Manager",
         "timeline": "0-24 hours", "status": random.choice(["COMPLETE", "IN_PROGRESS"])},
        {"action": "Contact all qualified alternate suppliers", "owner": "Procurement Lead",
         "timeline": "0-48 hours", "status": random.choice(["COMPLETE", "IN_PROGRESS"])},
        {"action": "Assess and communicate customer delivery impact", "owner": "Customer Service Director",
         "timeline": "0-24 hours", "status": random.choice(["COMPLETE", "IN_PROGRESS"])},
        {"action": "Implement production line prioritization", "owner": "Operations Director",
         "timeline": "0-24 hours", "status": random.choice(["COMPLETE", "IN_PROGRESS"])},
    ], 3)

    short_term_actions = random.sample([
        {"action": "Qualify and onboard emergency suppliers", "owner": "Supplier Quality",
         "timeline": "1-4 weeks", "status": "PLANNED"},
        {"action": "Implement product redesign for material substitution", "owner": "Engineering",
         "timeline": "2-6 weeks", "status": "PLANNED"},
        {"action": "Negotiate expedited shipping agreements", "owner": "Logistics Manager",
         "timeline": "1-2 weeks", "status": "PLANNED"},
        {"action": "Reallocate inventory across production sites", "owner": "Supply Planning",
         "timeline": "1-2 weeks", "status": "PLANNED"},
    ], 3)

    long_term_actions = random.sample([
        {"action": "Diversify supply base with multi-region sourcing", "owner": "VP Supply Chain",
         "timeline": "3-6 months", "status": "PLANNED"},
        {"action": "Increase strategic safety stock for critical materials", "owner": "Inventory Planning",
         "timeline": "1-3 months", "status": "PLANNED"},
        {"action": "Implement supply chain visibility platform", "owner": "Digital Transformation",
         "timeline": "6-12 months", "status": "PLANNED"},
        {"action": "Develop near-shoring partnerships", "owner": "Strategic Sourcing",
         "timeline": "6-12 months", "status": "PLANNED"},
    ], 3)

    return json.dumps({
        "plan_id": plan_id,
        "disruption_id": disruption_id,
        "plan_status": "ACTIVE",
        "phases": {
            "immediate_0_48h": immediate_actions,
            "short_term_1_6_weeks": short_term_actions,
            "long_term_recovery": long_term_actions,
        },
        "resource_requirements": {
            "budget_allocated": round(random.uniform(100000, 5000000), 2),
            "personnel_assigned": random.randint(5, 25),
            "executive_sponsor": "VP Operations",
        },
        "communication_plan": {
            "internal_stakeholders": ["Executive team", "Production managers", "Sales team"],
            "external_stakeholders": ["Key customers", "Logistics partners", "Board of directors"],
            "update_frequency": "Daily during active disruption, weekly during recovery",
        },
        "success_metrics": [
            "Maintain minimum 70% production capacity",
            "Zero lost customer orders",
            "Recovery to full production within target timeline",
            "Contingency cost within allocated budget",
        ],
        "next_review_date": (datetime.utcnow() + timedelta(days=3)).strftime("%Y-%m-%d"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })
