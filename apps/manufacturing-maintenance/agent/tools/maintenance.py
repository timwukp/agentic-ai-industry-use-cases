from strands import tool
import json, random, uuid
from datetime import datetime, timedelta


@tool
def schedule_maintenance(equipment_id: str, maintenance_type: str, priority: str) -> str:
    """Schedule a maintenance activity for equipment.

    Creates a maintenance schedule entry with resource allocation, estimated duration,
    and impact assessment. Supports preventive, predictive, and corrective maintenance types.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001').
        maintenance_type: Type of maintenance ('preventive', 'predictive', 'corrective').
        priority: Priority level ('critical', 'high', 'medium', 'low').

    Returns:
        JSON with schedule confirmation, resource assignments, and production impact estimate.
    """
    valid_types = ["preventive", "predictive", "corrective"]
    valid_priorities = ["critical", "high", "medium", "low"]

    if maintenance_type.lower() not in valid_types:
        return json.dumps({"error": f"Invalid maintenance_type. Must be one of: {valid_types}"})
    if priority.lower() not in valid_priorities:
        return json.dumps({"error": f"Invalid priority. Must be one of: {valid_priorities}"})

    schedule_id = f"SCH-{uuid.uuid4().hex[:8].upper()}"

    priority_lead_days = {"critical": 0, "high": 1, "medium": 7, "low": 14}
    lead_days = priority_lead_days.get(priority.lower(), 7)
    scheduled_date = datetime.utcnow() + timedelta(days=lead_days + random.randint(0, 3))

    duration_hours = round(random.uniform(1, 24), 1)
    if maintenance_type.lower() == "corrective":
        duration_hours = round(random.uniform(2, 48), 1)

    technicians = [
        {"name": "Mike Rodriguez", "specialization": "Mechanical", "cert_level": "Senior"},
        {"name": "Sarah Chen", "specialization": "Electrical", "cert_level": "Senior"},
        {"name": "James Wilson", "specialization": "Instrumentation", "cert_level": "Mid"},
        {"name": "Ana Petrova", "specialization": "Mechanical", "cert_level": "Mid"},
    ]

    assigned = random.sample(technicians, random.randint(1, 2))

    return json.dumps({
        "schedule_id": schedule_id,
        "status": "SCHEDULED",
        "equipment_id": equipment_id,
        "maintenance_type": maintenance_type.upper(),
        "priority": priority.upper(),
        "scheduled_date": scheduled_date.strftime("%Y-%m-%d"),
        "scheduled_time": f"{random.randint(6, 14):02d}:00",
        "estimated_duration_hours": duration_hours,
        "estimated_completion": (scheduled_date + timedelta(hours=duration_hours)).strftime("%Y-%m-%d %H:%M"),
        "assigned_technicians": assigned,
        "required_permits": [
            "LOTO (Lock-Out Tag-Out)" if random.random() > 0.3 else None,
            "Confined Space Entry" if random.random() > 0.7 else None,
            "Hot Work Permit" if random.random() > 0.8 else None,
        ],
        "production_impact": {
            "line_affected": f"Line {random.choice(['A', 'B', 'C'])}",
            "estimated_production_loss_units": random.randint(0, 500),
            "estimated_cost_of_downtime": round(random.uniform(500, 25000), 2),
            "alternative_routing_available": random.choice([True, False]),
        },
        "safety_requirements": [
            "Personal Protective Equipment (PPE) required",
            "Lock-Out Tag-Out (LOTO) procedure must be followed",
            "Area isolation required during maintenance",
        ],
        "created_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_work_order(equipment_id: str, description: str, priority: str) -> str:
    """Create a maintenance work order with task breakdown and resource requirements.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001').
        description: Description of the maintenance work needed.
        priority: Priority level ('critical', 'high', 'medium', 'low').

    Returns:
        JSON with work order number, task list, parts required, labor estimate, and approval status.
    """
    wo_number = f"WO-{datetime.now().strftime('%Y%m%d')}-{random.randint(10000, 99999)}"

    task_templates = [
        {"task": "Isolate equipment and apply LOTO", "duration_min": 15, "skill": "General"},
        {"task": "Perform visual inspection of components", "duration_min": 30, "skill": "Mechanical"},
        {"task": "Remove and inspect bearing assembly", "duration_min": 60, "skill": "Mechanical"},
        {"task": "Replace worn bearing with new unit", "duration_min": 45, "skill": "Mechanical"},
        {"task": "Check shaft alignment using laser alignment tool", "duration_min": 30, "skill": "Instrumentation"},
        {"task": "Refill and test lubrication system", "duration_min": 20, "skill": "Mechanical"},
        {"task": "Perform electrical insulation resistance test", "duration_min": 25, "skill": "Electrical"},
        {"task": "Run vibration baseline measurement", "duration_min": 20, "skill": "Instrumentation"},
        {"task": "Remove LOTO and perform test run", "duration_min": 30, "skill": "General"},
        {"task": "Document findings and update maintenance records", "duration_min": 15, "skill": "General"},
    ]

    num_tasks = random.randint(4, 8)
    tasks = random.sample(task_templates, num_tasks)
    for i, task in enumerate(tasks):
        task["sequence"] = i + 1
        task["status"] = "PENDING"

    total_labor_min = sum(t["duration_min"] for t in tasks)

    parts_needed = [
        {"part_number": f"BRG-{random.randint(1000, 9999)}", "description": "Deep groove ball bearing 6205-2RS", "quantity": random.randint(1, 2), "unit_cost": round(random.uniform(15, 150), 2)},
        {"part_number": f"SEL-{random.randint(1000, 9999)}", "description": "Mechanical shaft seal 35mm", "quantity": 1, "unit_cost": round(random.uniform(25, 200), 2)},
        {"part_number": f"LUB-{random.randint(1000, 9999)}", "description": "Synthetic bearing grease 400g", "quantity": 1, "unit_cost": round(random.uniform(8, 35), 2)},
    ]

    parts_cost = sum(p["quantity"] * p["unit_cost"] for p in parts_needed)
    labor_cost = round(total_labor_min / 60 * random.uniform(65, 120), 2)

    return json.dumps({
        "work_order_number": wo_number,
        "status": "CREATED",
        "equipment_id": equipment_id,
        "description": description,
        "priority": priority.upper(),
        "created_by": "Predictive Maintenance AI",
        "tasks": tasks,
        "parts_required": parts_needed,
        "cost_estimate": {
            "parts_cost": round(parts_cost, 2),
            "labor_cost": labor_cost,
            "total_estimated_cost": round(parts_cost + labor_cost, 2),
        },
        "labor_estimate": {
            "total_hours": round(total_labor_min / 60, 1),
            "technicians_required": random.randint(1, 3),
            "skills_required": list(set(t["skill"] for t in tasks)),
        },
        "approval": {
            "status": "AUTO_APPROVED" if priority.lower() in ["critical", "high"] else "PENDING_APPROVAL",
            "approver": "Maintenance Supervisor" if priority.lower() not in ["critical", "high"] else "Auto-approved (safety-critical)",
        },
        "target_completion": (datetime.utcnow() + timedelta(days={"critical": 1, "high": 3, "medium": 7, "low": 14}.get(priority.lower(), 7))).strftime("%Y-%m-%d"),
        "created_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_maintenance_history(equipment_id: str, months: int) -> str:
    """Get historical maintenance records for equipment.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001').
        months: Number of months of history to retrieve (1-24).

    Returns:
        JSON with maintenance records, cost summary, and failure pattern analysis.
    """
    months = min(max(months, 1), 24)

    maintenance_types = ["PREVENTIVE", "PREDICTIVE", "CORRECTIVE", "EMERGENCY"]
    type_weights = [0.4, 0.25, 0.25, 0.1]

    records = []
    num_records = random.randint(months, months * 3)
    for _ in range(num_records):
        mt = random.choices(maintenance_types, weights=type_weights, k=1)[0]
        cost = round(random.uniform(100, 15000), 2)
        downtime_hours = round(random.uniform(0.5, 48), 1)

        records.append({
            "work_order": f"WO-{random.randint(20230101, 20261231)}-{random.randint(10000, 99999)}",
            "date": (datetime.utcnow() - timedelta(days=random.randint(1, months * 30))).strftime("%Y-%m-%d"),
            "type": mt,
            "description": random.choice([
                "Bearing replacement - drive end",
                "Routine lubrication and filter change",
                "Vibration-triggered seal replacement",
                "Electrical panel inspection and cleaning",
                "Alignment correction and coupling inspection",
                "Emergency motor replacement",
                "Preventive gearbox oil change",
                "Sensor calibration and wiring check",
                "Coolant system flush and refill",
                "Belt tension adjustment and replacement",
            ]),
            "downtime_hours": downtime_hours,
            "cost": cost,
            "technician": random.choice(["M. Rodriguez", "S. Chen", "J. Wilson", "A. Petrova", "D. Kim"]),
            "outcome": random.choice(["COMPLETED", "COMPLETED", "COMPLETED", "PARTIAL", "DEFERRED"]),
        })

    records.sort(key=lambda r: r["date"], reverse=True)

    total_cost = sum(r["cost"] for r in records)
    total_downtime = sum(r["downtime_hours"] for r in records)
    corrective_pct = sum(1 for r in records if r["type"] in ["CORRECTIVE", "EMERGENCY"]) / len(records) * 100

    return json.dumps({
        "equipment_id": equipment_id,
        "period_months": months,
        "total_records": len(records),
        "records": records[:15],  # Return most recent 15
        "summary": {
            "total_maintenance_cost": round(total_cost, 2),
            "avg_cost_per_event": round(total_cost / len(records), 2),
            "total_downtime_hours": round(total_downtime, 1),
            "avg_downtime_per_event_hours": round(total_downtime / len(records), 1),
            "by_type": {
                mt: sum(1 for r in records if r["type"] == mt) for mt in maintenance_types
            },
            "reactive_maintenance_pct": round(corrective_pct, 1),
        },
        "patterns": {
            "most_common_issue": random.choice(["Bearing failure", "Seal wear", "Electrical faults"]),
            "avg_time_between_failures_days": random.randint(30, 180),
            "seasonal_pattern": random.choice(["Higher failures in summer (heat-related)", "No significant seasonal pattern", "Increased issues after holiday shutdowns"]),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_maintenance_calendar(facility_id: str, days: int) -> str:
    """Get upcoming maintenance schedule for a facility.

    Args:
        facility_id: Facility identifier (e.g., 'FAC-NORTH', 'all').
        days: Number of days ahead to show (1-90).

    Returns:
        JSON with scheduled maintenance activities, resource allocation, and capacity impact.
    """
    days = min(max(days, 1), 90)

    equipment_ids = [
        "EQ-CNC-001", "EQ-CNC-002", "EQ-CNC-003",
        "EQ-PUMP-001", "EQ-PUMP-002",
        "EQ-COMP-001", "EQ-CONV-001", "EQ-CONV-002",
        "EQ-TURB-001", "EQ-MOTOR-001", "EQ-MOTOR-002",
    ]

    scheduled_items = []
    num_items = random.randint(days // 3, days)
    for _ in range(num_items):
        sched_date = datetime.utcnow() + timedelta(days=random.randint(1, days))
        duration = round(random.uniform(1, 16), 1)

        scheduled_items.append({
            "schedule_id": f"SCH-{uuid.uuid4().hex[:8].upper()}",
            "equipment_id": random.choice(equipment_ids),
            "date": sched_date.strftime("%Y-%m-%d"),
            "start_time": f"{random.randint(6, 14):02d}:00",
            "duration_hours": duration,
            "type": random.choice(["PREVENTIVE", "PREDICTIVE", "INSPECTION", "CALIBRATION"]),
            "priority": random.choice(["HIGH", "MEDIUM", "MEDIUM", "LOW"]),
            "description": random.choice([
                "Quarterly bearing inspection",
                "Vibration-based predictive maintenance",
                "Lubrication schedule - routine",
                "Annual motor insulation test",
                "Sensor calibration",
                "Filter replacement and cleaning",
                "Alignment verification",
                "Safety system functional test",
                "Oil analysis sampling",
                "Thermal imaging survey",
            ]),
            "assigned_to": random.choice(["M. Rodriguez", "S. Chen", "J. Wilson", "A. Petrova"]),
            "status": random.choice(["SCHEDULED", "CONFIRMED", "PARTS_ORDERED"]),
        })

    scheduled_items.sort(key=lambda s: s["date"])

    # Weekly capacity summary
    weeks = {}
    for item in scheduled_items:
        week = datetime.strptime(item["date"], "%Y-%m-%d").isocalendar()[1]
        weeks.setdefault(week, {"maintenance_hours": 0, "events": 0})
        weeks[week]["maintenance_hours"] = round(weeks[week]["maintenance_hours"] + item["duration_hours"], 1)
        weeks[week]["events"] += 1

    return json.dumps({
        "facility_id": facility_id,
        "period_days": days,
        "total_scheduled": len(scheduled_items),
        "schedule": scheduled_items[:20],  # Return next 20 items
        "weekly_capacity": {f"Week {k}": v for k, v in sorted(weeks.items())},
        "resource_utilization": {
            "total_maintenance_hours": round(sum(s["duration_hours"] for s in scheduled_items), 1),
            "technician_hours_available": days * 4 * 8,  # 4 techs, 8 hours/day
            "utilization_pct": round(sum(s["duration_hours"] for s in scheduled_items) / (days * 4 * 8) * 100, 1),
        },
        "conflicts": [
            {"date": (datetime.utcnow() + timedelta(days=random.randint(1, days))).strftime("%Y-%m-%d"), "issue": "Two high-priority jobs overlap - need additional technician", "resolution": "Request contractor support"},
        ] if random.random() > 0.5 else [],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
