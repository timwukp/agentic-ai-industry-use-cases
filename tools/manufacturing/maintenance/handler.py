"""Gateway target: maintenance — scheduling, work orders, history, calendar.

Maintenance data is a deterministic simulation seeded from the function inputs
(stable within a calendar day).
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

VALID_TYPES = ["preventive", "predictive", "corrective"]
VALID_PRIORITIES = ["critical", "high", "medium", "low"]
PRIORITY_LEAD_DAYS = {"critical": 0, "high": 1, "medium": 7, "low": 14}
PRIORITY_TARGET_DAYS = {"critical": 1, "high": 3, "medium": 7, "low": 14}

TECHNICIANS = [
    {"name": "Mike Rodriguez", "specialization": "Mechanical", "cert_level": "Senior"},
    {"name": "Sarah Chen", "specialization": "Electrical", "cert_level": "Senior"},
    {"name": "James Wilson", "specialization": "Instrumentation", "cert_level": "Mid"},
    {"name": "Ana Petrova", "specialization": "Mechanical", "cert_level": "Mid"},
]

TASK_TEMPLATES = [
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

EQUIPMENT_IDS = [
    "EQ-CNC-001", "EQ-CNC-002", "EQ-CNC-003",
    "EQ-PUMP-001", "EQ-PUMP-002",
    "EQ-COMP-001", "EQ-CONV-001", "EQ-CONV-002",
    "EQ-TURB-001", "EQ-MOTOR-001", "EQ-MOTOR-002",
]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def schedule_maintenance(equipment_id: str, maintenance_type: str, priority: str) -> dict:
    maintenance_type, priority = maintenance_type.lower(), priority.lower()
    if maintenance_type not in VALID_TYPES:
        return tool_error(f"Invalid maintenance_type: {maintenance_type}", valid=VALID_TYPES)
    if priority not in VALID_PRIORITIES:
        return tool_error(f"Invalid priority: {priority}", valid=VALID_PRIORITIES)

    today = _today()
    r = _rng("schedule_maintenance", equipment_id.upper(), maintenance_type, priority,
             today.strftime("%Y-%m-%d"))
    scheduled_date = today + timedelta(days=PRIORITY_LEAD_DAYS[priority] + r.randint(0, 3))
    duration_hours = round(r.uniform(2, 48) if maintenance_type == "corrective"
                           else r.uniform(1, 24), 1)

    return tool_ok({
        "schedule_id": f"SCH-{r.randrange(16 ** 8):08X}",
        "status": "SCHEDULED",
        "equipment_id": equipment_id,
        "maintenance_type": maintenance_type.upper(),
        "priority": priority.upper(),
        "scheduled_date": scheduled_date.strftime("%Y-%m-%d"),
        "scheduled_time": f"{r.randint(6, 14):02d}:00",
        "estimated_duration_hours": duration_hours,
        "assigned_technicians": r.sample(TECHNICIANS, r.randint(1, 2)),
        "required_permits": [p for p in [
            "LOTO (Lock-Out Tag-Out)" if r.random() > 0.3 else None,
            "Confined Space Entry" if r.random() > 0.7 else None,
            "Hot Work Permit" if r.random() > 0.8 else None,
        ] if p],
        "production_impact": {
            "line_affected": f"Line {r.choice(['A', 'B', 'C'])}",
            "estimated_production_loss_units": r.randint(0, 500),
            "estimated_cost_of_downtime": round(r.uniform(500, 25000), 2),
            "alternative_routing_available": r.choice([True, False]),
        },
        "safety_requirements": [
            "Personal Protective Equipment (PPE) required",
            "Lock-Out Tag-Out (LOTO) procedure must be followed",
            "Area isolation required during maintenance",
        ],
        "note": "Demo CMMS: scheduling is simulated.",
    }, simulated=True)


def generate_work_order(equipment_id: str, description: str, priority: str) -> dict:
    priority = priority.lower()
    if priority not in VALID_PRIORITIES:
        return tool_error(f"Invalid priority: {priority}", valid=VALID_PRIORITIES)

    today = _today()
    r = _rng("work_order", equipment_id.upper(), description, priority,
             today.strftime("%Y-%m-%d"))
    now = datetime.now(timezone.utc)

    tasks = [dict(t) for t in r.sample(TASK_TEMPLATES, r.randint(4, 8))]
    for i, task in enumerate(tasks):
        task["sequence"] = i + 1
        task["status"] = "PENDING"
    total_labor_min = sum(t["duration_min"] for t in tasks)

    parts_needed = [
        {"part_number": f"BRG-{r.randint(1000, 9999)}",
         "description": "Deep groove ball bearing 6205-2RS",
         "quantity": r.randint(1, 2), "unit_cost": round(r.uniform(15, 150), 2)},
        {"part_number": f"SEL-{r.randint(1000, 9999)}",
         "description": "Mechanical shaft seal 35mm",
         "quantity": 1, "unit_cost": round(r.uniform(25, 200), 2)},
        {"part_number": f"LUB-{r.randint(1000, 9999)}",
         "description": "Synthetic bearing grease 400g",
         "quantity": 1, "unit_cost": round(r.uniform(8, 35), 2)},
    ]
    parts_cost = sum(p["quantity"] * p["unit_cost"] for p in parts_needed)
    labor_cost = round(total_labor_min / 60 * r.uniform(65, 120), 2)

    return tool_ok({
        "work_order_number": f"WO-{now.strftime('%Y%m%d')}-{r.randint(10000, 99999)}",
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
            "technicians_required": r.randint(1, 3),
            "skills_required": sorted(set(t["skill"] for t in tasks)),
        },
        "approval": {
            "status": ("AUTO_APPROVED" if priority in ("critical", "high")
                       else "PENDING_APPROVAL"),
            "approver": ("Auto-approved (safety-critical)" if priority in ("critical", "high")
                         else "Maintenance Supervisor"),
        },
        "target_completion": (today + timedelta(days=PRIORITY_TARGET_DAYS[priority]))
        .strftime("%Y-%m-%d"),
        "note": "Demo CMMS: work order creation is simulated.",
    }, simulated=True)


def get_maintenance_history(equipment_id: str, months: int = 12) -> dict:
    months = min(max(int(months), 1), 24)
    today = _today()
    r = _rng("maintenance_history", equipment_id.upper(), months)
    maintenance_types = ["PREVENTIVE", "PREDICTIVE", "CORRECTIVE", "EMERGENCY"]

    records = []
    for _ in range(r.randint(months, months * 3)):
        mt = r.choices(maintenance_types, weights=[0.4, 0.25, 0.25, 0.1], k=1)[0]
        records.append({
            "work_order": f"WO-{r.randint(20230101, 20261231)}-{r.randint(10000, 99999)}",
            "date": (today - timedelta(days=r.randint(1, months * 30))).strftime("%Y-%m-%d"),
            "type": mt,
            "description": r.choice([
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
            "downtime_hours": round(r.uniform(0.5, 48), 1),
            "cost": round(r.uniform(100, 15000), 2),
            "technician": r.choice(["M. Rodriguez", "S. Chen", "J. Wilson", "A. Petrova", "D. Kim"]),
            "outcome": r.choice(["COMPLETED", "COMPLETED", "COMPLETED", "PARTIAL", "DEFERRED"]),
        })
    records.sort(key=lambda x: x["date"], reverse=True)

    total_cost = sum(x["cost"] for x in records)
    total_downtime = sum(x["downtime_hours"] for x in records)
    corrective_pct = (sum(1 for x in records if x["type"] in ("CORRECTIVE", "EMERGENCY"))
                      / len(records) * 100)

    return tool_ok({
        "equipment_id": equipment_id,
        "period_months": months,
        "total_records": len(records),
        "records": records[:15],
        "summary": {
            "total_maintenance_cost": round(total_cost, 2),
            "avg_cost_per_event": round(total_cost / len(records), 2),
            "total_downtime_hours": round(total_downtime, 1),
            "avg_downtime_per_event_hours": round(total_downtime / len(records), 1),
            "by_type": {mt: sum(1 for x in records if x["type"] == mt)
                        for mt in maintenance_types},
            "reactive_maintenance_pct": round(corrective_pct, 1),
        },
        "patterns": {
            "most_common_issue": r.choice(["Bearing failure", "Seal wear", "Electrical faults"]),
            "avg_time_between_failures_days": r.randint(30, 180),
            "seasonal_pattern": r.choice([
                "Higher failures in summer (heat-related)",
                "No significant seasonal pattern",
                "Increased issues after holiday shutdowns",
            ]),
        },
    }, simulated=True)


def get_maintenance_calendar(facility_id: str = "all", days: int = 30) -> dict:
    days = min(max(int(days), 1), 90)
    today = _today()
    r = _rng("maintenance_calendar", facility_id.upper(), days, today.strftime("%Y-%m-%d"))

    scheduled_items = []
    for _ in range(r.randint(max(1, days // 3), days)):
        sched_date = today + timedelta(days=r.randint(1, days))
        scheduled_items.append({
            "schedule_id": f"SCH-{r.randrange(16 ** 8):08X}",
            "equipment_id": r.choice(EQUIPMENT_IDS),
            "date": sched_date.strftime("%Y-%m-%d"),
            "start_time": f"{r.randint(6, 14):02d}:00",
            "duration_hours": round(r.uniform(1, 16), 1),
            "type": r.choice(["PREVENTIVE", "PREDICTIVE", "INSPECTION", "CALIBRATION"]),
            "priority": r.choice(["HIGH", "MEDIUM", "MEDIUM", "LOW"]),
            "description": r.choice([
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
            "assigned_to": r.choice(["M. Rodriguez", "S. Chen", "J. Wilson", "A. Petrova"]),
            "status": r.choice(["SCHEDULED", "CONFIRMED", "PARTS_ORDERED"]),
        })
    scheduled_items.sort(key=lambda s: s["date"])

    weeks = {}
    for item in scheduled_items:
        week = datetime.strptime(item["date"], "%Y-%m-%d").isocalendar()[1]
        weeks.setdefault(week, {"maintenance_hours": 0, "events": 0})
        weeks[week]["maintenance_hours"] = round(
            weeks[week]["maintenance_hours"] + item["duration_hours"], 1)
        weeks[week]["events"] += 1

    total_hours = round(sum(s["duration_hours"] for s in scheduled_items), 1)
    available_hours = days * 4 * 8  # 4 techs, 8 hours/day

    return tool_ok({
        "facility_id": facility_id,
        "period_days": days,
        "total_scheduled": len(scheduled_items),
        "schedule": scheduled_items[:20],
        "weekly_capacity": {f"Week {k}": v for k, v in sorted(weeks.items())},
        "resource_utilization": {
            "total_maintenance_hours": total_hours,
            "technician_hours_available": available_hours,
            "utilization_pct": round(total_hours / available_hours * 100, 1),
        },
        "conflicts": ([{"date": (today + timedelta(days=r.randint(1, days))).strftime("%Y-%m-%d"),
                        "issue": "Two high-priority jobs overlap - need additional technician",
                        "resolution": "Request contractor support"}]
                      if r.random() > 0.5 else []),
    }, simulated=True)


TOOLS = {
    "schedule_maintenance": schedule_maintenance,
    "generate_work_order": generate_work_order,
    "get_maintenance_history": get_maintenance_history,
    "get_maintenance_calendar": get_maintenance_calendar,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
