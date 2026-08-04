"""Gateway target: equipment — status, roster, sensor history, alerts.

Sensor data is a deterministic simulation seeded from the function inputs
(stable within a calendar day). ISO 10816 vibration thresholds are real
reference values.
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

EQUIPMENT_TYPES = {
    "CNC": {"name": "CNC Milling Machine", "rpm_range": (800, 12000), "temp_range": (35, 95)},
    "PUMP": {"name": "Hydraulic Pump", "rpm_range": (1200, 3600), "temp_range": (40, 85)},
    "COMP": {"name": "Air Compressor", "rpm_range": (900, 3000), "temp_range": (50, 110)},
    "CONV": {"name": "Conveyor Belt Drive", "rpm_range": (60, 400), "temp_range": (30, 70)},
    "TURB": {"name": "Steam Turbine", "rpm_range": (3000, 15000), "temp_range": (80, 250)},
    "MOTOR": {"name": "Electric Motor", "rpm_range": (600, 3600), "temp_range": (35, 90)},
}

EQUIPMENT_ROSTER = [
    ("EQ-CNC-001", "CNC Milling Machine #1", "Machining"),
    ("EQ-CNC-002", "CNC Milling Machine #2", "Machining"),
    ("EQ-CNC-003", "CNC Lathe", "Machining"),
    ("EQ-PUMP-001", "Hydraulic Press Pump", "Forming"),
    ("EQ-PUMP-002", "Coolant Circulation Pump", "Utilities"),
    ("EQ-COMP-001", "Main Air Compressor", "Utilities"),
    ("EQ-COMP-002", "Backup Air Compressor", "Utilities"),
    ("EQ-CONV-001", "Assembly Line Conveyor A", "Assembly"),
    ("EQ-CONV-002", "Assembly Line Conveyor B", "Assembly"),
    ("EQ-CONV-003", "Packaging Conveyor", "Packaging"),
    ("EQ-TURB-001", "Steam Turbine Generator", "Power"),
    ("EQ-MOTOR-001", "Main Drive Motor", "Machining"),
    ("EQ-MOTOR-002", "Ventilation Fan Motor", "HVAC"),
    ("EQ-MOTOR-003", "Cooling Tower Motor", "Utilities"),
]

SENSOR_RANGES = {
    "temperature": (35, 110, "C"),
    "vibration": (0.5, 18.0, "mm/s"),
    "rpm": (800, 12000, "RPM"),
    "oil_pressure": (1.5, 6.5, "bar"),
    "power": (5, 250, "kW"),
}

ALERT_TEMPLATES = [
    {"equipment_id": "EQ-CNC-001", "type": "HIGH_VIBRATION", "severity": "CRITICAL", "message": "Spindle vibration 14.2 mm/s exceeds Zone D threshold", "action": "Immediate shutdown and bearing inspection required"},
    {"equipment_id": "EQ-PUMP-001", "type": "LOW_OIL_PRESSURE", "severity": "CRITICAL", "message": "Hydraulic oil pressure dropped to 1.3 bar", "action": "Check for leaks, verify oil level, inspect pump seals"},
    {"equipment_id": "EQ-COMP-001", "type": "HIGH_TEMPERATURE", "severity": "WARNING", "message": "Discharge temperature 108C approaching limit", "action": "Check cooling system, verify airflow, clean heat exchanger"},
    {"equipment_id": "EQ-CONV-002", "type": "BELT_MISALIGNMENT", "severity": "WARNING", "message": "Belt tracking deviation detected by proximity sensor", "action": "Schedule belt alignment during next planned stop"},
    {"equipment_id": "EQ-MOTOR-001", "type": "CURRENT_IMBALANCE", "severity": "WARNING", "message": "Phase current imbalance 8.3% exceeds 5% threshold", "action": "Check motor connections and power supply quality"},
    {"equipment_id": "EQ-TURB-001", "type": "BEARING_WEAR", "severity": "WARNING", "message": "Inner race defect frequency detected at 142 Hz", "action": "Plan bearing replacement within 2 weeks"},
    {"equipment_id": "EQ-CNC-003", "type": "TOOL_WEAR", "severity": "INFO", "message": "Cutting tool approaching end of expected life (87% worn)", "action": "Prepare replacement tooling for next shift change"},
    {"equipment_id": "EQ-MOTOR-003", "type": "EFFICIENCY_DROP", "severity": "INFO", "message": "Motor efficiency dropped 3.2% over past 30 days", "action": "Schedule electrical testing during next maintenance window"},
    {"equipment_id": "EQ-PUMP-002", "type": "CAVITATION_DETECTED", "severity": "WARNING", "message": "Characteristic cavitation frequencies detected in vibration spectrum", "action": "Check inlet pressure and valve positions"},
    {"equipment_id": "EQ-CNC-002", "type": "COOLANT_LEVEL_LOW", "severity": "INFO", "message": "Coolant reservoir at 22% capacity", "action": "Top up coolant during shift change"},
]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def get_equipment_status(equipment_id: str) -> dict:
    prefix = equipment_id.split("-")[1] if "-" in equipment_id else "CNC"
    eq_type = EQUIPMENT_TYPES.get(prefix, EQUIPMENT_TYPES["CNC"])
    today = _today()
    r = _rng("equipment_status", equipment_id.upper(), today.strftime("%Y-%m-%d"))

    rpm = r.randint(*eq_type["rpm_range"])
    temp_c = round(r.uniform(*eq_type["temp_range"]), 1)
    vibration = round(r.uniform(0.5, 18.0), 2)
    oil_pressure = round(r.uniform(1.5, 6.5), 1)
    power_kw = round(r.uniform(5, 250), 1)

    # health score derived from sensor readings
    t_lo, t_hi = eq_type["temp_range"]
    temp_score = max(0, 100 - (temp_c - t_lo) / (t_hi - t_lo) * 60)
    vib_score = max(0, 100 - vibration * 5)
    oil_score = 100 if 2.0 <= oil_pressure <= 5.5 else 60
    health_score = round(min(100, temp_score * 0.3 + vib_score * 0.4 + oil_score * 0.3), 1)

    status = "RUNNING" if health_score > 40 else "DEGRADED"
    if r.random() < 0.05:
        status = "STOPPED"

    alerts = []
    if vibration > 11.0:
        alerts.append({"type": "HIGH_VIBRATION", "severity": "CRITICAL",
                       "message": f"Vibration {vibration} mm/s exceeds ISO 10816 Zone D threshold"})
    elif vibration > 7.1:
        alerts.append({"type": "ELEVATED_VIBRATION", "severity": "WARNING",
                       "message": f"Vibration {vibration} mm/s in ISO 10816 Zone C"})
    if temp_c > t_hi * 0.9:
        alerts.append({"type": "HIGH_TEMPERATURE", "severity": "WARNING",
                       "message": f"Temperature {temp_c}C approaching upper limit"})
    if oil_pressure < 2.0:
        alerts.append({"type": "LOW_OIL_PRESSURE", "severity": "CRITICAL",
                       "message": f"Oil pressure {oil_pressure} bar below minimum threshold"})

    return tool_ok({
        "equipment_id": equipment_id,
        "equipment_name": eq_type["name"],
        "status": status,
        "health_score": health_score,
        "health_rating": ("GOOD" if health_score >= 75 else "FAIR" if health_score >= 50
                          else "POOR"),
        "sensors": {
            "temperature_c": temp_c,
            "vibration_mm_s": vibration,
            "rpm": rpm,
            "oil_pressure_bar": oil_pressure,
            "power_consumption_kw": power_kw,
        },
        "operating_hours": r.randint(500, 45000),
        "hours_since_last_maintenance": r.randint(50, 2000),
        "alerts": alerts,
    }, simulated=True)


def get_equipment_list(facility_id: str = "all") -> dict:
    today = _today()
    equipment_list = []
    for eq_id, name, dept in EQUIPMENT_ROSTER:
        r = _rng("equipment_row", facility_id.upper(), eq_id, today.strftime("%Y-%m-%d"))
        health = round(r.uniform(30, 100), 1)
        equipment_list.append({
            "equipment_id": eq_id,
            "name": name,
            "department": dept,
            "status": "RUNNING" if health > 50 else r.choice(["DEGRADED", "STOPPED"]),
            "health_score": health,
            "criticality": r.choice(["HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW"]),
            "last_maintenance": (today - timedelta(days=r.randint(1, 180))).strftime("%Y-%m-%d"),
            "next_scheduled_maintenance": (today + timedelta(days=r.randint(1, 90))).strftime("%Y-%m-%d"),
        })

    return tool_ok({
        "facility_id": facility_id,
        "total_equipment": len(equipment_list),
        "status_summary": {
            "running": sum(1 for e in equipment_list if e["status"] == "RUNNING"),
            "degraded": sum(1 for e in equipment_list if e["status"] == "DEGRADED"),
            "stopped": sum(1 for e in equipment_list if e["status"] == "STOPPED"),
        },
        "avg_health_score": round(sum(e["health_score"] for e in equipment_list)
                                  / len(equipment_list), 1),
        "equipment": equipment_list,
        "critical_equipment_below_threshold": [
            e for e in equipment_list if e["criticality"] == "HIGH" and e["health_score"] < 60
        ],
    }, simulated=True)


def get_sensor_data(equipment_id: str, sensor_type: str, hours: int = 24) -> dict:
    sensor_type = sensor_type.lower()
    if sensor_type not in SENSOR_RANGES:
        return tool_error(f"Invalid sensor_type: {sensor_type}", valid=sorted(SENSOR_RANGES))
    hours = min(max(int(hours), 1), 720)
    today = _today()
    r = _rng("sensor_data", equipment_id.upper(), sensor_type, hours,
             today.strftime("%Y-%m-%d"))

    range_min, range_max, unit = SENSOR_RANGES[sensor_type]
    base_value = r.uniform(range_min + (range_max - range_min) * 0.2,
                           range_min + (range_max - range_min) * 0.6)
    interval_minutes = max(15, (hours * 60) // 200)
    num_points = min(200, (hours * 60) // interval_minutes)

    readings = []
    trend_slope = r.uniform(-0.001, 0.005)
    for i in range(num_points):
        ts = today - timedelta(minutes=(num_points - i) * interval_minutes)
        value = round(max(range_min, min(range_max,
                                         base_value + trend_slope * i
                                         + r.gauss(0, (range_max - range_min) * 0.02))), 2)
        readings.append({"timestamp": ts.isoformat(), "value": value})

    values = [x["value"] for x in readings]
    avg_val = round(sum(values) / len(values), 2)
    std_dev = round((sum((v - avg_val) ** 2 for v in values) / len(values)) ** 0.5, 2)
    warn = round(range_min + (range_max - range_min) * 0.7, 2)
    crit = round(range_min + (range_max - range_min) * 0.9, 2)

    return tool_ok({
        "equipment_id": equipment_id,
        "sensor_type": sensor_type,
        "unit": unit,
        "period_hours": hours,
        "data_points": len(readings),
        "readings": readings[-50:],
        "statistics": {
            "mean": avg_val,
            "min": round(min(values), 2),
            "max": round(max(values), 2),
            "std_dev": std_dev,
            "trend": ("INCREASING" if trend_slope > 0.002
                      else "DECREASING" if trend_slope < -0.002 else "STABLE"),
            "trend_rate_per_hour": round(trend_slope * (60 / interval_minutes), 4),
        },
        "thresholds": {
            "warning": warn,
            "critical": crit,
            "breaches_warning": sum(1 for v in values if v > warn),
            "breaches_critical": sum(1 for v in values if v > crit),
        },
    }, simulated=True)


def get_equipment_alerts() -> dict:
    today = _today()
    r = _rng("equipment_alerts", today.strftime("%Y-%m-%d"))
    alerts = [dict(a) for a in
              r.sample(ALERT_TEMPLATES, r.randint(4, len(ALERT_TEMPLATES)))]
    for alert in alerts:
        alert["alert_id"] = f"ALT-{r.randint(10000, 99999)}"
        alert["triggered_at"] = (today - timedelta(minutes=r.randint(5, 1440))).isoformat()
        alert["acknowledged"] = r.choice([True, False, False])
    alerts.sort(key=lambda a: {"CRITICAL": 0, "WARNING": 1, "INFO": 2}[a["severity"]])
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")

    return tool_ok({
        "total_alerts": len(alerts),
        "severity_counts": {
            "critical": critical,
            "warning": sum(1 for a in alerts if a["severity"] == "WARNING"),
            "info": sum(1 for a in alerts if a["severity"] == "INFO"),
        },
        "unacknowledged": sum(1 for a in alerts if not a["acknowledged"]),
        "alerts": alerts,
        "recommendation": ("Address critical alerts immediately. Schedule warning-level items "
                           "within 48 hours." if critical > 0
                           else "No critical alerts. Monitor warning-level items during "
                                "routine rounds."),
    }, simulated=True)


TOOLS = {
    "get_equipment_status": get_equipment_status,
    "get_equipment_list": get_equipment_list,
    "get_sensor_data": get_sensor_data,
    "get_equipment_alerts": get_equipment_alerts,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
