from strands import tool
import json, random
from datetime import datetime, timedelta


@tool
def get_equipment_status(equipment_id: str) -> str:
    """Get real-time equipment health status with live sensor readings.

    Retrieves current sensor data (temperature, vibration, RPM, oil pressure, power
    consumption) and computes an overall health score for the specified equipment.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001', 'EQ-PUMP-014').

    Returns:
        JSON with sensor readings, health score (0-100), operating state, and alert flags.
    """
    equipment_types = {
        "CNC": {"name": "CNC Milling Machine", "rpm_range": (800, 12000), "temp_range": (35, 95)},
        "PUMP": {"name": "Hydraulic Pump", "rpm_range": (1200, 3600), "temp_range": (40, 85)},
        "COMP": {"name": "Air Compressor", "rpm_range": (900, 3000), "temp_range": (50, 110)},
        "CONV": {"name": "Conveyor Belt Drive", "rpm_range": (60, 400), "temp_range": (30, 70)},
        "TURB": {"name": "Steam Turbine", "rpm_range": (3000, 15000), "temp_range": (80, 250)},
        "MOTOR": {"name": "Electric Motor", "rpm_range": (600, 3600), "temp_range": (35, 90)},
    }

    prefix = equipment_id.split("-")[1] if "-" in equipment_id else "CNC"
    eq_type = equipment_types.get(prefix, equipment_types["CNC"])

    rpm = random.randint(*eq_type["rpm_range"])
    temp_c = round(random.uniform(*eq_type["temp_range"]), 1)
    vibration_mm_s = round(random.uniform(0.5, 18.0), 2)
    oil_pressure_bar = round(random.uniform(1.5, 6.5), 1)
    power_kw = round(random.uniform(5, 250), 1)

    # Derive health score from sensor readings
    temp_score = max(0, 100 - (temp_c - eq_type["temp_range"][0]) / (eq_type["temp_range"][1] - eq_type["temp_range"][0]) * 60)
    vib_score = max(0, 100 - vibration_mm_s * 5)
    oil_score = 100 if 2.0 <= oil_pressure_bar <= 5.5 else 60
    health_score = round(min(100, (temp_score * 0.3 + vib_score * 0.4 + oil_score * 0.3)), 1)

    status = "RUNNING" if health_score > 40 else "DEGRADED"
    if random.random() < 0.05:
        status = "STOPPED"

    alerts = []
    if vibration_mm_s > 11.0:
        alerts.append({"type": "HIGH_VIBRATION", "severity": "CRITICAL", "message": f"Vibration {vibration_mm_s} mm/s exceeds ISO 10816 Zone D threshold"})
    elif vibration_mm_s > 7.1:
        alerts.append({"type": "ELEVATED_VIBRATION", "severity": "WARNING", "message": f"Vibration {vibration_mm_s} mm/s in ISO 10816 Zone C"})
    if temp_c > eq_type["temp_range"][1] * 0.9:
        alerts.append({"type": "HIGH_TEMPERATURE", "severity": "WARNING", "message": f"Temperature {temp_c}C approaching upper limit"})
    if oil_pressure_bar < 2.0:
        alerts.append({"type": "LOW_OIL_PRESSURE", "severity": "CRITICAL", "message": f"Oil pressure {oil_pressure_bar} bar below minimum threshold"})

    return json.dumps({
        "equipment_id": equipment_id,
        "equipment_name": eq_type["name"],
        "status": status,
        "health_score": health_score,
        "health_rating": "GOOD" if health_score >= 75 else "FAIR" if health_score >= 50 else "POOR",
        "sensors": {
            "temperature_c": temp_c,
            "vibration_mm_s": vibration_mm_s,
            "rpm": rpm,
            "oil_pressure_bar": oil_pressure_bar,
            "power_consumption_kw": power_kw,
        },
        "operating_hours": random.randint(500, 45000),
        "hours_since_last_maintenance": random.randint(50, 2000),
        "alerts": alerts,
        "last_updated": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_equipment_list(facility_id: str) -> str:
    """List all equipment in a facility with current status summary.

    Args:
        facility_id: Facility identifier (e.g., 'FAC-NORTH', 'FAC-SOUTH', 'all').

    Returns:
        JSON with equipment roster, status counts, and overall facility health.
    """
    equipment_defs = [
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

    equipment_list = []
    for eq_id, name, dept in equipment_defs:
        health = round(random.uniform(30, 100), 1)
        status = "RUNNING" if health > 50 else random.choice(["DEGRADED", "STOPPED"])
        equipment_list.append({
            "equipment_id": eq_id,
            "name": name,
            "department": dept,
            "status": status,
            "health_score": health,
            "criticality": random.choice(["HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW"]),
            "last_maintenance": (datetime.utcnow() - timedelta(days=random.randint(1, 180))).strftime("%Y-%m-%d"),
            "next_scheduled_maintenance": (datetime.utcnow() + timedelta(days=random.randint(1, 90))).strftime("%Y-%m-%d"),
        })

    running = sum(1 for e in equipment_list if e["status"] == "RUNNING")
    degraded = sum(1 for e in equipment_list if e["status"] == "DEGRADED")
    stopped = sum(1 for e in equipment_list if e["status"] == "STOPPED")

    return json.dumps({
        "facility_id": facility_id,
        "facility_name": f"Manufacturing Plant {facility_id[-5:].replace('-', ' ').title()}",
        "total_equipment": len(equipment_list),
        "status_summary": {
            "running": running,
            "degraded": degraded,
            "stopped": stopped,
        },
        "avg_health_score": round(sum(e["health_score"] for e in equipment_list) / len(equipment_list), 1),
        "equipment": equipment_list,
        "critical_equipment_below_threshold": [
            e for e in equipment_list if e["criticality"] == "HIGH" and e["health_score"] < 60
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_sensor_data(equipment_id: str, sensor_type: str, hours: int) -> str:
    """Get historical sensor time-series data for analysis.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001').
        sensor_type: Sensor type ('temperature', 'vibration', 'rpm', 'oil_pressure', 'power').
        hours: Number of hours of history to retrieve (1-720).

    Returns:
        JSON with time-series sensor readings, statistics, and trend information.
    """
    hours = min(max(hours, 1), 720)

    sensor_ranges = {
        "temperature": (35, 110, "C"),
        "vibration": (0.5, 18.0, "mm/s"),
        "rpm": (800, 12000, "RPM"),
        "oil_pressure": (1.5, 6.5, "bar"),
        "power": (5, 250, "kW"),
    }

    range_min, range_max, unit = sensor_ranges.get(sensor_type, (0, 100, "units"))
    base_value = random.uniform(range_min + (range_max - range_min) * 0.2, range_min + (range_max - range_min) * 0.6)

    # Generate time-series data points (one per 15-minute interval, capped at 200 points)
    interval_minutes = max(15, (hours * 60) // 200)
    num_points = min(200, (hours * 60) // interval_minutes)

    readings = []
    trend_slope = random.uniform(-0.001, 0.005)
    for i in range(num_points):
        ts = datetime.utcnow() - timedelta(minutes=(num_points - i) * interval_minutes)
        drift = trend_slope * i
        noise = random.gauss(0, (range_max - range_min) * 0.02)
        value = round(max(range_min, min(range_max, base_value + drift + noise)), 2)
        readings.append({
            "timestamp": ts.isoformat() + "Z",
            "value": value,
        })

    values = [r["value"] for r in readings]
    avg_val = round(sum(values) / len(values), 2)
    min_val = round(min(values), 2)
    max_val = round(max(values), 2)
    std_dev = round((sum((v - avg_val) ** 2 for v in values) / len(values)) ** 0.5, 2)

    return json.dumps({
        "equipment_id": equipment_id,
        "sensor_type": sensor_type,
        "unit": unit,
        "period_hours": hours,
        "data_points": len(readings),
        "readings": readings[-50:],  # Return last 50 points for readability
        "statistics": {
            "mean": avg_val,
            "min": min_val,
            "max": max_val,
            "std_dev": std_dev,
            "trend": "INCREASING" if trend_slope > 0.002 else "DECREASING" if trend_slope < -0.002 else "STABLE",
            "trend_rate_per_hour": round(trend_slope * (60 / interval_minutes), 4),
        },
        "thresholds": {
            "warning": round(range_min + (range_max - range_min) * 0.7, 2),
            "critical": round(range_min + (range_max - range_min) * 0.9, 2),
            "breaches_warning": sum(1 for v in values if v > range_min + (range_max - range_min) * 0.7),
            "breaches_critical": sum(1 for v in values if v > range_min + (range_max - range_min) * 0.9),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_equipment_alerts() -> str:
    """Get all active alerts across all equipment in the facility.

    Returns:
        JSON with prioritized alert list, severity counts, and recommended actions.
    """
    alert_templates = [
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

    num_alerts = random.randint(4, len(alert_templates))
    alerts = random.sample(alert_templates, num_alerts)

    for alert in alerts:
        alert["alert_id"] = f"ALT-{random.randint(10000, 99999)}"
        alert["triggered_at"] = (datetime.utcnow() - timedelta(minutes=random.randint(5, 1440))).isoformat() + "Z"
        alert["acknowledged"] = random.choice([True, False, False])

    alerts.sort(key=lambda a: {"CRITICAL": 0, "WARNING": 1, "INFO": 2}[a["severity"]])

    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    warning = sum(1 for a in alerts if a["severity"] == "WARNING")
    info = sum(1 for a in alerts if a["severity"] == "INFO")

    return json.dumps({
        "total_alerts": len(alerts),
        "severity_counts": {
            "critical": critical,
            "warning": warning,
            "info": info,
        },
        "unacknowledged": sum(1 for a in alerts if not a["acknowledged"]),
        "alerts": alerts,
        "recommendation": "Address critical alerts immediately. Schedule warning-level items within 48 hours." if critical > 0 else "No critical alerts. Monitor warning-level items during routine rounds.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
