"""Gateway target: equipment — status, roster, sensor history, alerts.

Asset condition (health, status, criticality, sensor readings) comes from the
shared toolkit.asset_basis so the fleet table and the per-asset drill-down cannot
disagree about the same machine. ISO 10816 vibration thresholds are real
reference values.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import asset_basis, asset_type, tool_ok, tool_error
from toolkit.dispatch import dispatch

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

#: Fleet-wide chart bounds and units. Temperature and RPM vary by asset family
#: (a steam turbine runs to 250C, a conveyor drive to 70C), so _sensor_range
#: narrows those two per asset; the rest apply to every machine.
SENSOR_RANGES = {
    "temperature": (35, 250, "C"),
    "vibration": (0.5, 18.0, "mm/s"),
    "rpm": (0, 15000, "RPM"),
    "oil_pressure": (1.5, 6.5, "bar"),
    "power": (5, 250, "kW"),
}


def _sensor_range(equipment_id: str, sensor_type: str) -> tuple:
    """Chart bounds for one asset's sensor, from its own operating envelope.

    A single fleet-wide (35, 110) temperature band clamped the steam turbine's
    real 186.7C reading down to a 109.5C series mean, so its chart contradicted
    the 186.7C the detail pane printed for the same asset. RPM had the same
    problem in reverse: a conveyor drive turning 300 RPM was floored at the
    800 RPM bound taken from the CNC family.
    """
    lo, hi, unit = SENSOR_RANGES[sensor_type]
    envelope = asset_type(equipment_id)
    if sensor_type == "temperature":
        lo, hi = envelope["temp"]
        # Headroom above the nominal limit — a hot asset must be plottable above
        # its own ceiling, which is exactly when the operator is looking.
        hi = round(hi * 1.15)
    elif sensor_type == "rpm":
        # A stopped machine reads zero, so the floor stays at 0.
        hi = round(envelope["rpm"][1] * 1.05)
    return lo, hi, unit


def _sensor_thresholds(equipment_id: str, sensor_type: str) -> tuple:
    """Chart threshold lines, in agreement with the alert rules.

    Flat 70%/90%-of-range lines put vibration's "critical" marker at 16.25 mm/s
    while the alert list raised CRITICAL at 11.0, so a chart could sit entirely
    below its own critical line under a CRITICAL alert banner. Oil pressure was
    worse: low pressure is the fault, but the breach counters only counted values
    *above* the line, so a failing pump reported zero breaches.
    """
    if sensor_type == "vibration":
        return VIBRATION_WARNING, VIBRATION_CRITICAL, "ABOVE"
    if sensor_type == "oil_pressure":
        return OIL_WARNING, OIL_CRITICAL, "BELOW"
    if sensor_type == "temperature":
        t_hi = asset_type(equipment_id)["temp"][1]
        return (
            round(t_hi * TEMP_WARNING_FRAC, 1),
            round(t_hi * TEMP_CRITICAL_FRAC, 1),
            "ABOVE",
        )
    # rpm and power have no alert rule; keep the descriptive band.
    lo, hi, _ = _sensor_range(equipment_id, sensor_type)
    return round(lo + (hi - lo) * 0.7, 2), round(lo + (hi - lo) * 0.9, 2), "ABOVE"


# An alert fires when the asset's own reading crosses a threshold, and its
# message quotes that same reading. The messages used to hard-code values
# ("vibration 14.2 mm/s"), which contradicted the sensor chart for the same asset
# on the same screen; and templates were sampled at random, so a RUNNING machine
# at health 99 could carry a CRITICAL alert while a STOPPED one carried none.
#
# Each rule: (type, action, severity_for, message_for) — severity_for returns
# None when the reading is within limits and the alert must not fire.
#
# The cut-offs live in these module constants because the sensor-history chart
# draws its threshold lines from the same numbers (_sensor_thresholds). When the
# chart used a flat 90%-of-range line instead, a vibration series sat entirely
# below its own "critical" marker while this list raised CRITICAL on it.
#
# ISO 10816 Zone C starts at 7.1 mm/s, Zone D at 11.0 mm/s.
VIBRATION_WARNING, VIBRATION_CRITICAL = 7.1, 11.0
OIL_WARNING, OIL_CRITICAL = 2.5, 2.0
TEMP_WARNING_FRAC, TEMP_CRITICAL_FRAC = 0.85, 0.95

ALERT_RULES = [
    {
        "type": "HIGH_VIBRATION",
        "action": "Immediate shutdown and bearing inspection required",
        "severity_for": lambda b: (
            "CRITICAL"
            if b.vibration_mm_s > VIBRATION_CRITICAL
            else "WARNING" if b.vibration_mm_s > VIBRATION_WARNING else None
        ),
        "message_for": lambda b: (
            f"Vibration {b.vibration_mm_s} mm/s exceeds ISO 10816 "
            f"{'Zone D' if b.vibration_mm_s > VIBRATION_CRITICAL else 'Zone C'} "
            "threshold"
        ),
    },
    {
        "type": "LOW_OIL_PRESSURE",
        "action": "Check for leaks, verify oil level, inspect pump seals",
        "severity_for": lambda b: (
            "CRITICAL"
            if b.oil_pressure_bar < OIL_CRITICAL
            else "WARNING" if b.oil_pressure_bar < OIL_WARNING else None
        ),
        "message_for": lambda b: (
            f"Oil pressure {b.oil_pressure_bar} bar below the "
            f"{OIL_CRITICAL} bar minimum"
            if b.oil_pressure_bar < OIL_CRITICAL
            # at exactly the minimum the reading *is* it, not approaching it
            else f"Oil pressure {b.oil_pressure_bar} bar close to the "
            f"{OIL_CRITICAL} bar minimum"
        ),
    },
    {
        "type": "HIGH_TEMPERATURE",
        "action": "Check cooling system, verify airflow, clean heat exchanger",
        "severity_for": lambda b: (
            "CRITICAL"
            if b.temperature_c
            > asset_type(b.equipment_id)["temp"][1] * TEMP_CRITICAL_FRAC
            else (
                "WARNING"
                if b.temperature_c
                > asset_type(b.equipment_id)["temp"][1] * TEMP_WARNING_FRAC
                else None
            )
        ),
        "message_for": lambda b: (
            f"Temperature {b.temperature_c}C against a "
            f"{asset_type(b.equipment_id)['temp'][1]}C limit"
        ),
    },
    {
        "type": "DEGRADED_CONDITION",
        "action": "Schedule inspection during the next planned stop",
        # A catch-all so a low-health asset never sits in the fleet table with no
        # alert explaining why an operator should care.
        "severity_for": lambda b: (
            "WARNING"
            if b.status == "DEGRADED"
            else "INFO" if b.health_score < 75 else None
        ),
        "message_for": lambda b: (
            f"Health score {b.health_score} ({b.health_rating}) — "
            f"{b.status.lower()} in {b.criticality.lower()}-criticality service"
        ),
    },
]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _alerts_for(basis) -> list:
    """Every ALERT_RULES condition the asset's readings currently breach."""
    fired = []
    for rule in ALERT_RULES:
        severity = rule["severity_for"](basis)
        if severity is not None:
            fired.append(
                {
                    "type": rule["type"],
                    "severity": severity,
                    "message": rule["message_for"](basis),
                }
            )
    return fired


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def get_equipment_status(equipment_id: str) -> dict:
    today = _today()
    # Condition comes from the shared basis, not a fresh draw: this route and
    # get_equipment_list below both describe the same machine, and they used to
    # report EQ-CNC-003 as STOPPED at health 34.9 and RUNNING at 76.7.
    basis = asset_basis(equipment_id, today.strftime("%Y-%m-%d"))
    r = _rng("equipment_status", equipment_id.upper(), today.strftime("%Y-%m-%d"))

    temp_c = basis.temperature_c
    vibration = basis.vibration_mm_s
    oil_pressure = basis.oil_pressure_bar
    health_score = basis.health_score
    status = basis.status

    # The same rules the fleet-wide alert list evaluates. This route used to keep
    # its own copy with different cut-offs (temperature at 0.90 of the limit here
    # against 0.85/0.95 there, no oil-pressure warning band), so an asset could
    # show two alerts in the detail pane and three in the alert list.
    alerts = _alerts_for(basis)

    return tool_ok(
        {
            "equipment_id": equipment_id,
            "equipment_name": basis.equipment_name,
            "status": status,
            "health_score": health_score,
            "health_rating": basis.health_rating,
            "criticality": basis.criticality,
            "sensors": {
                "temperature_c": temp_c,
                "vibration_mm_s": vibration,
                "rpm": basis.rpm,
                "oil_pressure_bar": oil_pressure,
                "power_consumption_kw": basis.power_kw,
            },
            "operating_hours": r.randint(500, 45000),
            "hours_since_last_maintenance": r.randint(50, 2000),
            "alerts": alerts,
        },
        simulated=True,
    )


def get_equipment_list(facility_id: str = "all") -> dict:
    today = _today()
    day = today.strftime("%Y-%m-%d")
    equipment_list = []
    for eq_id, name, dept in EQUIPMENT_ROSTER:
        # Same basis the drill-down uses, so a row that says STOPPED opens onto a
        # detail pane that also says STOPPED.
        basis = asset_basis(eq_id, day)
        r = _rng("equipment_row", facility_id.upper(), eq_id, day)
        # A machine due for maintenance sooner is the one in worse condition —
        # an independent randint scheduled the healthiest asset first.
        days_out = 1 + int(basis.health_score / 100 * 89)
        equipment_list.append(
            {
                "equipment_id": eq_id,
                "name": name,
                "department": dept,
                "status": basis.status,
                "health_score": basis.health_score,
                "criticality": basis.criticality,
                "last_maintenance": (
                    today - timedelta(days=r.randint(1, 180))
                ).strftime("%Y-%m-%d"),
                "next_scheduled_maintenance": (
                    today + timedelta(days=days_out)
                ).strftime("%Y-%m-%d"),
            }
        )

    return tool_ok(
        {
            "facility_id": facility_id,
            "total_equipment": len(equipment_list),
            "status_summary": {
                "running": sum(1 for e in equipment_list if e["status"] == "RUNNING"),
                "degraded": sum(1 for e in equipment_list if e["status"] == "DEGRADED"),
                "stopped": sum(1 for e in equipment_list if e["status"] == "STOPPED"),
            },
            "avg_health_score": round(
                sum(e["health_score"] for e in equipment_list) / len(equipment_list), 1
            ),
            "equipment": equipment_list,
            "critical_equipment_below_threshold": [
                e
                for e in equipment_list
                if e["criticality"] == "HIGH" and e["health_score"] < 60
            ],
        },
        simulated=True,
    )


def get_sensor_data(equipment_id: str, sensor_type: str, hours: int = 24) -> dict:
    sensor_type = sensor_type.lower()
    if sensor_type not in SENSOR_RANGES:
        return tool_error(
            f"Invalid sensor_type: {sensor_type}", valid=sorted(SENSOR_RANGES)
        )
    hours = min(max(int(hours), 1), 720)
    today = _today()
    r = _rng(
        "sensor_data",
        equipment_id.upper(),
        sensor_type,
        hours,
        today.strftime("%Y-%m-%d"),
    )

    range_min, range_max, unit = _sensor_range(equipment_id, sensor_type)
    # Centre the series on the asset's current reading for this sensor, so the
    # chart's mean matches the number the health pill and the alert text quote.
    # Drawn independently, EQ-CNC-001 charted a 6.35 mm/s mean beneath a
    # "vibration 14.2 mm/s exceeds Zone D" alert for the same asset.
    basis = asset_basis(equipment_id, today.strftime("%Y-%m-%d"))
    current = {
        "temperature": basis.temperature_c,
        "vibration": basis.vibration_mm_s,
        "rpm": float(basis.rpm),
        "oil_pressure": basis.oil_pressure_bar,
        "power": basis.power_kw,
    }[sensor_type]
    base_value = min(max(current, range_min), range_max)
    interval_minutes = max(15, (hours * 60) // 200)
    num_points = min(200, (hours * 60) // interval_minutes)

    readings = []
    trend_slope = r.uniform(-0.001, 0.005)
    for i in range(num_points):
        ts = today - timedelta(minutes=(num_points - i) * interval_minutes)
        value = round(
            max(
                range_min,
                min(
                    range_max,
                    base_value
                    + trend_slope * i
                    + r.gauss(0, (range_max - range_min) * 0.02),
                ),
            ),
            2,
        )
        readings.append({"timestamp": ts.isoformat(), "value": value})

    values = [x["value"] for x in readings]
    avg_val = round(sum(values) / len(values), 2)
    std_dev = round((sum((v - avg_val) ** 2 for v in values) / len(values)) ** 0.5, 2)
    warn, crit, direction = _sensor_thresholds(equipment_id, sensor_type)

    def breached(value: float, threshold: float) -> bool:
        """Low oil pressure is a fault, so its breaches count downwards."""
        return value < threshold if direction == "BELOW" else value > threshold

    return tool_ok(
        {
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
                "trend": (
                    "INCREASING"
                    if trend_slope > 0.002
                    else "DECREASING" if trend_slope < -0.002 else "STABLE"
                ),
                "trend_rate_per_hour": round(trend_slope * (60 / interval_minutes), 4),
            },
            "thresholds": {
                "warning": warn,
                "critical": crit,
                "breach_direction": direction,
                "breaches_warning": sum(1 for v in values if breached(v, warn)),
                "breaches_critical": sum(1 for v in values if breached(v, crit)),
            },
        },
        simulated=True,
    )


def get_equipment_alerts() -> dict:
    """Alerts implied by the fleet's actual condition.

    Every alert is raised by a threshold on the asset's own basis reading and
    quotes that reading, so the alert list, the fleet health column and the sensor
    chart for a given asset always tell the same story.
    """
    today = _today()
    day = today.strftime("%Y-%m-%d")
    r = _rng("equipment_alerts", day)

    alerts = []
    for eq_id, name, _dept in EQUIPMENT_ROSTER:
        basis = asset_basis(eq_id, day)
        # Same helper get_equipment_status uses, so the detail pane and this list
        # cannot disagree about which rules an asset is breaching.
        for fired in _alerts_for(basis):
            action = next(
                rule["action"] for rule in ALERT_RULES if rule["type"] == fired["type"]
            )
            alerts.append(
                {
                    "equipment_id": eq_id,
                    "equipment_name": name,
                    **fired,
                    "action": action,
                    "alert_id": f"ALT-{r.randint(10000, 99999)}",
                    "triggered_at": (
                        today - timedelta(minutes=r.randint(5, 1440))
                    ).isoformat(),
                    # Only the acknowledgement is a free draw — it is a human
                    # action, not a property of the machine.
                    "acknowledged": r.choice([True, False, False]),
                }
            )
    alerts.sort(key=lambda a: {"CRITICAL": 0, "WARNING": 1, "INFO": 2}[a["severity"]])
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")

    return tool_ok(
        {
            "total_alerts": len(alerts),
            "severity_counts": {
                "critical": critical,
                "warning": sum(1 for a in alerts if a["severity"] == "WARNING"),
                "info": sum(1 for a in alerts if a["severity"] == "INFO"),
            },
            "unacknowledged": sum(1 for a in alerts if not a["acknowledged"]),
            "alerts": alerts,
            "recommendation": (
                "Address critical alerts immediately. Schedule warning-level items "
                "within 48 hours."
                if critical > 0
                else "No critical alerts. Monitor warning-level items during "
                "routine rounds."
            ),
        },
        simulated=True,
    )


TOOLS = {
    "get_equipment_status": get_equipment_status,
    "get_equipment_list": get_equipment_list,
    "get_sensor_data": get_sensor_data,
    "get_equipment_alerts": get_equipment_alerts,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
