"""Gateway target: prediction — failure prediction, vibration analysis, anomalies, reliability.

Predictions are deterministic simulations seeded from the function inputs.
ISO 10816 zone boundaries and bearing defect frequency ratios are real
reference values.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok
from toolkit.dispatch import dispatch

FAILURE_MODES = [
    {"mode": "BEARING_FAILURE", "component": "Main Bearing", "typical_rul_days": 45},
    {
        "mode": "SEAL_DEGRADATION",
        "component": "Mechanical Seal",
        "typical_rul_days": 60,
    },
    {"mode": "IMPELLER_WEAR", "component": "Impeller", "typical_rul_days": 90},
    {
        "mode": "MOTOR_WINDING_FAULT",
        "component": "Stator Winding",
        "typical_rul_days": 30,
    },
    {"mode": "GEAR_TOOTH_WEAR", "component": "Gearbox", "typical_rul_days": 120},
    {"mode": "SHAFT_MISALIGNMENT", "component": "Drive Shaft", "typical_rul_days": 75},
    {
        "mode": "LUBRICATION_BREAKDOWN",
        "component": "Lubrication System",
        "typical_rul_days": 20,
    },
    {
        "mode": "ELECTRICAL_INSULATION_DEGRADATION",
        "component": "Motor Insulation",
        "typical_rul_days": 55,
    },
]

SENSORS = ["temperature", "vibration", "rpm", "oil_pressure", "power_consumption"]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def predict_failure(equipment_id: str) -> dict:
    today = _today()
    r = _rng("predict_failure", equipment_id.upper(), today.strftime("%Y-%m-%d"))
    primary = r.choice(FAILURE_MODES)
    rul_days = max(
        1, int(r.gauss(primary["typical_rul_days"], primary["typical_rul_days"] * 0.3))
    )
    failure_probability = round(
        min(0.99, max(0.05, 1 - rul_days / (primary["typical_rul_days"] * 2))), 2
    )
    confidence = round(r.uniform(0.72, 0.96), 2)
    secondary = r.choice([m for m in FAILURE_MODES if m["mode"] != primary["mode"]])
    risk_level = (
        "CRITICAL"
        if rul_days < 14
        else "HIGH" if rul_days < 30 else "MEDIUM" if rul_days < 60 else "LOW"
    )

    return tool_ok(
        {
            "equipment_id": equipment_id,
            "prediction_model": "LSTM degradation model (demo simulation)",
            "model_accuracy": round(r.uniform(0.85, 0.95), 2),
            "primary_prediction": {
                "failure_mode": primary["mode"],
                "affected_component": primary["component"],
                "remaining_useful_life_days": rul_days,
                "estimated_failure_date": (today + timedelta(days=rul_days)).strftime(
                    "%Y-%m-%d"
                ),
                "failure_probability": failure_probability,
                "confidence_interval": {
                    "lower_days": max(1, rul_days - int(rul_days * (1 - confidence))),
                    "upper_days": rul_days + int(rul_days * (1 - confidence)),
                    "confidence_level": confidence,
                },
            },
            "secondary_prediction": {
                "failure_mode": secondary["mode"],
                "affected_component": secondary["component"],
                "probability": round(r.uniform(0.05, 0.25), 2),
            },
            "risk_level": risk_level,
            "degradation_trend": {
                "current_degradation_pct": round(r.uniform(20, 85), 1),
                "degradation_rate_per_day": round(r.uniform(0.1, 2.5), 2),
                "acceleration": r.choice(["STABLE", "ACCELERATING", "DECELERATING"]),
            },
            "contributing_factors": [
                {"factor": "Vibration trend increasing", "impact": "HIGH"},
                {"factor": "Temperature above baseline", "impact": "MEDIUM"},
                {
                    "factor": f"Operating hours: {r.randint(5000, 40000)}h",
                    "impact": "MEDIUM",
                },
                {
                    "factor": f"Last maintenance: {r.randint(30, 365)} days ago",
                    "impact": r.choice(["LOW", "MEDIUM"]),
                },
            ],
            "recommended_action": (
                f"Schedule {'immediate' if risk_level == 'CRITICAL' else 'preventive'} maintenance "
                f"for {primary['component']} replacement within "
                f"{min(rul_days, 7 if risk_level == 'CRITICAL' else 14)} days."
            ),
        },
        simulated=True,
    )


def analyze_vibration(equipment_id: str) -> dict:
    today = _today()
    r = _rng("analyze_vibration", equipment_id.upper(), today.strftime("%Y-%m-%d"))
    shaft_rpm = r.randint(900, 3600)
    shaft_freq = round(shaft_rpm / 60, 2)

    # bearing defect frequencies (typical ratios to shaft frequency)
    bpfo = round(shaft_freq * r.uniform(3.0, 5.5), 2)
    bpfi = round(shaft_freq * r.uniform(5.0, 8.5), 2)
    bsf = round(shaft_freq * r.uniform(2.0, 4.5), 2)
    ftf = round(shaft_freq * r.uniform(0.35, 0.48), 2)
    overall_velocity = round(r.uniform(0.5, 20.0), 2)

    # ISO 10816 zones (Class III machine)
    if overall_velocity <= 1.8:
        iso_zone, iso_desc = "A", "Good - newly commissioned machines"
    elif overall_velocity <= 4.5:
        iso_zone, iso_desc = "B", "Acceptable - unrestricted long-term operation"
    elif overall_velocity <= 11.2:
        iso_zone, iso_desc = "C", "Alert - restricted operation, plan maintenance"
    else:
        iso_zone, iso_desc = "D", "Danger - damage occurring, immediate action required"

    peaks = [
        {
            "frequency_hz": shaft_freq,
            "amplitude_mm_s": round(r.uniform(0.2, 5.0), 2),
            "label": "1X (Shaft speed)",
            "diagnosis": "Imbalance" if r.random() > 0.5 else "Normal",
        },
        {
            "frequency_hz": round(shaft_freq * 2, 2),
            "amplitude_mm_s": round(r.uniform(0.1, 3.0), 2),
            "label": "2X (Shaft speed)",
            "diagnosis": "Misalignment" if r.random() > 0.5 else "Normal",
        },
        {
            "frequency_hz": bpfo,
            "amplitude_mm_s": round(r.uniform(0.05, 2.5), 2),
            "label": "BPFO (Outer race)",
            "diagnosis": "Outer race defect" if r.random() > 0.6 else "Normal",
        },
        {
            "frequency_hz": bpfi,
            "amplitude_mm_s": round(r.uniform(0.05, 2.0), 2),
            "label": "BPFI (Inner race)",
            "diagnosis": "Inner race defect" if r.random() > 0.7 else "Normal",
        },
        {
            "frequency_hz": bsf,
            "amplitude_mm_s": round(r.uniform(0.02, 1.5), 2),
            "label": "BSF (Ball spin)",
            "diagnosis": "Rolling element defect" if r.random() > 0.8 else "Normal",
        },
    ]
    peaks.sort(key=lambda p: p["amplitude_mm_s"], reverse=True)
    defects = [p for p in peaks if p["diagnosis"] != "Normal"]

    return tool_ok(
        {
            "equipment_id": equipment_id,
            "analysis_type": "FFT Vibration Spectrum Analysis",
            "measurement_point": r.choice(
                [
                    "Drive End Bearing",
                    "Non-Drive End Bearing",
                    "Gearbox Input",
                    "Gearbox Output",
                ]
            ),
            "shaft_speed_rpm": shaft_rpm,
            "shaft_frequency_hz": shaft_freq,
            "overall_vibration": {
                "velocity_rms_mm_s": overall_velocity,
                "acceleration_peak_g": round(overall_velocity * r.uniform(0.8, 2.5), 2),
                "displacement_peak_um": round(overall_velocity * r.uniform(5, 20), 1),
            },
            "iso_10816_classification": {
                "zone": iso_zone,
                "description": iso_desc,
                "machine_class": "Class III (Large machines, rigid foundation)",
            },
            "bearing_defect_frequencies": {
                "BPFO_hz": bpfo,
                "BPFI_hz": bpfi,
                "BSF_hz": bsf,
                "FTF_hz": ftf,
            },
            "frequency_peaks": peaks,
            "defects_detected": defects,
            "diagnosis_summary": (
                "DEFECTS DETECTED: " + ", ".join(d["diagnosis"] for d in defects)
                if defects
                else "No significant defects detected. Machine operating normally."
            ),
            "recommendation": (
                "Schedule bearing replacement within 2 weeks"
                if defects
                else "Continue routine monitoring"
            ),
        },
        simulated=True,
    )


def detect_anomalies(equipment_id: str, hours: int = 24) -> dict:
    hours = min(max(int(hours), 1), 168)
    today = _today()
    r = _rng(
        "detect_anomalies", equipment_id.upper(), hours, today.strftime("%Y-%m-%d")
    )

    anomalies = []
    for sensor in SENSORS:
        num = r.randint(0, 3) if r.random() > 0.3 else 0
        for _ in range(num):
            z_score = round(r.uniform(2.5, 6.0), 2)
            anomalies.append(
                {
                    "sensor": sensor,
                    "timestamp": (
                        today - timedelta(hours=r.uniform(0, hours))
                    ).isoformat(),
                    "value": round(r.uniform(50, 200), 2),
                    "expected_value": round(r.uniform(40, 150), 2),
                    "z_score": z_score,
                    "severity": (
                        "CRITICAL"
                        if z_score > 4.5
                        else "WARNING" if z_score > 3.0 else "INFO"
                    ),
                    "detection_method": r.choice(
                        ["z-score", "moving_average_deviation", "isolation_forest"]
                    ),
                }
            )
    anomalies.sort(key=lambda a: a["z_score"], reverse=True)

    correlation_patterns = []
    if len(anomalies) >= 2:
        anomalous_sensors = sorted(set(a["sensor"] for a in anomalies))
        if len(anomalous_sensors) >= 2:
            pair = anomalous_sensors[:2]
            correlation_patterns.append(
                {
                    "sensors": pair,
                    "correlation": round(r.uniform(0.7, 0.98), 2),
                    "pattern": f"{pair[0]} spikes correlated with {pair[1]} increases",
                    "possible_cause": r.choice(
                        [
                            "Bearing degradation causing increased friction and heat",
                            "Load increase affecting multiple parameters",
                            "Lubrication issue causing cascading sensor changes",
                            "Misalignment causing vibration and temperature rise",
                        ]
                    ),
                }
            )

    return tool_ok(
        {
            "equipment_id": equipment_id,
            "analysis_window_hours": hours,
            "total_anomalies": len(anomalies),
            "anomaly_summary": {
                "critical": sum(1 for a in anomalies if a["severity"] == "CRITICAL"),
                "warning": sum(1 for a in anomalies if a["severity"] == "WARNING"),
                "info": sum(1 for a in anomalies if a["severity"] == "INFO"),
            },
            "anomalies": anomalies[:10],
            "correlation_patterns": correlation_patterns,
            "overall_assessment": (
                "ANOMALOUS"
                if any(a["severity"] == "CRITICAL" for a in anomalies)
                else "WATCH" if anomalies else "NORMAL"
            ),
            "sensors_analyzed": len(SENSORS),
            "recommendation": (
                "Investigate critical anomalies immediately. Cross-reference with "
                "maintenance history."
                if anomalies
                else "No anomalies detected. Equipment operating within normal "
                "parameters."
            ),
        },
        simulated=True,
    )


def get_reliability_metrics(equipment_id: str) -> dict:
    r = _rng("reliability_metrics", equipment_id.upper())
    mtbf_hours = r.randint(500, 8000)
    mttr_hours = round(r.uniform(1, 48), 1)
    availability = round(mtbf_hours / (mtbf_hours + mttr_hours) * 100, 2)
    performance_rate = round(r.uniform(80, 99), 1)
    quality_rate = round(r.uniform(92, 99.8), 1)
    oee = round(
        availability / 100 * performance_rate / 100 * quality_rate / 100 * 100, 1
    )
    failures_12m = r.randint(2, 20)

    return tool_ok(
        {
            "equipment_id": equipment_id,
            "period": "Last 12 months",
            "reliability_metrics": {
                "mtbf_hours": mtbf_hours,
                "mtbf_days": round(mtbf_hours / 24, 1),
                "mttr_hours": mttr_hours,
                "failure_rate_per_1000h": round(1000 / mtbf_hours, 3),
            },
            "oee_breakdown": {
                "oee_pct": oee,
                "availability_pct": availability,
                "performance_rate_pct": performance_rate,
                "quality_rate_pct": quality_rate,
                "oee_class": (
                    "World Class"
                    if oee >= 85
                    else "Good" if oee >= 70 else "Needs Improvement"
                ),
            },
            "failure_history": {
                "total_failures_12m": failures_12m,
                "total_downtime_hours": round(failures_12m * mttr_hours, 1),
                "top_failure_modes": [
                    {
                        "mode": "Bearing failure",
                        "count": r.randint(1, 5),
                        "avg_repair_hours": round(r.uniform(2, 12), 1),
                    },
                    {
                        "mode": "Seal leak",
                        "count": r.randint(0, 3),
                        "avg_repair_hours": round(r.uniform(1, 6), 1),
                    },
                    {
                        "mode": "Electrical fault",
                        "count": r.randint(0, 3),
                        "avg_repair_hours": round(r.uniform(1, 8), 1),
                    },
                ],
                "unplanned_downtime_pct": round(r.uniform(20, 70), 1),
            },
            "trends": {
                "mtbf_trend": r.choice(["IMPROVING", "STABLE", "DECLINING"]),
                "mtbf_change_pct": round(r.uniform(-15, 20), 1),
                "oee_trend": r.choice(["IMPROVING", "STABLE", "DECLINING"]),
                "oee_change_pct": round(r.uniform(-5, 10), 1),
            },
            "benchmarks": {
                "industry_avg_oee": 65.0,
                "industry_avg_mtbf_hours": 3000,
                "vs_industry_oee": round(oee - 65.0, 1),
                "vs_industry_mtbf": round((mtbf_hours - 3000) / 3000 * 100, 1),
            },
        },
        simulated=True,
    )


TOOLS = {
    "predict_failure": predict_failure,
    "analyze_vibration": analyze_vibration,
    "detect_anomalies": detect_anomalies,
    "get_reliability_metrics": get_reliability_metrics,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
