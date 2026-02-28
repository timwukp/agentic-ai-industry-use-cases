from strands import tool
import json, random, math
from datetime import datetime, timedelta


@tool
def predict_failure(equipment_id: str) -> str:
    """ML-based failure prediction for equipment with remaining useful life estimation.

    Uses historical sensor data, maintenance records, and degradation models to predict
    when equipment is likely to fail and what failure mode is most probable.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001', 'EQ-PUMP-014').

    Returns:
        JSON with remaining useful life (RUL), failure probability, predicted failure
        mode, confidence interval, and recommended actions.
    """
    failure_modes = [
        {"mode": "BEARING_FAILURE", "component": "Main Bearing", "typical_rul_days": 45},
        {"mode": "SEAL_DEGRADATION", "component": "Mechanical Seal", "typical_rul_days": 60},
        {"mode": "IMPELLER_WEAR", "component": "Impeller", "typical_rul_days": 90},
        {"mode": "MOTOR_WINDING_FAULT", "component": "Stator Winding", "typical_rul_days": 30},
        {"mode": "GEAR_TOOTH_WEAR", "component": "Gearbox", "typical_rul_days": 120},
        {"mode": "SHAFT_MISALIGNMENT", "component": "Drive Shaft", "typical_rul_days": 75},
        {"mode": "LUBRICATION_BREAKDOWN", "component": "Lubrication System", "typical_rul_days": 20},
        {"mode": "ELECTRICAL_INSULATION_DEGRADATION", "component": "Motor Insulation", "typical_rul_days": 55},
    ]

    primary_failure = random.choice(failure_modes)
    rul_days = max(1, int(random.gauss(primary_failure["typical_rul_days"], primary_failure["typical_rul_days"] * 0.3)))
    failure_probability = round(min(0.99, max(0.05, 1 - (rul_days / (primary_failure["typical_rul_days"] * 2)))), 2)
    confidence = round(random.uniform(0.72, 0.96), 2)

    secondary_mode = random.choice([m for m in failure_modes if m["mode"] != primary_failure["mode"]])

    risk_level = "CRITICAL" if rul_days < 14 else "HIGH" if rul_days < 30 else "MEDIUM" if rul_days < 60 else "LOW"

    return json.dumps({
        "equipment_id": equipment_id,
        "prediction_model": "LSTM Degradation Model v3.2",
        "model_accuracy": round(random.uniform(0.85, 0.95), 2),
        "primary_prediction": {
            "failure_mode": primary_failure["mode"],
            "affected_component": primary_failure["component"],
            "remaining_useful_life_days": rul_days,
            "estimated_failure_date": (datetime.utcnow() + timedelta(days=rul_days)).strftime("%Y-%m-%d"),
            "failure_probability": failure_probability,
            "confidence_interval": {
                "lower_days": max(1, rul_days - int(rul_days * (1 - confidence))),
                "upper_days": rul_days + int(rul_days * (1 - confidence)),
                "confidence_level": confidence,
            },
        },
        "secondary_prediction": {
            "failure_mode": secondary_mode["mode"],
            "affected_component": secondary_mode["component"],
            "probability": round(random.uniform(0.05, 0.25), 2),
        },
        "risk_level": risk_level,
        "degradation_trend": {
            "current_degradation_pct": round(random.uniform(20, 85), 1),
            "degradation_rate_per_day": round(random.uniform(0.1, 2.5), 2),
            "acceleration": random.choice(["STABLE", "ACCELERATING", "DECELERATING"]),
        },
        "contributing_factors": [
            {"factor": "Vibration trend increasing", "impact": "HIGH"},
            {"factor": "Temperature above baseline", "impact": "MEDIUM"},
            {"factor": f"Operating hours: {random.randint(5000, 40000)}h", "impact": "MEDIUM"},
            {"factor": f"Last maintenance: {random.randint(30, 365)} days ago", "impact": random.choice(["LOW", "MEDIUM"])},
        ],
        "recommended_action": f"Schedule {'immediate' if risk_level == 'CRITICAL' else 'preventive'} maintenance for {primary_failure['component']} replacement within {min(rul_days, 7 if risk_level == 'CRITICAL' else 14)} days.",
        "predicted_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def analyze_vibration(equipment_id: str) -> str:
    """Perform vibration spectrum analysis to detect bearing defects and imbalance.

    Analyzes vibration frequency spectrum to identify characteristic defect frequencies
    for bearings (BPFO, BPFI, BSF, FTF), imbalance, misalignment, and looseness.
    Results classified per ISO 10816 vibration severity standards.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001').

    Returns:
        JSON with frequency spectrum peaks, defect frequencies, ISO 10816 zone
        classification, and diagnosis.
    """
    shaft_rpm = random.randint(900, 3600)
    shaft_freq = round(shaft_rpm / 60, 2)

    # Bearing defect frequencies (typical ratios to shaft frequency)
    bpfo = round(shaft_freq * random.uniform(3.0, 5.5), 2)
    bpfi = round(shaft_freq * random.uniform(5.0, 8.5), 2)
    bsf = round(shaft_freq * random.uniform(2.0, 4.5), 2)
    ftf = round(shaft_freq * random.uniform(0.35, 0.48), 2)

    overall_velocity = round(random.uniform(0.5, 20.0), 2)

    # ISO 10816 zones
    if overall_velocity <= 1.8:
        iso_zone = "A"
        iso_desc = "Good - newly commissioned machines"
    elif overall_velocity <= 4.5:
        iso_zone = "B"
        iso_desc = "Acceptable - unrestricted long-term operation"
    elif overall_velocity <= 11.2:
        iso_zone = "C"
        iso_desc = "Alert - restricted operation, plan maintenance"
    else:
        iso_zone = "D"
        iso_desc = "Danger - damage occurring, immediate action required"

    # Generate frequency peaks
    peaks = [
        {"frequency_hz": shaft_freq, "amplitude_mm_s": round(random.uniform(0.2, 5.0), 2), "label": "1X (Shaft speed)", "diagnosis": "Imbalance" if random.random() > 0.5 else "Normal"},
        {"frequency_hz": round(shaft_freq * 2, 2), "amplitude_mm_s": round(random.uniform(0.1, 3.0), 2), "label": "2X (Shaft speed)", "diagnosis": "Misalignment" if random.random() > 0.5 else "Normal"},
        {"frequency_hz": bpfo, "amplitude_mm_s": round(random.uniform(0.05, 2.5), 2), "label": "BPFO (Outer race)", "diagnosis": "Outer race defect" if random.random() > 0.6 else "Normal"},
        {"frequency_hz": bpfi, "amplitude_mm_s": round(random.uniform(0.05, 2.0), 2), "label": "BPFI (Inner race)", "diagnosis": "Inner race defect" if random.random() > 0.7 else "Normal"},
        {"frequency_hz": bsf, "amplitude_mm_s": round(random.uniform(0.02, 1.5), 2), "label": "BSF (Ball spin)", "diagnosis": "Rolling element defect" if random.random() > 0.8 else "Normal"},
    ]

    peaks.sort(key=lambda p: p["amplitude_mm_s"], reverse=True)

    defects_found = [p for p in peaks if p["diagnosis"] != "Normal"]

    return json.dumps({
        "equipment_id": equipment_id,
        "analysis_type": "FFT Vibration Spectrum Analysis",
        "measurement_point": random.choice(["Drive End Bearing", "Non-Drive End Bearing", "Gearbox Input", "Gearbox Output"]),
        "shaft_speed_rpm": shaft_rpm,
        "shaft_frequency_hz": shaft_freq,
        "overall_vibration": {
            "velocity_rms_mm_s": overall_velocity,
            "acceleration_peak_g": round(overall_velocity * random.uniform(0.8, 2.5), 2),
            "displacement_peak_um": round(overall_velocity * random.uniform(5, 20), 1),
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
        "defects_detected": defects_found,
        "diagnosis_summary": f"{'DEFECTS DETECTED: ' + ', '.join(d['diagnosis'] for d in defects_found) if defects_found else 'No significant defects detected. Machine operating normally.'}",
        "recommendation": "Schedule bearing replacement within 2 weeks" if defects_found else "Continue routine monitoring",
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def detect_anomalies(equipment_id: str, hours: int) -> str:
    """Detect anomalies in recent sensor data using statistical methods.

    Applies z-score analysis, moving average deviation, and isolation forest results
    to identify unusual patterns in multi-sensor data.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001').
        hours: Number of hours of recent data to analyze (1-168).

    Returns:
        JSON with detected anomalies, severity scores, and potential causes.
    """
    hours = min(max(hours, 1), 168)

    sensors = ["temperature", "vibration", "rpm", "oil_pressure", "power_consumption"]
    anomalies = []

    for sensor in sensors:
        num_anomalies = random.randint(0, 3) if random.random() > 0.3 else 0
        for _ in range(num_anomalies):
            z_score = round(random.uniform(2.5, 6.0), 2)
            anomalies.append({
                "sensor": sensor,
                "timestamp": (datetime.utcnow() - timedelta(hours=random.uniform(0, hours))).isoformat() + "Z",
                "value": round(random.uniform(50, 200), 2),
                "expected_value": round(random.uniform(40, 150), 2),
                "z_score": z_score,
                "severity": "CRITICAL" if z_score > 4.5 else "WARNING" if z_score > 3.0 else "INFO",
                "detection_method": random.choice(["z-score", "moving_average_deviation", "isolation_forest"]),
            })

    anomalies.sort(key=lambda a: a["z_score"], reverse=True)

    correlation_patterns = []
    if len(anomalies) >= 2:
        correlated_sensors = random.sample(sensors, min(2, len(set(a["sensor"] for a in anomalies))))
        if len(correlated_sensors) == 2:
            correlation_patterns.append({
                "sensors": correlated_sensors,
                "correlation": round(random.uniform(0.7, 0.98), 2),
                "pattern": f"{correlated_sensors[0]} spikes correlated with {correlated_sensors[1]} increases",
                "possible_cause": random.choice([
                    "Bearing degradation causing increased friction and heat",
                    "Load increase affecting multiple parameters",
                    "Lubrication issue causing cascading sensor changes",
                    "Misalignment causing vibration and temperature rise",
                ]),
            })

    return json.dumps({
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
        "overall_assessment": "ANOMALOUS" if any(a["severity"] == "CRITICAL" for a in anomalies) else "WATCH" if anomalies else "NORMAL",
        "sensors_analyzed": len(sensors),
        "data_points_evaluated": random.randint(500, 5000),
        "recommendation": "Investigate critical anomalies immediately. Cross-reference with maintenance history." if anomalies else "No anomalies detected. Equipment operating within normal parameters.",
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_reliability_metrics(equipment_id: str) -> str:
    """Get equipment reliability and performance metrics.

    Calculates MTBF (Mean Time Between Failures), MTTR (Mean Time To Repair),
    OEE (Overall Equipment Effectiveness), and availability metrics based on
    historical operational data.

    Args:
        equipment_id: Equipment identifier (e.g., 'EQ-CNC-001').

    Returns:
        JSON with MTBF, MTTR, OEE breakdown, availability, and trend data.
    """
    mtbf_hours = random.randint(500, 8000)
    mttr_hours = round(random.uniform(1, 48), 1)
    availability = round(mtbf_hours / (mtbf_hours + mttr_hours) * 100, 2)
    performance_rate = round(random.uniform(80, 99), 1)
    quality_rate = round(random.uniform(92, 99.8), 1)
    oee = round(availability / 100 * performance_rate / 100 * quality_rate / 100 * 100, 1)

    failures_12m = random.randint(2, 20)
    total_downtime_hours = round(failures_12m * mttr_hours, 1)

    return json.dumps({
        "equipment_id": equipment_id,
        "period": "Last 12 months",
        "reliability_metrics": {
            "mtbf_hours": mtbf_hours,
            "mtbf_days": round(mtbf_hours / 24, 1),
            "mttr_hours": mttr_hours,
            "mttf_hours": mtbf_hours + random.randint(100, 500),
            "failure_rate_per_1000h": round(1000 / mtbf_hours, 3),
        },
        "oee_breakdown": {
            "oee_pct": oee,
            "availability_pct": availability,
            "performance_rate_pct": performance_rate,
            "quality_rate_pct": quality_rate,
            "oee_class": "World Class" if oee >= 85 else "Good" if oee >= 70 else "Needs Improvement",
        },
        "failure_history": {
            "total_failures_12m": failures_12m,
            "total_downtime_hours": total_downtime_hours,
            "top_failure_modes": [
                {"mode": "Bearing failure", "count": random.randint(1, 5), "avg_repair_hours": round(random.uniform(2, 12), 1)},
                {"mode": "Seal leak", "count": random.randint(0, 3), "avg_repair_hours": round(random.uniform(1, 6), 1)},
                {"mode": "Electrical fault", "count": random.randint(0, 3), "avg_repair_hours": round(random.uniform(1, 8), 1)},
            ],
            "unplanned_downtime_pct": round(random.uniform(20, 70), 1),
            "planned_downtime_pct": round(random.uniform(30, 80), 1),
        },
        "trends": {
            "mtbf_trend": random.choice(["IMPROVING", "STABLE", "DECLINING"]),
            "mtbf_change_pct": round(random.uniform(-15, 20), 1),
            "oee_trend": random.choice(["IMPROVING", "STABLE", "DECLINING"]),
            "oee_change_pct": round(random.uniform(-5, 10), 1),
        },
        "benchmarks": {
            "industry_avg_oee": 65.0,
            "industry_avg_mtbf_hours": 3000,
            "vs_industry_oee": round(oee - 65.0, 1),
            "vs_industry_mtbf": round((mtbf_hours - 3000) / 3000 * 100, 1),
        },
        "calculated_at": datetime.utcnow().isoformat() + "Z",
    })
