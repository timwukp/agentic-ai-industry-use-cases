"""Gateway target: prediction — failure prediction, vibration analysis, anomalies, reliability.

Predictions are deterministic simulations seeded from the function inputs.
ISO 10816 zone boundaries and bearing defect frequency ratios are real
reference values.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import asset_basis, tool_ok
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


# Share of failures attributable to each mode, in the order the dashboard lists
# them. Bearings dominate rotating-equipment failure statistics.
#: Production hours in the reporting year — the denominator both the failure
#: count and OEE availability are measured against. This plant runs continuously,
#: so it is the full 8760, and the two figures must use the same basis: dividing
#: failures by 8760 while measuring availability against a 2000-hour year makes a
#: machine that fails four times a year look 99% available.
SCHEDULED_HOURS = 8760

FAILURE_MODE_SHARES = [
    ("Bearing failure", 0.5, (2, 12)),
    ("Seal leak", 0.3, (1, 6)),
    ("Electrical fault", 0.2, (1, 8)),
]


def _partition_failures(total: int, r: random.Random) -> list:
    """Split `total` failures across the modes so the rows sum to the header.

    Drawn independently, the three mode counts summed to 9 under a
    "4 failures in 12 months" header on the same card. Largest-remainder
    apportionment keeps the split exact for any total, including 1.
    """
    exact = [(name, total * share, rng) for name, share, rng in FAILURE_MODE_SHARES]
    counts = [int(v) for _, v, _ in exact]
    # Hand out the rounding remainder to the modes with the largest fractions.
    remainder = total - sum(counts)
    order = sorted(range(len(exact)), key=lambda i: exact[i][1] % 1, reverse=True)
    for i in order[:remainder]:
        counts[i] += 1
    return [
        {
            "mode": name,
            "count": count,
            "avg_repair_hours": round(r.uniform(lo, hi), 1),
        }
        for (name, _, (lo, hi)), count in zip(exact, counts)
    ]


def predict_failure(equipment_id: str) -> dict:
    """Remaining useful life implied by the asset's current wear state.

    RUL is scaled by wear from the shared basis rather than drawn on its own: the
    dashboard shows the prediction card beside the fleet health pill for the same
    asset, and independent draws gave a 34-health STOPPED machine a 98-day RUL.
    """
    today = _today()
    basis = asset_basis(equipment_id, today.strftime("%Y-%m-%d"))
    r = _rng("predict_failure", equipment_id.upper(), today.strftime("%Y-%m-%d"))
    primary = r.choice(FAILURE_MODES)
    # A pristine asset gets its full nominal life; a fully worn one is nearly out
    # of it. Quadratic so the fall-off tracks the vibration curve in asset_basis.
    life_left = max(0.03, (1 - basis.wear) ** 2)
    rul_days = max(
        1,
        int(
            r.gauss(
                primary["typical_rul_days"] * life_left,
                primary["typical_rul_days"] * life_left * 0.2,
            )
        ),
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
                # degradation IS the wear state, in percent — the card prints it
                # next to the RUL that was just derived from the same number
                "current_degradation_pct": round(basis.wear * 100, 1),
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
    basis = asset_basis(equipment_id, today.strftime("%Y-%m-%d"))
    r = _rng("analyze_vibration", equipment_id.upper(), today.strftime("%Y-%m-%d"))
    # Same shaft speed the status route reports, so the spectrum's 1X peak lands
    # where the asset's own RPM says it should.
    shaft_rpm = basis.rpm or r.randint(900, 3600)
    shaft_freq = round(shaft_rpm / 60, 2)

    # bearing defect frequencies (typical ratios to shaft frequency)
    bpfo = round(shaft_freq * r.uniform(3.0, 5.5), 2)
    bpfi = round(shaft_freq * r.uniform(5.0, 8.5), 2)
    bsf = round(shaft_freq * r.uniform(2.0, 4.5), 2)
    ftf = round(shaft_freq * r.uniform(0.35, 0.48), 2)
    # The ISO zone printed here has to be the zone the asset's own vibration
    # reading falls in — drawn apart, this card said "Zone A, newly commissioned"
    # for an asset the alert list flagged at 14 mm/s.
    overall_velocity = basis.vibration_mm_s

    # ISO 10816 zones (Class III machine)
    if overall_velocity <= 1.8:
        iso_zone, iso_desc = "A", "Good - newly commissioned machines"
    elif overall_velocity <= 4.5:
        iso_zone, iso_desc = "B", "Acceptable - unrestricted long-term operation"
    elif overall_velocity <= 11.2:
        iso_zone, iso_desc = "C", "Alert - restricted operation, plan maintenance"
    else:
        iso_zone, iso_desc = "D", "Danger - damage occurring, immediate action required"

    # Peaks are a share of the overall RMS, and a defect is called only when its
    # own peak is significant. Independent draws produced 5 mm/s peaks under a
    # 0.7 mm/s overall reading, and named an "inner race defect" on a machine
    # whose spectrum was flat.
    def _peak(freq: float, label: str, share: float, defect: str) -> dict:
        amplitude = round(overall_velocity * share * r.uniform(0.8, 1.2), 2)
        return {
            "frequency_hz": freq,
            "amplitude_mm_s": amplitude,
            "label": label,
            # 1.8 mm/s is the ISO 10816 Zone A/B boundary — below it a peak is
            # not evidence of anything.
            "diagnosis": defect if amplitude > 1.8 else "Normal",
        }

    peaks = [
        _peak(shaft_freq, "1X (Shaft speed)", 0.55, "Imbalance"),
        _peak(round(shaft_freq * 2, 2), "2X (Shaft speed)", 0.32, "Misalignment"),
        _peak(bpfo, "BPFO (Outer race)", 0.24, "Outer race defect"),
        _peak(bpfi, "BPFI (Inner race)", 0.18, "Inner race defect"),
        _peak(bsf, "BSF (Ball spin)", 0.12, "Rolling element defect"),
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
    """12-month reliability, scaled by how worn the asset is.

    A worn machine fails more often and runs slower. Drawn independently, the
    OEE card reported "World Class 88%" for the asset the fleet table listed as
    STOPPED at health 34 — the two sit on the same drill-down screen.
    """
    today = _today()
    basis = asset_basis(equipment_id, today.strftime("%Y-%m-%d"))
    r = _rng("reliability_metrics", equipment_id.upper(), today.strftime("%Y-%m-%d"))

    # MTBF falls off with wear; the 500h floor is a machine failing weekly.
    mtbf_hours = max(500, int(8000 * (1 - basis.wear) ** 1.5 * r.uniform(0.85, 1.15)))
    # Operating hours in the year / MTBF, floored at one failure.
    failures_12m = max(1, round(SCHEDULED_HOURS / mtbf_hours))
    # Downtime is the sum of the repairs actually listed below, and MTTR is that
    # downtime per failure. Drawing MTTR on its own gave a card whose three
    # repair rows totalled 31h beside a "total downtime 4.2h" figure.
    failure_modes = _partition_failures(failures_12m, r)
    breakdown_hours = round(
        sum(m["count"] * m["avg_repair_hours"] for m in failure_modes), 1
    )
    mttr_hours = round(breakdown_hours / failures_12m, 1)
    # Planned maintenance is scheduled per quarter and roughly constant; the
    # unplanned share is therefore the failure downtime measured against the two
    # together, not a free 20-70% draw that could sit below the failure hours.
    planned_hours = round(4 * r.uniform(3, 10), 1)
    unplanned_pct = round(breakdown_hours / (breakdown_hours + planned_hours) * 100, 1)

    # OEE availability is planned production time less ALL downtime, not just
    # breakdowns: setup, changeover and adjustment losses dominate, and a worn
    # asset needs more of them. Counting only the ~15h of breakdown repair gave
    # 99.8% availability, which put 13 of 14 assets at "World Class" OEE
    # directly above a benchmark card reading "industry average 65%" — and rated
    # a DEGRADED machine 87.6%.
    setup_hours = round(SCHEDULED_HOURS * (0.03 + basis.wear * 0.12), 1)
    total_downtime = breakdown_hours + planned_hours + setup_hours
    availability = round((SCHEDULED_HOURS - total_downtime) / SCHEDULED_HOURS * 100, 2)
    # A worn asset is run below rated speed and scraps more, which is exactly
    # what the performance and quality rates measure.
    performance_rate = round(95 - basis.wear * 25 * r.uniform(0.95, 1.05), 1)
    quality_rate = round(99.5 - basis.wear * 6 * r.uniform(0.95, 1.05), 1)
    oee = round(
        availability / 100 * performance_rate / 100 * quality_rate / 100 * 100, 1
    )

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
                "total_downtime_hours": breakdown_hours,
                # The mode counts partition total_failures_12m — drawn apart, the
                # three rows summed to 9 under a "4 failures" header.
                "top_failure_modes": failure_modes,
                "planned_downtime_hours": planned_hours,
                "unplanned_downtime_pct": unplanned_pct,
            },
            "trends": {
                # A worn asset is on the way down; the trend label must not
                # contradict the wear-derived MTBF printed above it.
                "mtbf_trend": (
                    "DECLINING"
                    if basis.wear > 0.6
                    else "STABLE" if basis.wear > 0.3 else "IMPROVING"
                ),
                "mtbf_change_pct": round((0.45 - basis.wear) * 40, 1),
                "oee_trend": (
                    "DECLINING"
                    if basis.wear > 0.6
                    else "STABLE" if basis.wear > 0.3 else "IMPROVING"
                ),
                "oee_change_pct": round((0.45 - basis.wear) * 20, 1),
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
