"""Asset-anchored condition basis for the manufacturing tools.

Every manufacturing tool used to draw its own condition for an asset, so the
fleet table listed EQ-CNC-003 as STOPPED at health 34.9 while the drill-down for
that same asset reported RUNNING at health 76.7. Clicking a stopped machine
showed it running — that reads as broken data rather than a simulation.

The fix mirrors toolkit.property_basis: one deterministic basis keyed on the
asset id alone. Health, status and criticality are derived here from the asset's
own sensor readings, and each tool layers only its own concern on top (failure
prediction, reliability history, maintenance scheduling). Any tool given the same
asset id therefore agrees on what condition the machine is in.
"""

import hashlib
import random
import statistics
from dataclasses import dataclass

# Nominal operating envelope per asset family, keyed on the id's middle segment.
EQUIPMENT_TYPES = {
    "CNC": {"name": "CNC Milling Machine", "rpm": (800, 12000), "temp": (35, 95)},
    "PUMP": {"name": "Hydraulic Pump", "rpm": (1200, 3600), "temp": (40, 85)},
    "COMP": {"name": "Air Compressor", "rpm": (900, 3000), "temp": (50, 110)},
    "CONV": {"name": "Conveyor Belt Drive", "rpm": (60, 400), "temp": (30, 70)},
    "TURB": {"name": "Steam Turbine", "rpm": (3000, 15000), "temp": (80, 250)},
    "MOTOR": {"name": "Electric Motor", "rpm": (600, 3600), "temp": (35, 90)},
}

# Criticality is a property of the asset's role in the plant, not a die roll: the
# turbine and the press pump stop production, a backup compressor does not.
CRITICALITY = {
    "EQ-CNC-001": "HIGH",
    "EQ-CNC-002": "MEDIUM",
    "EQ-CNC-003": "HIGH",
    "EQ-PUMP-001": "HIGH",
    "EQ-PUMP-002": "MEDIUM",
    "EQ-COMP-001": "HIGH",
    "EQ-COMP-002": "LOW",
    "EQ-CONV-001": "HIGH",
    "EQ-CONV-002": "MEDIUM",
    "EQ-CONV-003": "MEDIUM",
    "EQ-TURB-001": "HIGH",
    "EQ-MOTOR-001": "HIGH",
    "EQ-MOTOR-002": "LOW",
    "EQ-MOTOR-003": "MEDIUM",
}

# Health bands the whole app shares. STOPPED is not a random 5% draw — a machine
# is stopped because its health collapsed, which is what the alert list and the
# maintenance schedule both assume when they single that asset out.
STOPPED_BELOW = 40.0
DEGRADED_BELOW = 65.0


@dataclass(frozen=True)
class AssetBasis:
    """What every manufacturing tool must agree on for a given asset id."""

    equipment_id: str
    equipment_name: str
    #: Latent wear state in [0, 1] — the single cause every reading follows.
    wear: float
    temperature_c: float
    vibration_mm_s: float
    rpm: int
    oil_pressure_bar: float
    power_kw: float
    health_score: float
    criticality: str

    @property
    def status(self) -> str:
        if self.health_score < STOPPED_BELOW:
            return "STOPPED"
        if self.health_score < DEGRADED_BELOW:
            return "DEGRADED"
        return "RUNNING"

    @property
    def health_rating(self) -> str:
        if self.health_score >= 75:
            return "GOOD"
        if self.health_score >= 50:
            return "FAIR"
        return "POOR"


def asset_type(equipment_id: str) -> dict:
    """Operating envelope for an asset id, defaulting to the CNC family."""
    parts = equipment_id.upper().split("-")
    return EQUIPMENT_TYPES.get(
        parts[1] if len(parts) > 1 else "", EQUIPMENT_TYPES["CNC"]
    )


def basis_rng(equipment_id: str, day: str) -> random.Random:
    """RNG seeded on asset id + day — the shared anchor for all tools.

    The day is part of the seed so the plant's condition moves between demo runs
    while staying stable within a session; every tool passes the same day.
    """
    seed = hashlib.sha256(f"asset_basis|{equipment_id.strip().upper()}|{day}".encode())
    return random.Random(int(seed.hexdigest()[:16], 16))


def asset_basis(equipment_id: str, day: str) -> AssetBasis:
    """Condition of one asset on one day, from a single latent wear state.

    Readings are derived from `wear` rather than drawn independently. Drawing
    them apart made the readings mutually implausible — vibration uniform over
    (0.5, 18.0) put 60% of the fleet past the ISO 10816 Zone C boundary, which
    then raised a CRITICAL vibration alert on ten of fourteen machines while
    their temperature and oil pressure read perfectly normal.
    """
    eq_type = asset_type(equipment_id)
    r = basis_rng(equipment_id, day)

    # Right-skewed: most assets are in reasonable shape, a few are badly worn.
    # Calibrated so a 14-asset plant averages ~10 running / ~4 degraded and
    # raises roughly one critical alert — a plant where everything is on fire
    # reads as broken data, and one where nothing is has nothing to demo.
    wear = r.betavariate(2.0, 2.8)

    # Vibration grows with the square of wear: bearing damage stays quiet, then
    # climbs sharply near end of life.
    vibration = round(
        min(18.0, max(0.5, 0.5 + wear**2 * 17.5 * r.uniform(0.85, 1.15))), 2
    )
    t_lo, t_hi = eq_type["temp"]
    temp_frac = min(1.0, max(0.0, wear * r.uniform(0.7, 1.3)))
    temp_c = round(t_lo + (t_hi - t_lo) * temp_frac, 1)
    # Seal and pump wear bleeds pressure, so a worn asset is likelier to be
    # outside the 2.0-5.5 bar band.
    oil_pressure = (
        round(r.uniform(1.5, 2.0), 1)
        if r.random() < wear * 0.55
        else round(r.uniform(2.0, 5.5), 1)
    )

    # Health is min-dominant, not a plain average: one reading deep in Zone D
    # means the machine needs attention even if everything else is nominal. A
    # weighted mean scored a 14 mm/s asset at 72 and called it RUNNING.
    temp_score = max(0.0, 100 - temp_frac * 60)
    vib_score = max(0.0, 100 - vibration * 5)
    oil_score = 100.0 if 2.0 <= oil_pressure <= 5.5 else 55.0
    sub = [temp_score, vib_score, oil_score]
    health = round(min(100.0, 0.55 * min(sub) + 0.45 * statistics.mean(sub)), 1)

    return AssetBasis(
        equipment_id=equipment_id.upper(),
        equipment_name=eq_type["name"],
        wear=round(wear, 3),
        temperature_c=temp_c,
        vibration_mm_s=vibration,
        # A worn machine is often run slower, and a stopped one reads zero.
        rpm=(
            0
            if health < STOPPED_BELOW
            else round(r.randint(*eq_type["rpm"]) * (1 - wear * 0.25))
        ),
        oil_pressure_bar=oil_pressure,
        power_kw=round(r.uniform(5, 250), 1),
        health_score=health,
        criticality=CRITICALITY.get(equipment_id.upper(), "MEDIUM"),
    )
