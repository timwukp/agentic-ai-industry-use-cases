# Maintenance Standards Summary — ISO 55000 & ISO 10816 (Demo Plant)

Document ID: STD-MAINT-001 | Effective: 2026-01-01 | Owner: Reliability Engineering

## ISO 55000 asset management principles (as applied at this plant)

- Value: maintenance decisions must trace to asset value (production impact x
  criticality), not just equipment age.
- Alignment: the maintenance plan is reviewed quarterly against production targets.
- Assurance: every critical asset has a documented maintenance strategy (preventive,
  predictive, or run-to-failure with rationale).
- Criticality classes: HIGH (production stopper / safety), MEDIUM (degrades output),
  LOW (redundant or non-production).

## ISO 10816 vibration severity (Class III — large machines, rigid foundation)

| Zone | Velocity RMS (mm/s) | Meaning | Required action |
|------|---------------------|---------|-----------------|
| A | <= 1.8 | Good — newly commissioned | None |
| B | 1.8 - 4.5 | Acceptable — unrestricted long-term operation | Routine monitoring |
| C | 4.5 - 11.2 | Alert — restricted operation | Plan maintenance within 2 weeks |
| D | > 11.2 | Danger — damage occurring | Immediate action / shutdown |

- Zone D reading on HIGH-criticality equipment: stop the machine, notify the shift
  supervisor, and open a critical work order the same shift.

## Bearing defect frequencies

Monitor BPFO (outer race), BPFI (inner race), BSF (ball spin), FTF (cage) sidebands.
A defect frequency amplitude above 25% of the 1X peak, trending upward across two
measurements, triggers a predictive work order.

## Reliability KPIs

- OEE = Availability x Performance x Quality. World class >= 85%; plant target 75%.
- MTBF/MTTR reviewed monthly per asset; reactive maintenance share target < 30%.
- Every failure event requires a failure mode code for Weibull trending.

## Maintenance program rules

- Preventive intervals derive from OEM manuals adjusted by observed MTBF.
- Predictive triggers (vibration, thermography, oil analysis) override calendar PMs.
- Deferred maintenance requires documented risk acceptance by the reliability manager.
