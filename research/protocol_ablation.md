# FROZEN 2026-08-20 — tag `ablation-preregistered`

Gates below may no longer change; the one-shot discipline applies from this commit onward.

# Protocol: governance ablation (counterfactual adoption analysis)

For the paper (Section "Counterfactual ablation"). Question: which of the
ten campaign candidates would WEAKER governance regimes have adopted,
given exactly the evidence stored in the committed results artifacts?

## Honesty preamble (read first)

This is a retrospective reclassification of already-public data, not a
blind experiment: the analyst has seen every outcome. Its integrity rests
on three mechanical properties, all checkable by a reviewer: (1) the
regime rules below are generic per evidence TYPE (comparison / calibration
/ detector / discovery-scan), not per candidate; (2) every input is a
committed artifact in `research/results/`; (3) regime R4 must reproduce
the recorded scoreboard exactly — if it does not, the mapping is wrong and
the run is void (built-in positive control).

## Regimes

- **R0 point-estimate chasing**: adopt iff the primary point estimate
  improves in a strict majority of stored units (cohorts/assets), no
  significance required.
- **R1 naive in-sample significance**: adopt iff ANY stored unit shows
  primary-test p < 0.05 with improvement sign (no correction, no
  consistency, no OOS). Missing/NaN p-values cannot adopt.
- **R2 multiplicity-corrected only**: Benjamini-Hochberg across the
  candidate's own stored p-value family at q < 0.05; comparison/discovery
  candidates adopt iff any corrected discovery survives WITH improvement
  sign; calibration candidates adopt iff NO calibration test rejects
  after correction.
- **R3 consistency/OOS-only**: adopt iff improvement direction holds in a
  strict majority of stored era/asset cells AND no cohort-level point
  estimate is opposite-signed. No significance requirement.
- **R4 production dual gate (control)**: the recorded verdicts of the
  frozen protocols. Not recomputed — asserted against
  `findings_addendum.md`'s scoreboard.

Nesting note: the two promoted candidates passed R4, whose requirements
imply R1–R3 and (empirically, from their stored metrics) R0; their rows
are derived by that implication and marked so.

## Candidate-to-evidence mapping (mechanical, from committed fields)

| # | Candidate | Type | Stored evidence (file · fields) |
|---|---|---|---|
| 1 | Regime-conditional EVT | calibration | **prose-only in study revision — EXCLUDED from R0–R3 (n/a), stated in the paper**; R4 = refuted (recorded) |
| 2 | Fisher combination | promoted | nested-implication row (see above) |
| 3 | Vol-filtered EVT VaR | promoted | nested-implication row |
| 4 | QIS shrinkage | comparison | `qis_test.json` · per-cohort `paired_mean_diff`, `bootstrap_p`, `eras.*.improved` |
| 5 | RFSV rough vol | calibration | `rfsv_test.json` · per-asset `kupiec_p`, `cc_p`, `rate` (arm rfsv vs ewma) |
| 6 | Signature features | comparison | `signature_test.json` · same shape as QIS |
| 7 | BOCPD/CUSUM v1 | detector | `bocpd_test.json` · per-cohort `median_lag`, `detected`, `fa_per_250bd`, `bootstrap_p`, era lag cells |
| 8 | BOCPD v2 | detector | `bocpd_v2_test.json` · `pooled_mean_lag_gain_bd`, `sign_permutation_p`, per-cohort medians, `fa_within_budget` |
| 9 | BC frequency v1 | discovery scan | `bcfreq_test.json` · `full_sample[].p/q/significant` |
| 10 | BC v2 | discovery scan | `bcfreq_v2_test.json` · `full_sample[].p/q`, `gate.c3_positive_control` |

Type-generic operationalizations (exact code in `run_ablation.py`):
- comparison: unit = cohort; improvement = `paired_mean_diff > 0`;
  p = `bootstrap_p`; era cells = `eras.*.improved`.
- calibration: unit = asset; improvement = |violation rate − 0.01|
  strictly smaller than incumbent's; p-family = candidate's
  {kupiec_p, cc_p} per asset; "rejects" = corrected q < 0.05.
- detector: unit = cohort; improvement = median lag strictly smaller
  (detection where incumbent has none counts as improvement; both-None is
  a tie) with false alarms within the stored budget; p = stored
  bootstrap/permutation p.
- discovery scan: unit = scan row; R0/R1 use raw `p`; R2 uses stored `q`
  (already BH within the scan); improvement sign = the scan's own
  `significant` orientation. **Positive-control status is deliberately
  IGNORED by R0–R3** — that is the point being measured (naive regimes
  never run positive controls); the paper reports gate.c3 alongside.

## Deliverables

`research/results/ablation_matrix.json` (10 x 5 adoption matrix + per-cell
reason strings) and the paper table generated from it verbatim.

## Fast-failure clause

If R4 fails to reproduce the recorded scoreboard, the run is void and the
mapping error is recorded here before any re-run (one-shot discipline on
the mapping itself).

## Freeze ceremony (EXECUTED 2026-08-20)

Pre-freeze, only the R4 calibration check may run. Freeze = rename +
tag `ablation-preregistered` on explicit user instruction; then R0–R3 are
computed once and committed.
