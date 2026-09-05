# Rejected candidates — pre-freeze screening kills

One line per candidate the theory scout (or a human survey) rejected BEFORE a
protocol freeze. This is the shelf's memory against re-shopping: Phase 0 of
every scout cycle reads this file, and a candidate listed here is consumed —
it may only be re-opened by a human with a written reason (new evidence, or a
representation change that voids the kill).

Post-freeze failures live in [findings_addendum.md](findings_addendum.md)
(they carry full protocols); representation-bound deferrals live in
[conditional_candidates.md](conditional_candidates.md). This file is for
candidates that never earned a protocol.

Append discipline: the scout adds ONE line per rejection via a micro-PR
touching only this file; a human merge is the acknowledgment.

| Date | Candidate | Target deficiency | Kill reason (one line of evidence) |
|---|---|---|---|
| 2026-08-11 | Smooth Local Projections (Barnichon & Brownlees 2019) | H3 — wide impact-function bands at h≤5 | Pre-registered positive-control power check: best 28.7% vs 80% gate across all configs; dominated by a simpler confound-isolating control. (H3 itself was later root-caused as an instrument defect and repaired — PR #65/#66 — so the target no longer exists in its old form.) |
| 2026-08-20 | ENSO (ONI) → US farm-products PPI (frozen test, tag `enso-farmppi-test-preregistered`) | Climate→ag-price transmission for a monthly branch | **Post-freeze FAST FAIL 0/4 gates**: Granger p=0.377; LP betas NEGATIVE at h∈{6,9,12} (−0.024..−0.044, bands straddle 0); era halves disagree; walk-forward pooled edge 0.0436 < 0.0903. Instrument power was 1.00 → real rejection. Per protocol: reads "US farm PPI doesn't carry the world-commodity effect", not "ENSO doesn't matter". |
| 2026-09-01 | Large-scale nonlinear Granger causality (data-driven multivariate network recovery, arXiv:2009.04681) | H2 — oil→10Y causality invisible at daily/all-frequency scan | Targets many-series (tens–hundreds) directed-network recovery from short series (neuroscience/genomics framing); PRISM's H2 question is one pre-specified pair — same applicability-gap failure class as QIS (p≈500 evidence vs p=5 use). Screened out pre-freeze, no protocol written. |
| 2026-09-01 | Neural / kernel-ridge nonlinear Granger causality (arXiv:2309.05107, 1711.08160, 1911.09879) | H2 — oil→10Y causality invisible at daily/all-frequency scan | Requires more training data or black-box hyperparameters (kernel bandwidth, network depth) disproportionate to a 2-variable daily-pair test; repeats BC v2's own lesson that 45 parameters/cell already over-fit the data volume available. Screened out pre-freeze, no protocol written. |
