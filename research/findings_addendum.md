# Findings Addendum — Triggered Revisions Re-Tested (Exploratory)

Post-study execution of the pre-registered failure→revision map
(protocol §6). Same back-to-back methodology as the study; run after the
`study-preregistered` freeze, labeled exploratory per protocol.

## Revision 1: regime-conditional EVT — **re-test REFUTES the fix for VaR**

Two variants were back-tested on C36 (point-in-time, monthly refits,
~8,500 out-of-sample days):

| Variant | NASDAQCOM violations | vs study's unconditional |
|---|---|---|
| Study baseline (unconditional 5y GPD) | 1.38% (target 1%) , CC p=0.046 | — |
| Current-regime VaR | 3.64%, red zone | **worse** |
| Regime-probability mixture VaR | 3.01%, red zone | **worse** |

**Why it fails — and why that is informative**: the point-in-time regime
estimate is itself lagged (H1b: >10bd detection lag). Conditioning
tomorrow's VaR on today's *estimated* regime means running with a THIN
calm-regime tail exactly when the market is transitioning into stress —
the two validated weaknesses (H1b lag, H4 clustering) compound instead of
cancelling. The unconditional 5y window, by accident of its bluntness,
always carries some crisis days and is therefore harder to surprise.

**Disposition**:
- `fit_gpd_by_regime` STAYS in PRISM as a **descriptive** layer — the
  synthetic test proves it correctly separates planted calm/stress tails,
  and "the stress-regime tail is ξ=X vs calm ξ=Y" is honest, validated
  descriptive content for the agent.
- The nightly payload's `by_regime` tails are labeled descriptive; the
  headline VaR remains the unconditional fit.
- H4 calibration remains OPEN. Next candidates (not yet tested): EGARCH-
  filtered EVT (conditional volatility, not conditional regime), or a
  shorter rolling window with exponential weighting.

## Revision 2: max-rule power audit — **confirms the diagnosis, fix shipped**

Synthetic planted-causality grids (20 seeds/cell, study settings):

| effect size β | max rule | Fisher | min+Bonferroni |
|---|---|---|---|
| 0.10 | 10% | **85%** | 80% |
| 0.15 | 15% | **100%** | 100% |
| 0.20 | 55% | **100%** | 100% |
| 0.30 | 100% | 100% | 100% |

False positives (pure-noise grids): max 0/20, Fisher 1/20, min 2/20.

**Decision**: `causality_scan` switched to **Fisher combination** —
8.5x power at β=0.10 for ~1-in-20 grids showing a single BH-controlled
false discovery (the FDR contract allows this; the old zero-FP behavior
was over-conservatism, not a guarantee). The noise-grid unit test was
updated from "zero discoveries ever" to the actual FDR bound (≤2 of 8
seed-grids), with the reasoning documented in the test.

**Monthly-frequency probe**: oil→10Y at monthly aggregation reaches
p≈0.12–0.16 (max) / 0.12 (Fisher) — still short of significance but an
order of magnitude closer than daily (q≈0.85). Consistent with the
literature operating at monthly+ horizons; a monthly-frequency scan tier
is a possible future addition.

## Revision 3: system prompt — shipped

Regime = validated historical lens (AUROC 0.85–0.91 cited) with explicit
lag caveat; impact functions presented as bands; crash-timing questions
get the fragility-vs-trigger framing with the SPA finding cited; per-regime
tails offered as descriptive context only.
