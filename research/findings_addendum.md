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
- ~~H4 calibration remains OPEN~~ **RESOLVED by candidate 2** (below).

## Revision 1b: volatility-filtered EVT — **PASSES, promoted to production**

Candidate 2 (McNeil-Frey): EWMA(0.94) conditional volatility, GPD on
standardized residuals, VaR_t+1 = sigma_t+1 × residual quantile. Same
point-in-time protocol, C36, 9,026 OOS days:

| Variant | NASDAQCOM | DGS10 |
|---|---|---|
| Unconditional (study baseline) | 1.38%, CC p=0.046, amber | 1.61%, amber |
| Regime-conditional (refuted) | 3.64%, red | 1.50%, red |
| **Vol-filtered (candidate 2)** | **1.04%, Kupiec p=0.69, CC p=0.61, GREEN** | **1.00%, Kupiec p=0.98, CC p=0.99, GREEN** |

Max violations in any 22-day window: 4 (NASDAQ) / 3 (DGS10) — the
clustering that killed both prior variants is gone. Mechanism: volatility
clusters (the one robustly forecastable property of daily returns) and the
EWMA filter needs no hidden-state inference, so it adapts within days
instead of lagging like the regime estimate.

Promoted: `fit_vol_filtered_var` in prism/tails.py; the nightly payload's
`calibrated` block is now the headline forward-looking VaR; the system
prompt directs the agent to quote it for magnitudes. Two synthetic-truth
tests added (causality of the sigma filter; calibration on planted GARCH).

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

## QIS covariance cleaning in the HMM regime layer — **FAST FAILURE, not promoted**

Pre-registered test (`protocol_qis.md`, tag `qis-test-preregistered`;
motivated by the deep-research report's #1 shortlist item). Baseline vs
shrunk-covariance HMM, identical in everything else, three cohorts,
point-in-time:

| Cohort | baseline H1b AUROC | QIS AUROC | Δ | bootstrap p | lag Δ |
|---|---|---|---|---|---|
| C10 | 0.7438 | 0.7403 | **−0.0035** | 0.62 | 0 |
| C20 | 0.7634 | 0.7653 | +0.0019 | 0.068 | 0 |
| C36 (primary) | 0.7379 | 0.7377 | **−0.0002** | 0.009* | 0 |

*C36's small p attaches to a NEGATIVE point difference — evidence of a
tiny systematic degradation, not improvement.

**Gate verdict (frozen criteria)**: condition 1 fails (improvement in only
1/3 cohorts), condition 2 fails (no significant pooled improvement in the
right direction), era stability mixed (3/6 eras). **QIS does not enter
PRISM.**

**Why the null makes sense in hindsight** (post-hoc interpretation,
labeled as such): shrinkage earns its keep when p/n is adverse. Our regime
layer runs p=4-5 variables against 750+ training days (p/n < 0.01) — the
sample covariance is already nearly optimal, so shrinkage mostly nudges
probabilities by noise. The deep-research report itself scoped QIS's
evidence to p in the hundreds (portfolio covariance); the test confirms
the transfer to tiny-p regime detection does not hold. The self-calibrated
`studylib/qis.py` implementation remains available for any future
LARGE-p application (e.g. a cross-sectional portfolio layer), where the
literature's evidence actually lives.

## Revision 3: system prompt — shipped

Regime = validated historical lens (AUROC 0.85–0.91 cited) with explicit
lag caveat; impact functions presented as bands; crash-timing questions
get the fragility-vs-trigger framing with the SPA finding cited; per-regime
tails offered as descriptive context only.
