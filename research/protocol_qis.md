# QIS Covariance Cleaning in the HMM Regime Layer — Pre-Registered Test Protocol

**Status**: FROZEN before any test code runs (same discipline as the main
study, tag reference `study-preregistered`). Changing hypotheses, thresholds,
or cohorts after execution invalidates the confirmatory claim. A negative
result is a valid outcome: **fast failure = QIS does not enter PRISM** and
the result is documented in the findings addendum.

**Motivation** (deep-research report, `deep_research_tao_math_finance.json`):
hmmlearn's GaussianHMM estimates per-state covariance matrices by (weighted)
sample covariance. With ~4-5 observed variables this is low-dimensional, so
the theoretical benefit of shrinkage is NOT presumed — that is exactly what
this test decides. No assumption is smuggled in: the null hypothesis is
"QIS does not help".

## Hypothesis (single, pre-registered)

**H-QIS**: replacing each HMM state's covariance with its Ledoit-Wolf-style
shrunk counterpart improves stress-regime detection, measured by:

- **Primary endpoint**: H1b point-in-time AUROC (expanding monthly refits,
  filtered last-obs stress probability vs the frozen NBER+crash chronology).
  Point-in-time because that is the deployable claim; H1a (smoothed) is
  reported as a secondary descriptive endpoint.
- **Secondary endpoints**: H1b median detection lag; H1a smoothed AUROC;
  HMM log-likelihood (in-sample, descriptive only).

## Decision gate (journal-grade, frozen)

QIS is promoted to PRISM only if ALL of:

1. **Direction**: H1b AUROC(QIS) > AUROC(baseline) in ≥ 2 of 3 cohorts
   (C10, C20, C36), with no cohort degrading by more than 0.02.
2. **Significance**: stationary block-bootstrap (B=1000, block=20, seed=7)
   on the paired daily score differences yields p < 0.05 for the pooled
   AUROC improvement (per-cohort p-values reported; pooling via Stouffer).
3. **Era stability**: the sign of the improvement holds in ≥ 3 of 4
   pre-registered eras (chronology.ERAS) where the cohort covers the era.
4. **No lag regression**: median detection lag must not worsen by > 2
   business days in any cohort.

Anything less = fast failure, documented, QIS stays out.

## Method (frozen)

- **Baseline**: `fit_regimes` / `pit_regime_probs` exactly as shipped
  (hmmlearn GaussianHMM, full covariance, seed 7).
- **Treatment**: identical pipeline, except after each EM fit the per-state
  covariances are replaced by the analytical nonlinear-shrinkage-style
  estimator applied to the state-weighted data (implementation:
  `research/studylib/qis.py`, a faithful port of Ledoit-Wolf QIS
  (Bernoulli 2022); for p ≤ 10 dimensions the estimator reduces smoothly
  toward linear shrinkage — implementation must pass synthetic
  self-calibration before use). Probabilities are then re-smoothed with
  the modified emission model (one extra E-step pass; transition matrix
  and means kept from EM to isolate the covariance effect).
- **Point-in-time discipline**: unchanged from the main study — monthly
  expanding refits, last-obs filtered probability applied forward.
- **Cohorts**: C10 (2016+), C20 (2006+), C36 (1990+) as defined in
  run_study.py. C36 is the primary cohort (most stress episodes).
- **Seeds**: 7 everywhere. Bootstrap B=1000, block=20.
- **Self-calibration prerequisite**: the QIS implementation must first pass
  synthetic tests — (a) on Gaussian data with known covariance, shrinkage
  reduces Frobenius loss vs sample covariance for p/n in {0.1, 0.5}; (b) on
  identity-covariance data it does not fabricate structure; (c) the shrunk
  matrix is always positive-definite. A cleaner that fails its own
  calibration disqualifies the test, not the hypothesis.

## What is NOT claimed

- No portfolio/covariance-cleaning claim (we run p≈5, not p≈500 — the
  regime the QIS literature targets). This tests ONLY whether shrinkage
  helps HMM regime detection at our dimensionality.
- No claim about other PRISM layers.

## Outputs

`research/results/qis_test.json` (all endpoints, all cohorts, all eras,
bootstrap p-values) + verdict paragraph in findings addendum. If promoted:
PRISM change in a separate PR referencing this protocol.
