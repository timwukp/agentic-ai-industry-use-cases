# RFSV Rough-Volatility Forecaster vs EWMA — Pre-Registered Test Protocol

**Status**: FROZEN before any test code (tag `rfsv-test-preregistered`).
Null hypothesis: **RFSV does not improve on the incumbent EWMA(0.94)**
inside the vol-filtered EVT VaR pipeline. The incumbent is already
calibration-green (PR #51), so the bar for replacement is strict
superiority — a tie keeps the simpler EWMA. Fast failure is a valid,
expected-plausible outcome (deep-research report graded RFSV evidence
"medium: gains modest, asset-dependent").

## Honest data limitation (pre-registered, not discovered later)

The RFSV literature (Gatheral-Jaisson-Rosenbaum 2014) builds on intraday
realized variance. We have daily closes only. The pre-registered proxy:
5-day rolling realized volatility (annualization-free, same units as
returns) as the observable vol series. If RFSV's edge exists only with
intraday RV, this test CANNOT detect it — a null here reads "RFSV with
daily-data proxies does not beat EWMA", not "rough volatility is false".

## Method (frozen)

- **Incumbent**: `fit_vol_filtered_var` exactly as shipped — EWMA(0.94)
  sigma, GPD on standardized residuals, VaR = sigma_next x residual q99.
- **Challenger**: identical pipeline, sigma_next replaced by the RFSV
  forecast:
  - vol proxy v_t = 5-day rolling std of returns
  - Hurst H estimated per refit window from the q=2 structure function
    scaling of log v (regression of log m(2,Δ) on log Δ, Δ ∈ {1..20});
    H clamped to [0.02, 0.45]
  - forecast: discrete Nuzman-Poor kernel over the trailing 500 obs of
    log v: E[log v_{t+1}] = Σ w_i log v_{t-i},
    w_i ∝ 1 / ((i+1)^(H+1/2) · (i+1)), normalized; sigma_next = exp(E) ·
    bias correction exp(Var/2) with Var from window residuals
  - residual standardization and GPD identical to the incumbent
- **Back-test**: C36 (primary; most stress episodes), monthly refits of the
  residual quantile, daily sigma updates, both assets (NASDAQCOM_ret,
  DGS10_diff), point-in-time throughout. Seeds 7.

## Decision gate (frozen)

RFSV replaces EWMA only if ALL of:

1. Kupiec p > 0.05 AND Christoffersen CC p > 0.05 AND Basel green on
   BOTH assets (parity with the incumbent's current status);
2. |violation rate − 1%| strictly smaller than the incumbent's on both
   assets (better point calibration);
3. no clustering regression: max violations in any 22bd window ≤
   incumbent's.

Tie or partial → EWMA stays (simplicity wins at equal calibration).

## Outputs

`research/results/rfsv_test.json` + addendum verdict. If (unexpectedly)
promoted: PRISM change in a separate PR referencing this protocol.
