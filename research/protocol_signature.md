# Signature Features for Regime Detection — Pre-Registered Test Protocol

**Status**: FROZEN before any test code (tag `signature-test-preregistered`).
Null hypothesis: **augmenting the HMM's input panel with path-signature
features does not improve point-in-time stress detection.** Fast failure is
a valid outcome. Scoreboard context: 2 promoted / 3 fast-failed so far.

## Scope adjustment (pre-registered, with reason)

The deep-research shortlist envisioned signatures of the 13-channel news
FACTOR stream. Only ~2 days of factor history exist (pipeline live since
2026-08-08), so that application is untestable and is EXPLICITLY DEFERRED
to the LASSO-duel window (~late Oct). What IS testable now, on 36 years of
market data, is the same mathematical object applied to the MARKET stream:
do depth-2 signature features of the rolling market path improve regime
detection? A null here does not preclude the factor-stream test later; a
promotion here would apply only to the market-stream feature set.

## Method (frozen)

- **Baseline**: `pit_regime_probs` exactly as in the QIS test — HMM(3
  states, full cov, seed 7) on the standard panel columns
  (NASDAQCOM_ret, slope_diff [, VIXCLS_diff, DCOILWTICO_ret]), monthly
  expanding refits, filtered last-obs stress probability.
- **Treatment**: identical HMM pipeline; the input panel is augmented with
  **three depth-2 signature features** — normalized Lévy areas over a
  rolling 22-business-day window of the cumulative paths:
  - A(equity, vol-proxy): equity return path vs |return| path (C10/C20/C36
    where VIXCLS exists, use VIXCLS_diff path; else |NASDAQCOM_ret|)
  - A(equity, slope): equity vs curve-slope path
  - A(vol-proxy, slope)
  where A(x,y)_t = 0.5 * Σ_{s in window} (x_s dy_s − y_s dx_s), z-scored
  by trailing 250d mean/sd (shifted 1 day; no same-day leakage). Lévy area
  is the depth-2 antisymmetric signature term — the lead-lag/rotation
  information raw daily levels cannot carry. Feature count kept at 3 to
  hold the HMM's parameterization sane (7-8 dims max) and because the
  antisymmetric terms are the only depth-2 content not already spanned by
  levels and squares.
- Everything else identical: cohorts C10/C20/C36 (C36 primary), PIT
  discipline, chronology labels, seeds 7, bootstrap B=1000 block=20.

## Decision gate (frozen — identical to the QIS gate)

Promote only if ALL of:
1. H1b AUROC improvement in ≥ 2/3 cohorts, no cohort degrading > 0.02;
2. pooled paired-score block-bootstrap p < 0.05 in the improving direction;
3. era-stability: improvement sign holds in ≥ 3/4 covered eras;
4. median detection lag not worse by > 2bd in any cohort.

## Self-calibration prerequisite

The Lévy-area implementation must first pass synthetic tests:
(a) on a planted rotation (x leads y by construction: y_t = x_{t-k}) the
area is systematically signed and its sign flips when the lead is
reversed; (b) on independent noise the area z-scores are ~N(0,1) with no
drift; (c) strict causality — feature at t must not change when future
data changes.

## Outputs

`research/results/signature_test.json` + addendum verdict. Promotion (if
any) via separate PRISM PR referencing this protocol.
