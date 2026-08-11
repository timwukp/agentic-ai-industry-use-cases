# Breitung-Candelon Frequency-Domain Causality — Pre-Registered Test Protocol

**Status**: FROZEN at tag `bcfreq-test-preregistered`, before any test code.

**Null hypothesis**: frequency-band decomposition does NOT recover the
literature-documented oil→10Y causality that PRISM's all-frequency daily
scan misses (H2 分歧), and does not add band-localized edges beyond what
the incumbent already finds. Fast failure is a valid outcome.

**Deficiency targeted**: (c) — the validation study's H2 found the
documented oil→yields edge invisible at daily frequency (q≈0.85 in its own
documented era), while the monthly-aggregation probe came an order of
magnitude closer (p≈0.12). Diagnosis: a monthly-scale relation drowned by
daily noise. Breitung-Candelon (2006, J. Econometrics) is the classical
instrument for exactly this: a linear-restriction Wald/F test of Granger
non-causality AT a chosen frequency ω within a VAR, whose own empirical
demonstration (yield spread → output) showed causality concentrated in
business-cycle bands. Corroboration on our exact domain: Gronwald (2009)
found frequency-specific oil→macro causality.

**Candidate and counter-evidence (same breath)**: BC inherits VAR
assumptions (linearity, stationarity, lag sufficiency); band tests on
short samples suffer size distortion; and testing many bands multiplies
comparisons — the design answers with the same BH-FDR discipline the
incumbent scan uses, applied across the full band×pair grid. If the edge
appears only without multiplicity control, the verdict is 分歧.

## Method (frozen)

- **Data**: C40 cohort (1986+, oil exists), daily returns/diffs as in the
  main study; VAR estimated on the pair (DCOILWTICO_ret, DGS10_diff), lag
  order by BIC capped at 22 (one trading month).
- **Bands (fixed a priori, ω in radians, daily sampling)**: period >1y
  (ω<0.025), quarterly-to-yearly (0.025-0.10), monthly-to-quarterly
  (0.10-0.30), weekly-to-monthly (0.30-1.25), sub-weekly (>1.25). BC
  statistic evaluated at 3 grid points per band; band p = max over its
  grid points (a band "shows causality" only if all its points do —
  conservative within band).
- **Grid and multiplicity**: pairs = {oil→DGS10, DGS10→oil (direction
  control), VIX→NASDAQ (positive control — the confirmed edge should
  appear SOMEWHERE), NASDAQ→VIX} × 5 bands = 20 hypotheses, BH q<0.10
  across the full grid (same threshold as the incumbent scan).
- **Era stability**: the headline claim (oil→DGS10 in low-frequency bands)
  must hold in ≥2 of the 3 eras C40 covers, same sign of the BC statistic.
- Seeds 7; statsmodels VAR; the BC restriction implemented per the
  original paper (two linear restrictions on lag polynomial coefficients
  at frequency ω, F-test).

## Decision gate (frozen)

The frequency tier is promoted into PRISM's nightly causality scan only if
ALL of:
1. **Recovery**: oil→DGS10 survives BH (q<0.10) in at least one
   pre-registered LOW-frequency band (period ≥ 1 month) on the full C40
   sample;
2. **Specificity**: the same edge does NOT appear in the sub-weekly band
   (if it does, the finding is not frequency-localized and daily-scan
   failure is unexplained — 分歧 on mechanism);
3. **Positive control**: VIX→NASDAQ appears in at least one band (an
   instrument that can't see the confirmed edge can't be trusted for new
   ones);
4. **Direction control**: DGS10→oil does NOT survive BH in the same
   low-frequency bands (documented direction is oil→yields);
5. **Era stability**: condition 1's band holds in ≥2/3 eras.

Fast failure otherwise; the honest null reads "the oil→yields miss is not
(only) a frequency-aggregation artifact detectable by linear band tests."

## Self-calibration prerequisites (before real data)

1. **Planted band-limited causality**: y driven by a band-pass-filtered
   lag of x (low-frequency only) — BC must flag the correct band and stay
   silent in the others.
2. **All-frequency causality**: y = βx_{t-1} + ε — BC must flag ALL bands
   (sanity: the statistic reduces toward standard Granger).
3. **Pure-noise silence**: independent series — zero BH survivors across
   the 20-cell grid over ≥8 seeds (FDR contract).
4. **Strict causality is inherited from VAR estimation on past data only**
   (full-sample estimation is acceptable HERE because the claim is
   descriptive causality structure, not real-time detection — the same
   epistemic class as the incumbent H2 scan; stated to prevent
   over-claiming).

## Outputs

`research/results/bcfreq_test.json` + addendum verdict. If promoted: a
monthly "frequency tier" section in the nightly PRISM causality payload,
separate PR.
