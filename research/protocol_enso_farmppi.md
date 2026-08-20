# FROZEN 2026-08-20 — tag `enso-farmppi-test-preregistered`

Gates below may no longer change; the one-shot discipline applies from this commit onward.

# Protocol: ENSO (ONI) → US farm-products producer prices

Candidate from the climate-macro deep research (2026-08-19, 23 claims
verified 3-vote; report: `~/Downloads/research-climate-macro-finance-2026-08-19.md`).
Literature basis: Brunner (REStat 2002) — 1σ ENSO surprise ≈ +3.5–4pp world
real commodity price inflation; Cashin et al. (JIE 2017) GVAR; Ubilava
(AJAE 2018) — out-of-sample predictability holds for tropical agricultural
commodities only.

## Null hypothesis

ONI carries no incremental information for US farm-products producer-price
inflation (FRED `WPU01`, monthly log-diff) beyond its own history: no
Granger-causal signal, no impulse response distinguishable from zero, no
out-of-sample edge over an AR(1) baseline.

## Endpoints

- **Primary (A)**: ONI → `WPU01` monthly log-diff, 1974-06 through the
  freeze date. Pre-freeze power check (2026-08-20, 200 seeds, real ONI as
  regressor, planted +3.5% cumulative-12m response, noise = real WPU01
  σ=0.0283): **power 1.00** on the combined gate; null false-positive 0.03.
- **EXCLUDED by power: US food CPI (`CPIUFDSL`)**. At the literature's
  US-specific effect (+0.14pp cumulative) the combined-gate power is 0.34
  — untestable at n=625 months. Recorded here so it is not re-proposed;
  may run as EXPLORATORY only, no confirmatory weight.

## Decision gates (all must pass; judged mechanically)

1. Granger p < 0.05, ONI → Δlog WPU01, maxlag 3 (production
   `prism.granger_pvalue`).
2. Local projection (production `prism.impact.local_projection`, horizons
   1–12, monthly panel): 95% band excludes 0 with positive sign at h ∈
   {6, 9, 12} (any).
3. Era stability: gates 1–2 direction agrees in both halves
   (1974–2000 / 2000–freeze).
4. Walk-forward out-of-sample (REVISED after joint power exploration,
   2026-08-20): production `prism.walk_forward` with monthly-tuned windows
   `train_years=17, test_months=48`, **horizon h=6**; gate = pooled
   n_test-weighted `edge_vs_ar1` > **0.0903** (threshold = empirical 95th
   percentile under the simulated null, frozen here as a number).
   Simulated power **0.817**, false positive **0.05** (120 seeds).

   Two designs were explored and REJECTED before settling on this one —
   recorded because the findings are durable:
   - The production `confirm()` fold-vote rule (≥70% of folds positive) is
     doubly broken at monthly frequency: with default daily windows every
     fold is skipped (guards `len(test)<30`, `len(train)<200`); with
     monthly-tuned windows it has power 0.61 at false-positive 0.17.
   - At the h=12 horizon NO rule reaches 80% power (best calibrated: 0.27)
     — a 12-month-cumulation effect gives only ~50 independent draws in 50
     years. OOS confirmation is only achievable at shorter horizons
     (h=6: 0.817; h=3: 0.792). Gates 1–2 keep h∈{6,9,12}; the OOS gate
     runs at h=6 where the data can actually speak.

## Known limitations (declared up front)

- The +3.5% target is a WORLD commodity magnitude applied to a US farm PPI —
  the real-data test decides whether the transmission survives that
  translation; a null reads "US farm PPI doesn't carry it", not "ENSO
  doesn't matter".
- ONI is a 3-month running mean published with delay — the point-in-time
  run must lag the regressor by one month beyond the season-center date
  (no vintage archive is used; this is a conservative lag, stated here).
- ~17 El Niño episodes in-sample; era splits leave ~8 each — episode-level
  (not month-level) effective n is small, which gate 3 partially absorbs.
- Monthly frequency: this candidate CANNOT enter the daily pipeline as-is;
  adoption would require a monthly branch or regime-conditioning use.

## Fast-failure clause

Any gate fails → candidate archived in `research/rejected_candidates.md`
(post-freeze failures also get a findings_addendum entry), no variant
without a new pre-registration. One-shot re-test discipline applies.

## Data & reproduction

- ONI: NOAA CPC `oni.ascii.txt` (season-center month convention).
- `WPU01`, `CPIUFDSL`: FRED API (key at SSM `/agentic/finance/fred-api-key`).
- Power checks: `research/run_enso_power_check.py` (gates 1–2) and
  `research/run_enso_gate4_power.py` (gate 4 design space) → results at
  `research/results/enso_power_check.json` and
  `research/results/enso_gate4_power.json` (seeds fixed, reproducible).

## Freeze ceremony (EXECUTED 2026-08-20)

All four gates carry simulated power (1.00 / 1.00 / direction-only /
0.817) with controlled false positives; the dry-run was completed before
this freeze. The real-data runner is written only after this commit's
tag, per the lifecycle.
