# DRAFT — not yet frozen, confers no confirmatory status

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
4. Walk-forward out-of-sample: sign hit-rate edge over AR(1) baseline
   (production `prism.walk_forward`), positive edge required.
   **Power for this gate is NOT yet simulated** — must be added to the
   dry-run before the freeze tag, per the joint-constraints rule.

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
- Power check: `research/run_enso_power_check.py` → results committed at
  `research/results/enso_power_check.json` (seeds fixed, reproducible).

## Freeze ceremony (pending)

Merge of this DRAFT = human acknowledgment. Freezing = follow-up commit
renaming to `protocol_enso_farmppi.md` + tag `enso-farmppi-test-preregistered`,
only after gate-4 power is added to the dry-run and passes.
