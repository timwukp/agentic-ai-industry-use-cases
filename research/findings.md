# PRISM Historical Validation Study — Findings & Interpretation

Companion to `report.md` (mechanical results). Protocol frozen at
`study-preregistered`; PRISM under test at `cd565a96`. This document
interprets; it does not re-judge. Every claim below cites the verdict
matrix.

## Executive summary

Across 10/20/30/36/40/50-year cohorts of real data, the study **supports
the regime layer as a descriptive instrument, partially supports it as a
real-time detector, and does not support the causality, impact-precision,
tail-calibration, factor-proxy, or economic-predictability claims** at the
pre-registered thresholds. In the user's framing: the regime layer is
一致/大體一致 with history; the causal and predictive layers are 分歧 —
and the honest headline is that **at daily frequency, with conservative
multiple-testing control, this system (like most published attempts)
cannot demonstrate exploitable predictability**. That is a scientific
result, not a failure of the study.

## What held up

1. **H1a — Regime detection (descriptive): 支持 in 4/5 cohorts.**
   Smoothed stress probability vs NBER recessions + crash windows:
   AUROC 0.85–0.91 in C40/C36/C20/C10, 0.67 in C50 (the sparse two-variable
   1970s panel drags it down). The HMM genuinely "sees" 2008, 2020, 2022.
2. **H1b — Real-time detection: 大體一致, not 支持.** Point-in-time
   AUROC clears 0.70 in 4/5 cohorts, but median detection lag exceeds the
   10-business-day bar. Per the pre-registered revision map: **regime
   outputs are relabeled "historical context", not real-time signals** —
   the agent's system prompt should say so (revision queued).

## What did not hold up

3. **H2 — Literature reproduction: 分歧.** The documented oil→10Y edge is
   invisible to our scan (q≈0.85 in its own documented era). Two candidate
   causes, pre-registered as a power audit: (a) the conservative
   `max(TE_p, Granger_p)` combination sacrifices too much power; (b) daily
   noise swamps the monthly-scale relations the literature documents. The
   VIX→equity edge does appear (q<0.03) in zirp/covid eras but not the
   moderation era — partial, so 分歧 under the frozen criterion.
4. **H3 — Impact functions: 分歧 on precision.** Signs are informative
   (VIX shocks → positive next-week equity response — consistent with the
   documented volatility-risk-premium rebound, an interesting confirmation)
   but the 95% credible bands include zero at h≤5: the framework's
   uncertainty is honest, and honestly too wide for point claims.
5. **H4 — VaR calibration: 分歧 (amber, clustered).** Violation rates
   1.4–1.6% vs the 1% target and Christoffersen rejects independence —
   violations cluster in stress episodes. **Triggered revision (from the
   frozen map): regime-conditional EVT** — fit GPD per HMM state.
6. **H5/H5b — Factor proxies: clean null / 分歧.** After BH-FDR, zero of
   63 factor→market edges survive; event-study hit rates are 0–33%. Two
   readings, both recorded: the CAMEO count/Goldstein proxy is too crude
   an instrument (it demonstrably misses 9/11-scale spikes at ±3bd/2σ), OR
   the Phase 2 premise itself overreaches. Per the revision map, the live
   factor layer is **demoted to descriptive context** until its own
   accumulating history (Haiku-scored, richer than CAMEO) can be tested
   directly — earliest ~60 trading days from 2026-08-08.
7. **H6 — Economic significance: 分歧 (no predictability).** Best naive
   strategy nets Sharpe 0.27 pre-SPA; Hansen SPA p≈0.70 across every
   cohort — indistinguishable from data snooping. The system's own
   CONFIRMED gate (0 confirmed in production) is therefore **vindicated as
   correctly conservative**: it refused to confirm edges that this study
   now shows are not economically real.
8. **H8 — Tail stability: 分歧.** ξ estimates flip sign across eras
   (thin-tailed in ZIRP, fat-tailed in covid-era) and the bipower jump
   stat does not discriminate crash windows (AUROC ≈ 0.5). The
   unconditional-tail assumption is rejected — same revision as H4:
   condition the tail model on regime.

## Protocol deviations (logged, §5-compatible)

- Gold: Stooq's CSV export sits behind a JS challenge → Twelve Data
  history (2007-12+) substituted; pre-2008 gold out of scope.
- GDELT: BigQuery CLI unavailable on the study machine → official reduced
  backfile (1979–2013-03) substituted; H5's factor-era coverage ends
  2013-03, so zirp-era factor claims are partial and covid-era absent.

## What this means for the product

- **Keep** (validated): regime ribbon as historical context; the honest
  uncertainty bands; the CONFIRMED gate's conservatism; EVT as a
  fat-tails *descriptor* (ξ>0 in crisis eras) rather than a calibrated
  VaR engine.
- **Revise** (triggered by the frozen map): regime-conditional EVT for
  H4/H8; power audit of the max-rule for H2; system-prompt language:
  regime = historical context, impact functions = wide-band estimates.
- **Demote** (per H5/H6): factor loadings stay hypothesis-grade
  descriptive context; no predictability claims anywhere in agent
  answers. The system prompt already enforces this — the study confirms
  it must stay.
- **Re-test later**: the live Haiku factor series reaches testable length
  (~60 trading days) around late October 2026; H5 can then be re-run
  against the real pipeline instead of the CAMEO proxy.

## The one-sentence answer to "準嗎?"

The mathematics is sound and the engineering honest — the regime lens
genuinely matches 50 years of crisis history descriptively — but at the
pre-registered bar, **neither the causal edges nor any trading-grade
predictability survives rigorous out-of-sample and data-snooping tests**,
and the system's own refusal to CONFIRM anything is exactly the behavior
this study validates.
