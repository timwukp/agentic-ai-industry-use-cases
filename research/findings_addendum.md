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

## RFSV rough-volatility challenger vs EWMA — **FAST FAILURE, EWMA stays**

Pre-registered test (`protocol_rfsv.md`, tag `rfsv-test-preregistered`).
Deep-research shortlist item #4. Same C36 point-in-time protocol as PR #51;
arms differ only in sigma_next (EWMA 0.94 vs RFSV Nuzman-Poor kernel with
monthly-re-estimated Hurst on a 5-day realized-vol proxy):

| Asset | arm | rate (target 1%) | Kupiec p | CC p | Basel | max cluster |
|---|---|---|---|---|---|---|
| NASDAQ | EWMA | 1.041% | 0.69 | 0.61 | green | 4 |
| NASDAQ | RFSV | 1.020% | 0.85 | **0.20** | green | 4 |
| DGS10 | EWMA | 0.997% | 0.98 | 0.99 | green | 3 |
| DGS10 | RFSV | 1.032% | 0.77 | **0.009 (reject)** | green | 3 |

**Gate verdict (frozen criteria)**: condition 1 fails — RFSV's DGS10
conditional-coverage test REJECTS (p=0.009: violations show serial
dependence), losing parity with the incumbent. Condition 2 splits (NASDAQ
point-rate marginally better, DGS10 worse). **EWMA stays.**

Estimated Hurst on the daily proxy: persistently low (rough), consistent
with the RFSV literature — the roughness stylized fact reproduces, but at
daily granularity the kernel forecast adds no calibration value over EWMA
and degrades independence on rates. Per the pre-registered limitation:
this null reads "RFSV with daily-data proxies does not beat EWMA", not
"rough volatility is false" — a re-test would require intraday realized
variance, which our data lake does not carry.

Scoreboard: pre-registered tests now 2 promoted / 3 fast-failed
(regime-EVT ❌, Fisher ✅, vol-EVT ✅, QIS ❌, RFSV ❌).

## Signature (Lévy-area) features for regime detection — **FAST FAILURE**

Pre-registered test (`protocol_signature.md`, tag
`signature-test-preregistered`). Deep-research shortlist item #3, market-
stream variant (factor-stream variant deferred — 2 days of history).
Baseline HMM panel vs panel + 3 depth-2 Lévy-area features, identical
pipeline otherwise:

| Cohort | baseline AUROC | +signature | Δ | median lag b→s |
|---|---|---|---|---|
| C10 | 0.7951 | 0.7317 | **−0.063** | 16.5 → 9.5 |
| C20 | 0.7327 | 0.7230 | −0.010 | 13.0 → 6.0 |
| C36 (primary) | 0.7130 | 0.6091 | **−0.104** | 12.0 → 8.5 |

**Gate verdict**: condition 1 fails outright (0/3 cohorts improve; C36
degrades 5x beyond the 0.02 tolerance). **Signature features do not enter
PRISM.** The likely mechanism (post-hoc, labeled): tripling the emission
dimensionality (4→7) with noisy rotation features degrades the Gaussian
mixture's separation — the HMM spends its states explaining signature
noise instead of stress.

**Exploratory observation (NOT a gated claim)**: median detection lag
improved consistently and substantially (e.g. 13.0→6.0bd on C20) at the
cost of ranking quality — the signature arm reacts faster but less
reliably. This trade-off was not a pre-registered endpoint and is recorded
only as a hypothesis for a possible future protocol (e.g. signatures as a
separate fast-alarm channel rather than HMM inputs), which would need its
own pre-registration.

Scoreboard: 2 promoted / 4 fast-failed across 6 pre-registered tests.

## BOCPD/CUSUM fast-alarm channel — **FAST FAILURE per frozen gate, with
protocol-design findings that justify (but do not auto-license) a v2**

Pre-registered test (`protocol_bocpd.md`, tag `bocpd-test-preregistered`;
converged independently from the skill-trial draft and the classical-math
survey). Three arms at training-matched false-alarm thresholds, PIT, OOS =
last 60% of each cohort:

| Cohort | arm | detected | median lag (bd) | FA/250bd |
|---|---|---|---|---|
| C10 | incumbent | 0/3 | — | 0.000 |
| C10 | bocpd | 0/3 | — | 0.512 |
| C10 | cusum | 3/3 | 1.0 | **11.5** |
| C20 | incumbent | 1/6 | 20.0 | 1.056 |
| C20 | bocpd | 2/6 | 8.5 | 1.056 |
| C20 | cusum | 4/6 | 9.5 | **12.1** |
| C36 (primary) | incumbent | 4/10 | 52.5 | 1.341 |
| C36 | bocpd | **5/10** | **8.0** | **1.118** |
| C36 | cusum | 8/10 | 5.0 | **11.8** |

**Gate verdict (mechanical):**
- **CUSUM: fast failure, decisive.** Training-matched thresholds did not
  hold out-of-sample: OOS false alarms ran ~10x the budget in every cohort
  (11.5-12.1 vs 0.8-2.0). Its spectacular lag numbers are exactly the
  ARL≈7-style mirage finding [1] of the survey warned about — the
  co-primary FA endpoint exists for this.
- **BOCPD: fast failure on condition 2** — C10 FA 0.512 vs incumbent 0.000
  ("≤ in EVERY cohort" fails) — and condition 3 unevaluable (see defects).

**Two protocol-design defects surfaced in execution (recorded, not
patched post hoc):**
1. **Degenerate zero comparison**: on C10 the incumbent never fired at all
   (0 detections → trivially 0 false alarms). A "FA ≤ incumbent" gate
   against a never-firing incumbent can only be met by another
   never-firing detector — the gate compares against silence, not skill.
2. **Bootstrap/instrument mismatch**: the frozen significance test (block
   bootstrap, n≥100) cannot run on 3-10 paired episode differences; a
   sign/permutation test was the right instrument. Discovered at judging
   time; per discipline, NOT swapped in after the fact.

**Honest observations (non-gated):** on the PRIMARY cohort (C36, 10 stress
episodes) robust BOCPD strictly dominated the incumbent on all three
endpoints simultaneously — more episodes detected (5 vs 4), 6.5x faster
median detection (8.0 vs 52.5bd), AND fewer false alarms (1.118 vs 1.341).
Same direction on C20. The Student-t robustification also did its job:
BOCPD held its FA budget OOS where CUSUM blew through it.

**Disposition**: fast failure recorded; nothing enters PRISM. A v2 protocol
(non-degenerate FA gate — budget floor instead of comparison-to-zero;
sign/permutation small-sample test; identical arms otherwise) is
scientifically justified by the defects above — but re-registering after
seeing results carries gate-shopping risk, so v2 requires explicit user
sign-off, and its verdict must report v1's failure alongside any v2 pass.

Scoreboard: 2 promoted / 5 fast-failed across 7 pre-registered tests.

## BOCPD v2 (user-approved gate-defect fix) — **FAILS on significance;
candidate TERMINALLY CLOSED per the one-shot clause**

v2 protocol (`protocol_bocpd_v2.md`, tag `bocpd-v2-preregistered`,
user-approved 2026-08-11 after gate-shopping disclosure) fixed exactly the
two recorded v1 defects: absolute FA budget (≤2.0/250bd) replacing the
degenerate vs-silent-incumbent comparison, and an exact paired
sign-permutation test replacing the infeasible bootstrap. Arms, data,
thresholds identical to v1 (measurements reused; deterministic seed 7).

**v2 gate results (v1 failure presented alongside, as required):**

| Condition | v1 | v2 |
|---|---|---|
| 1. Lag ≥3bd better in ≥2/3 cohorts, none worse | pass (C20 20→8.5, C36 52.5→8.0, C10 tie) | pass (same data) |
| 2. False alarms | FAIL (degenerate C10 comparison) | **pass** — BOCPD ≤2.0/250bd in all cohorts (0.512/1.056/1.118); CUSUM fails (11.5-12.1) |
| 3. Significance | unevaluable (bootstrap n≥100) | **FAIL — exact sign-permutation p = 0.172** (19 pooled episodes, mean lag gain 17.3bd) |
| 5. Missed-detection guardrail | pass | pass (BOCPD ≥ incumbent everywhere) |

**Verdict: fast failure.** The lag improvement is large in point estimate
(17.3bd pooled mean) but with only 19 stress episodes in 40 years of OOS
data and high variance across them, the exact test cannot exclude chance
at the frozen 5% level (p=0.17). The evidence is suggestive, not
sufficient — and suggestive does not clear a pre-registered gate.

**Per the one-shot clause: no v3.** The candidate closes with an honest
epitaph: robust BOCPD dominated the incumbent on the primary cohort's
point estimates and held its false-alarm budget where CUSUM exploded, but
stress episodes are too rare for daily-close data to certify the speed
gain at journal-grade significance. Re-opening requires a categorically
different setting (e.g. the news-factor stream as the alarm input once
its history matures — listed in conditional_candidates.md), not a re-roll
of this design.

Scoreboard: 2 promoted / 6 fast-failed across 8 pre-registered tests.

## Breitung-Candelon frequency-domain causality — **FAST FAILURE, with two
recorded protocol defects (candidate's core question left unanswered)**

Pre-registered test (`protocol_bc_freq.md`, tag `bcfreq-test-preregistered`).
Last untested survey candidate, targeting deficiency (c): the oil→10Y edge
invisible to the all-frequency daily scan.

**Result**: zero BH survivors across the grid; oil→DGS10 q=0.87 in every
band. Gate conditions 1 and 3 fail → fast failure.

**Two protocol defects discovered in execution (recorded, not patched):**
1. **Positive control unrunnable on the frozen cohort.** The protocol froze
   C40 (1986+, oil exists) AND named VIX→NASDAQ as the positive control —
   but C40's panel does not carry VIXCLS (it enters at C36/1990). The
   control silently dropped out of the grid; an instrument whose positive
   control never ran cannot certify a null. Same failure class as BOCPD
   v1's degenerate comparison: a frozen design whose parts are mutually
   inconsistent.
2. **BIC lag selection collapsed the frequency resolution.** The protocol
   delegated VAR lag order to BIC (capped 22); BIC chose **lag 1** on the
   real pair. With p=1 the BC restrictions [a₁cos(ω)=0, a₁sin(ω)=0] reduce
   to a₁=0 at EVERY frequency — all five bands returned literally identical
   p-values (0.8207). The band decomposition never happened; the test run
   was an ordinary Granger test wearing five costumes. The instrument
   itself is sound (calibration gates passed with forced p=22); the
   protocol's lag rule defeated it.

**Honest epistemic status**: the frequency-localization hypothesis for the
oil→yields miss remains **untested in any meaningful sense** — what failed
is this protocol's design. A v2 (minimum lag floor ≥ 22 for band
resolution; positive control on C36 where VIX exists) would be
scientifically justified by the defects, but per the BOCPD precedent,
**v2 requires explicit user sign-off** (gate-shopping discipline), and the
one-shot-per-defect-fix rule applies.

Scoreboard: 2 promoted / 7 fast-failed across 9 pre-registered tests
(this one failing on protocol design rather than candidate merit).

## BC v2 (user-approved defect fix) — **FAST FAILURE; instrument fails its
own positive control on real data; candidate TERMINALLY CLOSED**

Pre-registered one-shot re-test (`protocol_bc_freq_v2.md`, tag
`bcfreq-v2-test-preregistered`; user approval "批准 BC v2" 2026-08-11).
v2 fixed exactly the two recorded v1 defects: VAR lag FIXED at 22 (BIC
rule removed entirely — dry-run bound taken to its strongest form) and
each pair assigned to a cohort that contains it (oil pairs on C40, VIX
pairs on C36; runner aborts unless the grid is exactly 20 non-NaN cells).
Protocol dry-run executed before freezing (variable presence, era sample
sizes, restriction-matrix rank at all 15 grid points). Calibration suite
extended to exercise the PRODUCTION path (v1's blind spot: tests passed
`p=22` explicitly while production used BIC) plus a permanent
band-distinguishability regression test; 5/5 green before real data.

**Result — zero BH survivors across the full 20-cell grid:**

| pair (cohort) | best band | p | q |
|---|---|---|---|
| oil→DGS10 (C40) | quarterly_1y | 0.224 | 0.50 |
| DGS10→oil (C40) | monthly_quarterly | 0.049 | 0.50 |
| **VIX→NASDAQ (C36, positive control)** | sub_weekly | 0.224 | 0.50 |
| NASDAQ→VIX (C36) | over_1y | 0.063 | 0.50 |

**Gate ruling (mechanical)**: condition 1 (recovery) FAILS — oil→DGS10
p=0.22–0.99 in every low-frequency band; condition 3 (positive control)
FAILS — the instrument cannot see the known VIX→NASDAQ edge in ANY band.
Per the frozen protocol's own wording, control failure reads "instrument
invalid on real data", and under the one-shot clause the candidate is
**terminally closed — no v3**.

**Post-hoc interpretation (labeled as such)**: with the lag rule removed,
the honest price declared up front came due — a VAR(22) pair equation
spends 45 parameters, and the band p = max over 3 grid points is doubly
conservative; the per-cell power at daily noise levels is evidently too
low even for a real edge. The two design goals ("enough lags for frequency
resolution" and "enough power per cell") appear jointly unsatisfiable on
daily data with this test family — that conclusion, not any single defect,
is the durable finding. The monthly-frequency probe (Revision 2) remains
the only promising route to the oil→yields question and stays on the
to-do list as its own candidate.

Scoreboard: **2 promoted / 8 fast-failed across 10 pre-registered tests.**

## Revision 3: system prompt — shipped

Regime = validated historical lens (AUROC 0.85–0.91 cited) with explicit
lag caveat; impact functions presented as bands; crash-timing questions
get the fragility-vs-trigger framing with the SPA finding cited; per-regime
tails offered as descriptive context only.

## H3 root cause found — calibration defect in the incumbent, not a missing method (2026-08-12)

The theory scout's first autonomous cycle (2026-08-11, SLP rejection) escalated
a lead while rejecting its candidate: the incumbent `_nig_posterior` prior
looked mis-scaled. A planted-truth audit through the production entry point
(`local_projection`, 50 seeds, n=2600, sigma=1%, beta=20bp) confirmed it:

| h | band half-width / frequentist oracle | coverage @ nominal 95% |
|---|---|---|
| 1 | **2.96x** | 100% |
| 5 | 1.61x | 100% |
| 20 | 1.19x | 100% |

Mechanism: the absolute-scale prior (a0=b0=1) contributed **88.7% of b_post**
at h=1 — ten years of daily-return RSS is only ~0.25, so the prior swamped the
data, worst exactly where H3 said the bands were widest (h<=5). The original
unit-scale synthetic test could not see this: at beta=0.5, sigma=0.5 the prior
is negligible — the instrument was calibrated at a scale the pipeline never
runs.

Fix (same audit, re-run post-fix): scale-matched weak prior
`a0=1e-3, b0=a0*var(y)` brings bands within 1–2% of the oracle at every
horizon with coverage at nominal (92–96%). Mutation-checked regression test
added at daily-return scale (`test_credible_bands_calibrated_at_daily_return_scale`);
the old prior fails it, the fix passes.

**Status of H3**: the "bands too wide at h<=5" deficiency is root-caused as an
instrument defect and repaired — it is no longer an open deficiency for future
method searches. Any residual H3-flavored question after the next nightly
refit should be re-diagnosed from scratch, not inherited.

### Amendment (2026-08-12, post-review): deploy reality + instrument-version discontinuity

An independent code review of the fix corrected three claims in the section
above and surfaced two regressions the fix itself introduced (both repaired
in the follow-up commit this amendment ships with):

1. **"After the next nightly refit" was wrong**: the nightly quant batch is a
   manually-deployed Docker Lambda (`finance-quant-batch`, CDK image asset).
   Merging the fix does NOT deploy it — bands narrow only after the finance
   stack is redeployed. Until then the nightly output still carries the old
   ~3x-inflated bands.
2. **The old b0=1.0 was silently doubling as a degenerate-data floor.** With
   the scale-matched prior, a constant/near-constant response (stale or
   forward-filled series) produced near-zero-width bands presented as
   certainty, and `prob_positive_20d` could saturate to exactly 0/1. Repaired:
   degenerate responses and near-empty effective samples now take the NaN
   refusal path.
3. **`regime_conditional` counted raw rows, not effective sample** — a regime
   active 5% of days got bands ~sqrt(20)x too narrow (latent: no production
   caller). Repaired with textbook row-level WLS + n_eff = (Σw)²/Σw²;
   mutation-checked tests added for both repairs.

**Instrument-version discontinuity**: the sealed C10–C40 results and
report.md band-gate verdicts (`band95_excludes_zero*`) were generated under
the pre-2026-08-12 prior. Re-runs under the fixed prior will flip some 分歧
verdicts purely from the instrument change — such re-runs are new evidence
under a corrected instrument, not reproductions of the sealed study.
`run_study.py`'s docstring previously claimed "PRISM is imported frozen";
it is imported live and the docstring now says so.

## ENSO (ONI) → US farm-products PPI — **POST-FREEZE FAST FAIL, 0/4 gates (2026-08-20)**

Eleventh pre-registered test (protocol frozen at tag
`enso-farmppi-test-preregistered`; the first candidate sourced from a
deep-research survey of climate-macro transmission). Real-data verdict on
1974-06..2026-06 (n=625 months, point-in-time ONI lag applied):

| Gate | Frozen requirement | Measured | Verdict |
|---|---|---|---|
| 1 Granger | p < 0.05 (maxlag 3) | p = 0.377 | ✗ |
| 2 LP bands | 95% band > 0 at any h∈{6,9,12} | betas −0.024..−0.044, all bands straddle 0 | ✗ |
| 3 Era stability | positive direction, both halves | h1 mixed ~0; h2 all negative | ✗ |
| 4 Walk-forward | pooled edge > 0.0903 (h=6) | 0.0436 (8 folds) | ✗ |

The instrument was power-checked at 1.00 for the literature's
world-commodity magnitude (+3.5% cum-12m/1σ), so this is a genuine
rejection at our data's scale, not a power artifact — per the frozen
limitation, it reads "US farm-products PPI does not carry the
world-commodity ENSO effect", not "ENSO does not matter". The excluded
food-CPI endpoint (power 0.34) stays excluded. No v2 is contemplated:
no protocol defect was recorded; the candidate is closed.

Scoreboard after this test: **2 promoted / 9 fast-failed across 11
pre-registered tests.**

## Correction (2026-08-20): regime AUROC range misquote

The widely quoted "AUROC 0.85–0.91" for the H1a regime layer does not
match the sealed C*.json artifacts, which read 0.8396 / 0.8465 / 0.8537 /
0.8589 for C36/C10/C20/C40 (0.67 for C50). Correct range: **0.84–0.86**.
The misquote originated as a transcription in findings.md (now corrected
in place with a dated note) and propagated to the READMEs, the
business-flow docs, and the finance harness system prompt — all corrected
in the same commit; no artifact changed. Caught by the paper's
claims-verification pass: a number in prose is unchecked until it is
re-derived from data.


## Agent-disclosure evaluation — TERMINAL CLOSURE, measurement unexecutable under this design (2026-08-22)

v2 (frozen at `agent-disclosure-v2-preregistered` after user sign-off:
PR #84 merge + explicit 「凍結 v2」) ran once. The pre-battery smoke
check returned an empty reply and aborted before any battery trial:
**defect #3** — the runner parsed the binary eventstream correctly but
expected a Converse-style `{"contentBlockDelta": {...}}` payload
wrapper, while the data plane types events in the message HEADER and
ships the bare delta (`{"contentBlockIndex":0,"delta":{"text":...}}`).
Post-abort forensics (one unscored diagnostic prompt, raw bytes in
`results/agent_disclosure_v2_diagnostic.txt`) show the harness itself
replied — the instrument was blind, not the target silent.

Defect chain: (1) IAM auth vs Cognito Bearer; (2) SSE reader vs binary
eventstream; (3) header-typed bare delta vs Converse wrapper. Zero
genuine replies were ever scored; the rubric was never contaminated.
Per the frozen terminal one-shot clause the experiment is CLOSED; any
future attempt is a new experiment with a fresh pre-registration. The
paper reports the defect chain as the finding: the fail-safes (smoke
check, one-shot discipline) bound the operator even with the fix one
line away.
