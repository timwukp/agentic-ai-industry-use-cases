# Robust BOCPD Fast-Alarm Channel for Stress Onset — Pre-Registered Test Protocol

**Status**: FROZEN at tag `bocpd-test-preregistered`, before any test code.
Drafted by an independent agent during the theory-to-production skill trial;
cross-validated by the independent classical-math deep-research survey
(`deep_research_classical_math.json`), whose adversarially-verified findings
converged on the same candidate and the same fairness trap (matched ARL).
Two additions from that survey are incorporated below: a CUSUM comparison arm
and the production-grade ARL floor. Moving any threshold after the tag
invalidates the confirmatory claim.

**Null hypothesis**: a robust Bayesian Online Changepoint Detection (BOCPD)
fast-alarm channel does NOT improve real-time stress-onset detection over the
incumbent point-in-time HMM stress probability. Fast failure is a valid,
expected-plausible outcome (standard BOCPD's documented false-discovery rate
on real-world data exceeds 90% without robustification — Knoblauch, Jewson &
Damoulas 2018).

## Deficiency targeted (named wound, from the frozen study)

**H1b — real-time detection lag.** The incumbent's PIT AUROC clears 0.70 in
4/5 cohorts but the **median detection lag exceeds the 10-business-day bar**
(`research/findings.md`, H1b), which is why regime outputs were demoted to
"historical context". Two prior facts motivate a *separate alarm channel*
rather than another HMM-input tweak:

1. The signature test (`protocol_signature.md`, fast-failed) recorded an
   exploratory, non-gated observation: lag improved consistently
   (13.0→6.0bd on C20) whenever reactivity was added — but at the cost of
   ranking quality when forced *through* the HMM. Hypothesis: speed and
   ranking should be **separate instruments**, not one compromised one.
2. HMM filtered probabilities are structurally slow: state inference must
   accumulate likelihood before P(stress) crosses 0.5. BOCPD's run-length
   posterior is designed for exactly this — online, exact, causal detection
   of "the current segment just ended".

This candidate does NOT touch the validated descriptive ribbon (H1a,
AUROC 0.85–0.91) and does not claim predictability (H6's SPA null stands).
The deliverable, if promoted, is an honest "regime-shift alarm fired N days
ago" line in the model payload — a detection claim, never a forecast claim.

## Candidate and counter-evidence (in the same breath)

- **Method**: BOCPD (Adams & MacKay 2007) over the standardized panel
  residuals, **Student-t emission model** (robust variant), constant hazard
  H=1/250 (≈1 expected changepoint/year, matching chronology's era/crash
  density; sensitivity at 1/125 and 1/500 reported, primary frozen at 1/250).
- **Counter-evidence baked into the design**: plain Gaussian BOCPD declares
  changepoints on every fat-tail outlier — >90% false discovery on real
  data (Knoblauch et al. 2018; Altamirano et al. 2023; Wendelberger et al.
  2021 all treat this as the known failure mode). Daily financial returns
  are exactly the adversarial case (heavy tails + volatility clustering, the
  repo's own H8 finding: ξ>0 in crisis eras). Therefore the false-alarm
  endpoint below is CO-PRIMARY: **a lag win with more false alarms is a
  fast failure**, not a partial success. A Gaussian-emission arm is run as
  a falsification control — if it does NOT overfire on our data, the
  literature's warning didn't transfer and the report must say so.

## Incumbent (named exactly)

`research/studylib/pit.py::pit_regime_probs` — expanding-window monthly
refits of `tools/finance/quant_batch/prism/regime.py::fit_regimes`
(GaussianHMM, 3 states, seed 7), filtered last-observation P(stress),
alarm = first P(stress) > 0.5. Exactly the arm the study scored for H1b.
The incumbent's H1b numbers are already on file (`research/results/*.json`);
they are re-generated in-run, not copied, so both arms share code paths.

The incumbent is deployed and descriptively validated, so the bar is
**strict superiority on lag at no false-alarm cost — a tie keeps the
incumbent alone**.

## Method (to be frozen)

- **Arms differ only in the alarm source.** Panel construction, cohorts,
  chronology labels, PIT discipline (info ≤ t only), seeds (7) identical.
- BOCPD arm: at each date t, run-length posterior updated causally on the
  standardized panel (same columns the HMM sees, z-scored on trailing
  training window only). Alarm at t iff P(run length ≤ 5) > τ.
- **CUSUM arm (added from the classical-math survey)**: two-sided CUSUM on
  the same standardized equity-return series (the classical minimal
  instrument; Moustakides-optimal under Lorden's criterion), threshold
  h matched to the same training false-alarm budget. Runs under the
  identical gate — if the 1954 method matches robust BOCPD, simplicity
  wins per the skill's tie rule.
- **Production ARL floor (survey finding [1])**: the matched false-alarm
  budget must correspond to an average run length to false alarm of
  ≥ 250 trading days. Literature lag headlines bought at ARL≈7 are
  explicitly not reproducible under this design.
- **Threshold matching (the fairness core)**: τ is chosen ON THE TRAINING
  SEGMENT ONLY of each cohort so the BOCPD arm's training false-alarm rate
  equals the incumbent's. Lag is then compared out-of-sample at matched
  false-alarm budget — comparing lag at unequal alarm rates is the classic
  way to fake a detector win.
- Cohorts C10 / C20 / C36 (C36 primary), stress windows = NBER ∪ crash
  windows from `research/chronology.py`, unchanged.
- Bootstrap: stationary block bootstrap, B=1000, block=20, seed 7, on the
  paired per-episode detection-lag differences.

## Decision gate (numeric, to be frozen before any code)

Promote the fast-alarm channel only if ALL of:

1. **Lag**: median detection lag (stress-window start → first alarm)
   improves by ≥ 3 business days vs incumbent in ≥ 2/3 cohorts, and no
   cohort worsens.
2. **False alarms (co-primary)**: out-of-sample false-alarm rate (alarms
   outside stress windows, per 250bd) ≤ incumbent's in EVERY cohort at the
   matched-τ operating point.
3. **Significance**: block-bootstrap p < 0.05 on the pooled paired lag
   improvement (per-cohort p reported; pooled via Stouffer).
4. **Era stability**: improvement sign holds in ≥ 3/4 covered eras
   (`chronology.ERAS`).
5. **Missed-detection guardrail**: episodes detected ≥ incumbent's count
   per cohort (an alarm channel that gets faster by skipping episodes
   fails).

Anything less = fast failure, documented in the findings addendum,
scoreboard updated. **If the Student-t arm fails but the lag direction is
consistently right, the verdict is fast-fail (absolute) for this design —
a variant (e.g. beta-divergence BOCPD) requires a NEW pre-registration,
not a post-hoc patch.**

## Known limitations (declared up front)

1. Hazard rate is a prior choice; primary value frozen, two sensitivities
   reported descriptively. A null could read "wrong hazard", but re-tests
   on hazard alone are not licensed without a new protocol.
2. BOCPD detects distributional breaks, not "stress" semantically; a break
   into a *calm* regime also alarms. The false-alarm endpoint prices this
   in — direction labeling (via sign of post-break mean shift) is reported
   descriptively, not gated.
3. Daily closes only; volatility clustering means many "changepoints" are
   vol bursts. The Student-t emission and matched-false-alarm design
   address this; if they don't suffice, the honest null reads "BOCPD on
   daily closes fails our false-alarm bar", not "changepoint theory false".
4. Chronology stress windows are the same ground truth the incumbent was
   scored on — comparative claims are fair; absolute lag numbers inherit
   the chronology's window-start conventions.

## Fast-failure clause

On failure: results JSON + addendum entry + scoreboard update; the channel
does not enter PRISM; the payload and system prompt are untouched. Re-test
conditions that would justify a new protocol: (a) intraday data enters the
lake (breaks limitation 3), (b) a robust-BOCPD variant with materially
different loss (beta-divergence / score-matching) is chosen, or (c) the
factor stream reaches testable length and the alarm is re-scoped to news
factors.

## Self-calibration prerequisites (Phase 3, run before the back-test)

The BOCPD implementation must pass ALL of, on synthetic data with planted
ground truth, before touching real cohorts:

1. **Planted mean-shift**: on Gaussian segments with known changepoints,
   ≥95% of planted breaks detected within 5 steps at τ; detection dates
   within known tolerance of truth.
2. **Pure-noise silence**: on i.i.d. noise with NO breaks, false-alarm rate
   at τ consistent with the run's matched budget (binomial CI covers it).
3. **Heavy-tail robustness (the decisive one)**: on Student-t(3) noise with
   NO breaks, the Student-t emission arm must NOT alarm above budget, and
   the Gaussian-emission control arm is EXPECTED to overfire — confirming
   the instrument reproduces the literature's failure mode before we trust
   its cure.
4. **Planted vol-burst distractor**: GARCH-style vol clustering with no
   mean break — alarms above budget = instrument fails (this is the daily-
   returns trap in miniature).
5. **Strict causality mutation test**: change FUTURE observations; assert
   all past run-length posteriors and alarm dates are bit-identical.
6. **Threshold-matching harness check**: verify the τ-matching procedure on
   synthetic incumbent/challenger pairs with known operating points.

An instrument failing any of these disqualifies the TEST, not the
hypothesis — fix or replace the instrument; never soften the check.

## Outputs

`research/results/bocpd_test.json` (per-cohort: episodes, lags, alarms,
matched τ, bootstrap p) + findings-addendum verdict judged mechanically
against the gate above. Promotion (if any) via a separate PRISM PR
referencing this protocol, carrying the Phase-3 synthetic tests as unit
tests.

## Seeds & sizes (referee section)

Seed 7 everywhere. Bootstrap B=1000, block 20. Hazard 1/250 (primary),
{1/125, 1/500} sensitivity. Student-t ν estimated per training window,
clamped [3, 30]. Run-length alarm window k=5, τ per-cohort matched.
Cohorts C10/C20/C36 as defined in `research/protocol.md` §2.
