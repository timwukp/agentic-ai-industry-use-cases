DRAFT — not yet frozen, confers no confirmatory status

# Protocol (DRAFT): Explicit-duration semi-Markov (HSMM) regime layer vs the incumbent Gaussian-HMM

Scout cycle: 2026-09-01. Target deficiency: **H1b** — real-time regime-detection
lag (median 11–16.5 business days across cohorts, per `research/report.md`
H1b sections; PRISM's own 2026-08-20 correction sets H1a discrimination at
AUROC 0.84–0.86, so the lag problem is not a discrimination problem).

## 1. Null hypothesis

H0 (never the reverse): **Replacing the incumbent's implicit geometric
state-duration with an explicit, non-geometric duration model (HSMM) does
NOT reduce PRISM's point-in-time regime-detection lag, and/or does NOT
retain the incumbent's discrimination (AUROC), at PRISM's own daily,
p≈2–4, cohort-dependent regime-layer scale.**

## 2. Incumbent, named exactly

- `fit_regimes()` in `tools/finance/quant_batch/prism/regime.py` — a
  3-state `hmmlearn.hmm.GaussianHMM` (`covariance_type="full"`, `n_iter=200`,
  `random_state=7`). Per-state expected duration is computed there as
  `persistence[label] = 1.0 / max(1e-9, 1.0 - p_stay)` — i.e. the model's
  implied sojourn-time distribution is **geometric** (memoryless, constant
  hazard) by construction of a first-order Markov chain. This is the exact
  mechanism the candidate targets: a geometric-duration filter systematically
  under-weights "the regime is about to persist" evidence right after a
  transition, which is one credible mechanism for H1b's lag (this is a
  hypothesis about mechanism, not yet a demonstrated cause — labeled as
  such).
- Point-in-time wrapper: `pit_regime_probs()` in `research/studylib/pit.py`
  (expanding-window monthly refits, last fitted month's filtered
  probability carried forward to every day of the FOLLOWING month — a
  coarse but strictly point-in-time scheme; both arms inherit this
  identically).
- Scoring: `auroc()` and `detection_lags()` in `research/studylib/metrics.py`,
  invoked exactly as `research/run_study.py::h1b_point_in_time` does
  (threshold 0.5, `stress` state probability vs `chronology`-defined
  NBER-recession ∪ crash-window labels).
- Incumbent's real numbers (from the sealed `research/report.md`, reused
  as the comparison baseline — not re-run under a changed instrument):

| Cohort | AUROC (H1b, PIT) | median lag (bd) | n_episodes |
|---|---|---|---|
| C50 | 0.685 | 6.5 | 18 |
| C40 | 0.7609 | 11.0 | 15 |
| C36 (primary) | 0.7379 | 15.5 | 14 |
| C20 | 0.7634 | 15.5 | 8 |
| C10 | 0.7438 | 16.5 | 4 |

Because the incumbent NEVER records zero episodes in any cohort, condition
3 below is a real budget-style floor, not a degenerate vs.-silence
comparison (the defect that sank BOCPD v1 on C10).

## 3. Candidate

A hidden semi-Markov model (HSMM / explicit-duration Markov-switching
model) with the SAME 3-state Gaussian emission structure and the SAME
per-cohort input columns as the incumbent (`REGIME_BASE` +
`REGIME_EXTRA`, cohort-dependent — C50/C40 lack VIX/oil, C36-C10 carry all
four), but with an explicit, pre-registered discretized negative-binomial
duration distribution per state (2 free parameters per state: mean and
dispersion, estimated by EM/forward-backward over the pre-registered
duration support), replacing the chain's implicit geometric sojourn time.
Same seed (7), same PIT wrapper mechanics as the incumbent (monthly
expanding-window refit, filtered last-observation carried forward).

**Fixed (non-data-driven) hyperparameter**: maximum explicit-duration
support `D_max = 90` business days, chosen a priori (≈ the incumbent's own
widest reported per-cohort expected-duration order of magnitude) and NOT
selected by AIC/BIC/cross-validation. This directly applies dry-run check
(b): a hyperparameter-selection rule (e.g. BIC-chosen `D_max`) is exactly
the mechanism that collapsed the Breitung-Candelon v1 test's frequency
resolution (`findings_addendum.md`, BC section, defect 2) — so this
protocol removes that failure mode by fiat rather than repeating it.

## 4. Decision gate (frozen, mechanical, numeric)

Two PRIMARY conditions (both required):

- **G1 (discrimination, non-inferiority + improvement)**: PIT AUROC for
  HSMM must be ≥ incumbent AUROC − 0.02 in EVERY cohort (guardrail — this
  is the exact metric that the fast-failed signature-features candidate
  violated by up to −0.104), AND strictly greater than the incumbent in
  ≥3/5 cohorts.
- **G2 (the deficiency itself — POWER-CHECKED, see §6)**: pooled, paired,
  one-sided Wilcoxon signed-rank test on per-episode
  `(incumbent_lag − candidate_lag)`, pooling ALL FIVE cohorts' episodes
  (n=59: 18+15+14+8+4), H1: median difference > 0, α=0.05.

Three GUARDRAILS (any single failure is also a fast-fail, no override):

- **G3 (no cohort regression)**: candidate's median lag must not exceed
  the incumbent's by more than 3 business days in ANY cohort.
- **G4 (era stability)**: within the primary C36 cohort, the sign of the
  median lag difference must be non-negative in ≥2/3 of the pre-registered
  eras in `research/chronology.py` (`ERAS`).
- **G5 (missed-episode floor)**: the count of "never-detected" episodes
  (i.e. `detection_lags()`'s conservative fallback, lag == episode length)
  must not increase vs. the incumbent in any cohort.

## 5. Known limitations (declared up front)

1. **Duration-parameter identifiability**: an HSMM's explicit duration
   distribution is estimated from very few COMPLETE observed sojourns — at
   most 18 per cohort, 59 pooled across 50 years. The literature itself
   flags this as an open, unresolved problem for duration-dependent
   Markov-switching: "there is currently no procedure for estimating this
   duration or testing whether a given duration is appropriate for a given
   data set" (Reis & Pereira, "Mitigating the choice of the duration in
   DDMS models through a parametric link", arXiv:2307.01405, 2023 —
   applies to macro/financial duration-dependent switching generally, not
   specifically validated at PRISM's exact scale). We mitigate by fixing
   `D_max` a priori (§3), but the negative-binomial mean/dispersion are
   still EM-estimated from the same thin episode history as the incumbent's
   own transition matrix — this is a shared, not new, data constraint.
2. **Financial-domain HSMM precedent exists but at a different task**: a
   regularized VAR-HSMM has been fit to multivariate financial (NYSE
   portfolio) return series and shown to segment regimes with covariance
   regularization ("A Regularized Vector Autoregressive Hidden Semi-Markov
   Model, with Application to Multivariate Financial Data", arXiv:1804.10308,
   2018) — that paper targets regime SEGMENTATION quality on cross-sectional
   equity portfolios (large p), not real-time DETECTION LAG on PRISM's p≈4
   macro/vol panel; the applicability gap is the same one the shelf's own
   QIS/RFSV kills warned about (evidence at a different scale/task than
   ours).
3. **General explicit-duration formalism is mature, pre-2020, and
   well-taxonomized** (Dong & Pentland-style survey "Explicit-Duration
   Markov Switching Models", arXiv:1909.05800, 2019 — a pedagogical
   monograph, not itself an empirical finance result) — maturity of the
   MATH is not evidence of transfer to PRISM's scale; that is exactly what
   this protocol tests.
4. **PIT coarseness inherited identically by both arms** (§2) — neither arm
   is credited/blamed for intra-month responsiveness.
5. A null here reads "explicit-duration modeling does not reduce PRISM's
   regime-detection lag at its own daily/p≈4 scale, via this proxy
   instrument," not "duration-dependence in Markov-switching models is
   false" — literature evidence spans domains (ECG segmentation, activity
   recognition, macro business-cycle dating at quarterly frequency) with
   very different data-generating rates of regime change.

## 6. Positive-control power check (mandatory, run pre-freeze, in code
interpreter — see `research/scout/memo_2026-09-01.md` §Power check for the
full simulation and numbers)

The frozen G2 instrument (§4) was power-checked BEFORE this draft was
written, using the closest real, documented analog effect size available
on THIS exact deficiency in THIS exact system: the BOCPD v2 pre-registered
re-test (`findings_addendum.md`, "BOCPD v2" section) found a real-data
per-episode win-rate of 13/19 = 0.684 (mean pooled lag gain 17.3bd) that
did **not** clear an exact sign-permutation test at n=19 (p=0.172).

- A sign-permutation (binomial) test on episode WINS ONLY, at n=19/26/59,
  reaches 80% power only at implausibly large win-rates (≥0.85 at n=26,
  ≥0.80 at n=59) — i.e. **the original design (sign test, 3-cohort pool)
  is invalid: <80% power at the one real documented effect size we have.**
- **Redesign applied** (this is the §6 mandatory redesign-or-reject step,
  executed BEFORE freezing, not after seeing this candidate's results):
  switching the test statistic to Wilcoxon signed-rank (uses magnitude, not
  just sign) AND pooling all 5 cohorts (n=59, not 3/n=26) raises power to
  **94.4%** at the documented effect size (d≈0.479). This redesign is
  reflected in G2 above.
- Disclosed honestly: this power check calibrates against BOCPD's
  documented effect, not HSMM's true (unknown) effect. If HSMM's real
  effect is smaller, G2 may still be underpowered on real data — that
  would be a legitimate null, not a design failure, and reads accordingly.

**Verdict of this dry-run**: design is valid to proceed to a real-data test
under the REDESIGNED G2 (Wilcoxon, 5-cohort pool). Per the skill's Phase 2
mandate, this redesign happens in the pre-registration record itself and is
disclosed in full in the memo — the protocol is NOT frozen (no tag, no
`protocol_<name>.md`) pending human review.

## 7. Fast-failure clause

- Fails if G1 or G2 fails. Fails (no override) if any of G3/G4/G5 fails.
- On failure: HSMM does not enter PRISM; the negative-binomial duration
  fit code is archived (would live under `research/studylib/` alongside
  `changepoint.py`, `qis.py`, `signature.py` — not created in this DRAFT
  cycle, since a human must freeze first).
- If failure traces to a recorded PROTOCOL defect (not candidate merit —
  e.g. `D_max=90` proves mechanically wrong for a cohort, or the pooling
  scheme is later shown non-exchangeable across cohorts), a v2 may be
  scientifically justified but requires explicit human sign-off
  (gate-shopping disclosure) and carries the one-shot clause per the
  BOCPD/BC precedent: fail again for ANY reason and the candidate is
  terminally closed.
- If G2 fails specifically because the REAL effect size is smaller than
  the documented BOCPD precedent (i.e. the power check was valid but the
  candidate's true effect isn't there), this reads as "explicit-duration
  modeling does not measurably help H1b at PRISM's scale" — a valid,
  reportable null, not grounds for a v2.

## 8. Seeds, cohorts, sizes

- Seed 7 (matches production `fit_regimes`/`pit_regime_probs` defaults).
- Cohorts: C50, C40, C36 (primary), C20, C10 — identical definitions to
  `research/run_study.py::COHORTS`.
- Wilcoxon signed-rank: `scipy.stats.wilcoxon`, pooled n=59 episodes,
  one-sided (`alternative="greater"` on incumbent−candidate), α=0.05.
- Era splits: `research/chronology.py::ERAS`, applied within C36 only (the
  only cohort with ≥3 usable eras at ≥250 days each, per existing
  `_era_slices` logic in `run_study.py`).
