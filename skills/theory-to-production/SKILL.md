---
name: theory-to-production
description: Run the full research → discover → test → prove → apply pipeline for adopting scientific/mathematical theories into a production system. Use when the user wants to (a) survey frontier or classical theory (math, statistics, ML, econometrics, any quantitative field) for candidates applicable to their system, (b) rigorously validate a candidate technique against real data before adoption, or (c) both end-to-end. Triggers on requests like "research whether X theory helps our system", "find new methods for our model and test them", "科學方法測試", "研究、發現、測試、論證、應用", or any ask to evaluate a paper/technique/algorithm for production adoption with journal-grade rigor. The core deliverable is a pre-registered, fast-failure-honest verdict — not an implementation-first spike.
---

# Theory-to-Production Pipeline

Distilled from a live campaign that surveyed frontier mathematics (Tao, RMT,
compressed sensing, rough volatility, signatures) and classical applied math
(BOCPD, frequency-domain causality) and ran ten pre-registered back-tests
against a production quant system: **2 promoted, 8 fast-failed, zero
contaminations**. The methodology is domain-agnostic; the examples are
finance but the loop applies to any "should this theory enter our system?"
question.

## The one-sentence contract

**Literature prestige never touches production; only a pre-registered test
against the user's own data, at the user's own scale, decides — and a
documented failure is a first-class deliverable.**

## Phase 0 — Frame the research WITH local constraints (the step everyone skips)

Before any search, extract from the codebase/user the **local constraint
fingerprint** and bake it into the research question itself:

- dimensionality (p, n, p/n ratio), data frequency/granularity, history depth
- what the system ALREADY does (incumbents to beat, not a green field)
- **diagnosed deficiencies** — candidates must target a named wound, not
  float free ("improves accuracy" is not a wound; "detection lags stress
  onset by >10 days" is)
- previously tested-and-rejected methods (so research doesn't re-recommend)
- **previously tested-and-PROMOTED methods** — promotions set the
  strict-superiority bar (a candidate challenging a calibration-green
  incumbent must beat it, not tie it)
- **prior surveys**: if a deep-research report already exists, re-read it
  and the scoreboard FIRST, mark consumed candidates, and only then search
  for new ones — never re-shop a shelf that was already picked clean
- maintain the conditional-candidates list in a NAMED file
  (`research/conditional_candidates.md`), not scattered in prose

Failure mode this prevents (observed): a survey ranked candidates by
literature evidence strength; the #1 candidate's evidence lived at p≈500
dimensions while the target system ran p=5 — it fast-failed in 3.5 minutes.
Four of four "literature stars" failed to transfer; both promotions were
old, simple methods matched to diagnosed deficiencies. **The applicability
gap between "proven in the literature" and "effective at our scale" is the
single biggest killer — surface it in the question, not the postmortem.**

**Constraints are design choices, not laws (user-taught correction).** The
WORLD is high-dimensional — economics, politics, energy, health, war are
all high-dimensional processes; a system's current low-dimensional
representation is a choice that can grow. So a candidate that fails at the
current scale gets one of TWO verdicts, and the protocol must say which:
- **fast-fail (absolute)**: the method is wrong for the deficiency itself
- **conditional-fail (representation-bound)**: the method is right math for
  a scale the system doesn't have YET — archive it as "activates when the
  representation grows to X" (e.g. covariance cleaning shelved at p=5 but
  pre-qualified for a future cross-sectional layer at p≈500). Track these
  in a standing "conditional candidates" list; when the system's
  dimensionality grows, re-open them BEFORE searching for new candidates.
Research questions should therefore include BOTH tracks: methods for the
current representation AND methods that would justify growing it.

## Phase 1 — Research (discover candidates)

Use the deep-research workflow (or equivalent multi-source search) with the
Phase-0-framed question. Require of the output:

- falsifiable claims with citations, adversarially verified (multi-vote)
- per-candidate: mathematical maturity / documented evidence AT the local
  scale / precise deficiency match / testability with data actually on hand
- counter-evidence actively sought (e.g. "illusion of sparsity" against
  LASSO) — a shortlist without counter-evidence is a sales brochure
- shortlist of ≤3-4 with a test-design sketch each

When relaying the report to the user: **applicability caveats go in the
same line as the headline claim, never a paragraph later.**

## Phase 2 — Pre-register (freeze before any test code exists)

For the chosen candidate, write `research/protocol_<name>.md` containing:

1. **Null hypothesis** = "the candidate does NOT help" (never the reverse)
2. **Incumbent** named exactly (file/function of the shipped baseline);
   if the incumbent is already good, require STRICT superiority — a tie
   keeps the simpler incumbent
3. **Decision gate**: numeric thresholds fixed in advance — typically
   (a) direction consistency across ≥2/3 data cohorts, (b) significance
   (block-bootstrap p<0.05 on paired differences, or the domain's standard
   calibration tests), (c) stability across pre-registered era/subsample
   splits, (d) no regression on guardrail metrics
4. **Known limitations declared up front** (e.g. "literature uses intraday
   data; we test a daily proxy — a null reads 'proxy fails', not 'theory
   false'")
5. **Fast-failure clause**: what happens on failure (documented, not
   adopted) and what conditions would justify a future re-test
6. Seeds, bootstrap sizes, cohort definitions — everything a referee needs

**Protocol dry-run (mandatory before tagging)**: mechanically verify the
frozen design is internally consistent and runnable — every named control,
arm, cohort, and parameter must actually exist and execute on the frozen
data. Observed failures this step would have caught: a positive control
naming a variable absent from the frozen cohort (the control silently
dropped and the null was void); a data-driven lag rule (BIC) collapsing a
frequency test's resolution to nothing (all bands identical); a false-alarm
gate comparing against an incumbent that never fires (degenerate). Checks:
(a) list every variable each arm consumes and assert presence in the
cohort's panel; (b) for any data-driven hyperparameter rule, bound it so
the instrument's mechanism survives the worst allowed value; (c) for every
comparative condition, ask "can a degenerate incumbent/arm make this
trivially passable or unpassable?"; (d) **positive-control power check**:
simulate data at the cohort's sample size and noise level with the known
control edge planted at its documented effect size — if the frozen
instrument detects it in <~80% of seeds, the design is invalid BEFORE it
runs. Observed failure this would have caught: a v2 that fixed a
resolution defect (fixed VAR lag 22) then died on real data because the
positive control was invisible at every frequency — 45 parameters per
cell plus a max-over-grid band rule left no power; resolution and power
were jointly unsatisfiable, and a pre-freeze synthetic power check would
have shown it for free. Fixing one defect exposes the next binding
constraint — check the constraints JOINTLY, not sequentially.

**One-shot re-test discipline (defect-fix v2s)**: a failure caused by
recorded PROTOCOL defects (not candidate merit) may justify a v2 — but
(i) v2 requires explicit user sign-off with full disclosure that this is
gate-adjacent territory (never quietly re-run); (ii) v2 fixes ONLY the
recorded defects, byte-identical intent elsewhere; (iii) v2 carries a
written one-shot clause: fail again — for ANY reason, including "the
positive control fails on real data" (= instrument invalid) — and the
candidate is terminally closed, no v3. Two candidates were closed this
way (BOCPD, BC); both stayed closed.

Then **commit + tag** (`<name>-test-preregistered`) via the repo's sanctioned
write path BEFORE writing runnable test code. Moving goalposts after the tag
invalidates the confirmatory claim — say so in the protocol.

**Draft state**: a protocol not yet frozen is named `DRAFT_protocol_<name>.md`
and carries a "DRAFT — not yet frozen, confers no confirmatory status"
header. Only the commit+tag ceremony promotes it to `protocol_<name>.md`.
Research-only exercises stop at DRAFT.

## Phase 3 — Self-calibrate the instruments

Every new statistical tool or feature implementation must first pass
synthetic tests with PLANTED ground truth:

- a detector must find planted signal AND stay silent on pure noise
- a filter must be strictly causal — mutation test: change FUTURE data,
  assert past outputs are bit-identical
- an estimator must beat the naive baseline where theory says it should,
  and must NOT fabricate structure where there is none
- calibration tests (e.g. Kupiec/Christoffersen for VaR-like claims) must
  pass on synthetic correctly-calibrated series and reject planted
  miscalibration
- **calibration must exercise the PRODUCTION entry point, called exactly
  as the runner will call it** — not an internal function with
  hyperparameters passed explicitly. Observed blind spot: tests called
  the core statistic with `p=22` while the production scan path chose the
  lag by BIC (which picked p=1 and silently destroyed the mechanism); the
  tested instrument was not the shipped instrument, and calibration green
  meant nothing. If a hyperparameter rule exists, the calibration suite
  must go THROUGH it; better, per dry-run check (b), remove the rule.

**An instrument that fails its own calibration disqualifies the TEST, not
the hypothesis.** Fix or replace the instrument; never soften the check.

## Phase 4 — Back-to-back test (point-in-time, walk-forward)

- **Point-in-time discipline everywhere**: at date t, only data ≤ t. Watch
  for smoothed/full-sample outputs masquerading as real-time (e.g. HMM
  predict_proba is smoothed — wrap with expanding-window refits taking the
  filtered last observation). The gap between the smoothed score and the
  PIT score IS the look-ahead bias, worth reporting.
- Arms differ in EXACTLY the candidate component; everything else (seeds,
  windows, labels, cohorts) identical — isolate the effect.
- **Matched operating points for detector comparisons**: never compare
  detection lag (or hit rate) at unequal false-alarm rates — thresholds
  must be matched on training data so speed wins aren't bought with noise.
  Make the trade-off's other side a co-primary endpoint.
- Multiple cohorts (e.g. 10/20/36-year lookbacks) + pre-registered era
  splits for stability.
- Checkpoint per cohort (JSON) so long runs resume; run in background and
  monitor.

## Phase 5 — Verdict + archive (the phase that makes failures valuable)

- Judge MECHANICALLY against the frozen gate. A significant p-value in the
  wrong direction is evidence of harm, not a nuance to explain away.
- Write the verdict into a findings addendum: results table, gate-by-gate
  ruling, post-hoc mechanism interpretation **labeled as post-hoc**, and
  any exploratory observation recorded as hypothesis-for-a-future-protocol
  (never as a claim).
- Keep a running **scoreboard** (promoted vs fast-failed) — the ratio is
  the methodology's credibility. If nothing ever fails, the gate is too
  soft; if nothing ever passes, candidates aren't matched to deficiencies.
- Ship the whole test (protocol, instruments, runner, results JSON,
  verdict) as a PR even on failure: an unrecorded failure gets repeated;
  a recorded one becomes institutional knowledge with a timestamp.

## Phase 6 — Promote (only survivors)

- Implementation into production code in a SEPARATE PR referencing the
  protocol; add synthetic-truth unit tests mirroring Phase 3.
- Update downstream consumers honestly: system prompts / docs must carry
  the validated bounds AND the caveats (e.g. "quote the calibrated block,
  note it moves with current volatility").
- Deploy, re-run the live pipeline once, verify the new output end-to-end
  (payload fields present, consumer behavior correct) before the PR merges.
- If the promotion later fails a wider re-test, demote with the same
  ceremony — the gate cuts both ways forever.

## Anti-patterns (each observed to cost real time)

- Implementing the candidate INSIDE production first, testing later
- Ranking candidates by paper count / venue prestige instead of
  deficiency-match at local scale
- "The test failed but the idea is good, let's ship a variant" without a
  new pre-registration
- Softening a gate after seeing results ("0.049 vs 0.05 is basically...")
- Reporting only the arm that won; hiding the incumbent's numbers
- Treating a refuted own-design (e.g. regime-conditional EVT) differently
  from a refuted external candidate — the gate has no author loyalty
- Calibrating an internal function while production calls a wrapper with
  a different hyperparameter path — test what ships, not what's convenient
- Fixing protocol defects one at a time across re-tests instead of
  checking the design's constraints jointly in the dry-run — each re-run
  burns the candidate's one shot on the next unexamined constraint
