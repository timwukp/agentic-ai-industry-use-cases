# Robust BOCPD Fast-Alarm Channel — v2 Protocol (gate-defect fix, user-approved)

**Status**: FROZEN at tag `bocpd-v2-preregistered`, before any v2 code runs.

**Provenance and gate-shopping disclosure (mandatory reading):** v1
(`protocol_bocpd.md`, tag `bocpd-test-preregistered`) FAST-FAILED. Two
protocol-design defects were recorded at judging time in the findings
addendum: (1) the false-alarm gate compared challengers against an
incumbent that never fired on C10 — a degenerate comparison only another
never-firing detector could pass; (2) the frozen block-bootstrap
significance test requires ~100 samples but stress episodes number 3-10
per cohort, making the condition unevaluable. This v2 exists ONLY to fix
those two gate defects. It was **explicitly approved by the user on
2026-08-11** after a full gate-shopping risk disclosure. Any v2 report
MUST present the v1 failure alongside. **One-shot clause: if v2 fails,
the candidate is terminally closed — no v3 under any rationale.**

## What is IDENTICAL to v1 (the anti-gate-shopping core)

- Arms: incumbent (HMM filtered P(stress)>0.5), robust Student-t BOCPD
  (df clamp 8, hazard 1/250, P(run≤5)>τ), CUSUM (k=0.5) — same code,
  `research/studylib/changepoint.py`, unchanged.
- Data: cohorts C10/C20/C36 (C36 primary), same panel columns, same
  chronology labels, same PIT z-scoring (trailing 250d, shifted).
- Threshold matching procedure: τ/h chosen on the TRAINING segment (first
  40%) only; deadtime 20bd; seeds 7. Sensitivity hazards {1/125, 1/500}
  reported descriptively, not gated.
- Self-calibration gates: the six planted-truth tests already in
  tests/unit/test_studylib.py (passing, including the t(3) falsification
  control).

## What CHANGES (exactly the two recorded defects, nothing else)

1. **False-alarm gate (condition 2)** — was "OOS FA ≤ incumbent in every
   cohort" (degenerate against a silent incumbent). Now an ABSOLUTE
   budget: **OOS false alarms ≤ 2.0 per 250 business days in every
   cohort** (= ARL to false alarm ≥ 125bd; stricter than v1's training
   budgets on C10/C36, comparable on C20 — fixed a priori, independent of
   any arm's realized behavior). Threshold matching still targets the
   incumbent's training FA where available, floored at the ARL≥250d rule
   as in v1.
2. **Significance instrument (condition 3)** — was block bootstrap
   (n≥100 infeasible). Now an **exact paired sign-permutation test** on
   per-episode detection outcomes, pooled across cohorts: for each stress
   episode, challenger-vs-incumbent lag difference (missed = episode
   length, v1 convention); under H0 the sign of each paired difference is
   exchangeable; p = exact permutation probability of a mean improvement
   ≥ observed over all 2^n sign assignments (n = pooled episodes ≈ 19,
   exact enumeration feasible). Promote requires p < 0.05.

## Decision gate v2 (frozen)

Promote the fast-alarm channel only if ALL of:
1. **Lag**: median OOS detection lag improves vs incumbent by ≥3bd in
   ≥2/3 cohorts, no cohort worse (unchanged from v1).
2. **False alarms**: OOS FA ≤ 2.0 per 250bd in EVERY cohort (fixed
   budget, defect-1 fix).
3. **Significance**: pooled exact sign-permutation p < 0.05 on paired
   episode lag differences (defect-2 fix).
4. **Era stability**: improvement sign holds in ≥3/4 covered eras
   (unchanged).
5. **Missed-detection guardrail**: episodes detected ≥ incumbent per
   cohort (unchanged).

CUSUM runs under the same gate; its v1 OOS FA blow-up (~11-12/250bd)
already fails condition 2 unless the rerun differs, which is not expected
since nothing about its arm changed.

## Outputs

`research/results/bocpd_v2_test.json` + addendum verdict presenting v1
and v2 side by side. Promotion (if any) via separate PRISM PR carrying
both protocols in its description.
