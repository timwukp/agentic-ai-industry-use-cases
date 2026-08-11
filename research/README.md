# Research — Pre-Registered Validation & Method Tests

This directory is the audit trail for every quantitative claim PRISM makes.
Nothing here is exploratory notebook debris: each study was **pre-registered**
(protocol committed and git-tagged BEFORE any test code existed), judged
**mechanically** against frozen numeric gates, and archived **win or lose**.

## The discipline

1. **Freeze first** — `protocol_<name>.md` states the null hypothesis
   ("the candidate does NOT help"), the exact incumbent, numeric decision
   gates, known limitations, and a fast-failure clause; it is tagged
   (`<name>-test-preregistered`) before the runner is written. Moving
   goalposts after the tag invalidates the confirmatory claim.
2. **Self-calibrating instruments** — every statistical tool must first pass
   synthetic tests with planted ground truth (find the planted signal, stay
   silent on noise, prove strict causality by future-mutation), exercising
   the production code path. See `tests/unit/test_studylib.py`.
3. **Point-in-time everywhere** — at date *t*, only data ≤ *t*; smoothed
   full-sample outputs (e.g. HMM `predict_proba`) are wrapped with
   expanding-window refits taking the filtered last observation.
4. **Failures are deliverables** — a documented fast failure prevents the
   same idea from being re-implemented in six months.

The whole loop is packaged as the reusable `theory-to-production` agent
skill; its usability test is documented in `DRAFT_protocol_skilltest.md` +
`skill_test_criteria.md`.

## The validation study (PR #46)

10/20/30/40/50-year back-to-back tests of every PRISM layer against real
FRED/market data: `protocol.md` (frozen at tag `study-preregistered`) →
`report.md` (full verdict matrix) → `findings.md` (interpretation).
Headlines: regime layer valid as a historical lens (AUROC 0.85–0.91) but
lagging >10bd in real time; VaR now calibration-green after the
vol-filtered revision; no economic predictability survives Hansen SPA.

## Method-test scoreboard: 2 promoted / 8 fast-failed

Verdicts with full tables in [`findings_addendum.md`](findings_addendum.md).

| # | Candidate | Protocol | Verdict |
|---|---|---|---|
| 1 | Regime-conditional EVT (own design) | study §6 revision | ❌ refuted — regime lag compounds at transitions |
| 2 | Fisher causality combination | study §6 revision | ✅ **promoted** — power 10-55%→85-100%; first CONFIRMED edge (VIX→DGS10, q=0.0018) |
| 3 | Vol-filtered EVT VaR (McNeil-Frey) | study §6 revision | ✅ **promoted** — calibration green both assets |
| 4 | QIS covariance shrinkage | `protocol_qis.md` | ❌ fast fail — no help at p=5 (conditional: re-open at large p) |
| 5 | RFSV rough volatility | `protocol_rfsv.md` | ❌ fast fail — daily proxy loses CC parity (conditional: needs intraday RV) |
| 6 | Signature (Lévy-area) features | `protocol_signature.md` | ❌ fast fail — 0/3 cohorts; AUROC −0.10 on primary |
| 7 | BOCPD/CUSUM fast alarm v1 | `protocol_bocpd.md` | ❌ fast fail + 2 protocol defects recorded |
| 8 | BOCPD v2 (user-approved fix) | `protocol_bocpd_v2.md` | ❌ sign-permutation p=0.172 — terminally closed |
| 9 | Breitung-Candelon freq causality v1 | `protocol_bc_freq.md` | ❌ fast fail on protocol design (BIC lag collapse; control unrunnable) |
| 10 | BC v2 (user-approved fix) | `protocol_bc_freq_v2.md` | ❌ positive control invisible on real data — terminally closed |

Methods that failed only because of the system's CURRENT representation
(dimensionality, data granularity) are archived with explicit re-activation
conditions in [`conditional_candidates.md`](conditional_candidates.md) —
constraints are design choices, not laws.

## File map

- `protocol*.md` — frozen pre-registrations (one per study/test)
- `report.md`, `findings.md`, `findings_addendum.md` — verdicts
- `studylib/` — self-calibrated instruments (backtests, forecast tests,
  metrics, breaks, PIT wrappers, QIS, signatures, changepoint, BC)
- `run_*.py` — test runners (one per protocol; checkpointed)
- `results/` — JSON verdict data + run logs
- `chronology.py`, `cameo_map.py` — frozen event chronology / factor maps
- `data/` — local mirror of fetched series (regenerable; not committed)
- `deep_research_*.json` — adversarially-verified survey archives
- `conditional_candidates.md` — representation-bound candidates + triggers

## Reproduction

`make study` re-runs the validation study bit-for-bit on a clean checkout
(fixed seeds, cached parquet checkpoints per cohort). Individual method
tests: `python research/run_<name>_test.py` after `make study` has built
the data mirror.
