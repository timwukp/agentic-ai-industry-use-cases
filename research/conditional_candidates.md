# Conditional Candidates — representation-bound methods awaiting activation

Methods that fast-failed (or were deferred) NOT because the math is wrong
but because the system's current representation hasn't reached their
applicable scale. **Re-open this list BEFORE searching for new candidates
whenever the representation grows.** (Per the theory-to-production skill,
Phase 0; user-taught principle: constraints are design choices, not laws.)

| Candidate | Activation condition | Pre-qualified assets | Origin |
|---|---|---|---|
| QIS/Ledoit-Wolf covariance cleaning | Cross-sectional portfolio layer at p ≈ hundreds | `research/studylib/qis.py` (self-calibrated) | PR #52 fast failure at p=5 |
| RFSV rough-volatility forecasting | Intraday realized variance enters the data lake | `research/run_rfsv_test.py` harness | PR #53 fast failure on daily proxy |
| Signature features (factor stream, original target) | Haiku factor history ≥ 60 trading days (~late Oct 2026) | `research/studylib/signature.py` (self-calibrated, causality-tested) | Deferred in protocol_signature.md |
| Signature fast-alarm channel (hypothesis) | Own pre-registration; matched false-alarm thresholds | Exploratory lag observation (13→6bd, PR #54) | Non-gated observation, PR #54 |
| HAR-family vol forecasting | Intraday realized variance enters the data lake | — | Skill self-test survey (dropped pre-protocol) |
| Monthly/mixed-frequency causality tier | Decision to grow the temporal representation | Monthly probe evidence (oil→10Y p≈0.12 vs daily q≈0.85) | findings_addendum.md Revision 2 |
| Robust BOCPD fast-alarm (news-factor input) | Factor stream ≥ 60 trading days AND a new protocol (market-stream design terminally closed per v2 one-shot clause) | `research/studylib/changepoint.py` (6 calibration gates passed) | v1+v2 fast failures, PR #55 |
