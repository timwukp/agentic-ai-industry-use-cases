# Rejected candidates — pre-freeze screening kills

One line per candidate the theory scout (or a human survey) rejected BEFORE a
protocol freeze. This is the shelf's memory against re-shopping: Phase 0 of
every scout cycle reads this file, and a candidate listed here is consumed —
it may only be re-opened by a human with a written reason (new evidence, or a
representation change that voids the kill).

Post-freeze failures live in [findings_addendum.md](findings_addendum.md)
(they carry full protocols); representation-bound deferrals live in
[conditional_candidates.md](conditional_candidates.md). This file is for
candidates that never earned a protocol.

Append discipline: the scout adds ONE line per rejection via a micro-PR
touching only this file; a human merge is the acknowledgment.

| Date | Candidate | Target deficiency | Kill reason (one line of evidence) |
|---|---|---|---|
| 2026-08-11 | Smooth Local Projections (Barnichon & Brownlees 2019) | H3 — wide impact-function bands at h≤5 | Pre-registered positive-control power check: best 28.7% vs 80% gate across all configs; dominated by a simpler confound-isolating control. (H3 itself was later root-caused as an instrument defect and repaired — PR #65/#66 — so the target no longer exists in its old form.) |
