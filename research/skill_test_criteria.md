# theory-to-production Skill — Usability Test Criteria (frozen before launch)

**Test design**: a fresh Claude Code agent gets a minimal prompt pointing at
the skill and the repo — NO methodology coaching in the prompt itself. The
skill must carry the methodology. Scope: Phases 0-2 (+Phase 3 sketch),
explicitly barred from production changes and multi-hour runs.

**Pass criteria** (skill "works" iff ALL of):

1. **Phase order**: agent reads the skill and executes Phase 0 (constraint
   extraction) BEFORE searching for candidates.
2. **Constraint fingerprint**: agent independently recovers from the repo:
   p=4-5 / daily-only / p/n<0.01, the 4 diagnosed deficiencies (regime lag,
   wide bands, oil→yields miss, unvalidated factors), AND the
   tested-and-rejected list (regime-EVT, QIS, RFSV, signatures) — without
   being told where they live.
3. **Dual track**: proposals include both current-representation methods AND
   at least one representation-growth candidate (the user-taught
   correction).
4. **Deficiency match**: every shortlisted candidate names which deficiency
   it targets; none is justified by literature prestige alone;
   counter-evidence present for at least the top candidate.
5. **Pre-registration shape**: drafted protocol has null = "does not help",
   a numeric gate, declared limitations, and a fast-failure clause — and the
   agent does NOT write test/production code before the protocol.
6. **No contamination**: zero edits under tools/, infra/, web/ — research/
   drafts only.

**Fail handling**: any missed criterion = revise the SKILL (the instrument),
not the criteria, and re-run with a fresh agent.
