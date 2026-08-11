# Breitung-Candelon Frequency-Domain Causality v2 — Pre-Registered Test Protocol

**Status**: FROZEN at tag `bcfreq-v2-test-preregistered`, before any test
code. **One-shot clause**: this is the single user-approved re-test of the
BC candidate (approved 2026-08-11, "批准 BC v2"). If the frozen gate below
is not met, the candidate is TERMINALLY CLOSED — no v3, regardless of how
interpretable the failure is.

**Null hypothesis**: unchanged from v1 — frequency-band decomposition does
NOT recover the literature-documented oil→10Y causality that PRISM's
all-frequency daily scan misses, and does not add band-localized edges
beyond what the incumbent already finds. Fast failure is a valid outcome.

## Why a v2 exists (and what it may NOT do)

v1 (`protocol_bc_freq.md`, tag `bcfreq-test-preregistered`) fast-failed on
two PROTOCOL defects, recorded in the findings addendum — the hypothesis
itself was never actually tested:

1. **BIC lag collapse**: the lag order was BIC-chosen (1..22); BIC picked
   p=1, at which the two BC restriction rows span the same single
   coefficient at every ω — all 5 bands collapsed to one identical p-value
   (0.8207). Zero frequency resolution.
2. **Silently dropped positive control**: the VIX pairs were pre-registered
   on the C40 cohort, which has no VIXCLS (VIX starts 1990). `band_scan`
   filtered them out; the grid ran 10 cells instead of 20 and gate
   condition 3 was vacuously unfalsifiable.

v2 fixes EXACTLY these two defects. Everything else — bands, grid rule,
BH threshold, gate logic, seeds — is byte-identical in intent to v1.
Any further deviation discovered mid-run is a protocol violation to be
recorded, not silently absorbed.

## Method (frozen)

- **VAR lag order: FIXED p=22** (one trading month). No data-driven lag
  rule of any kind remains — the strongest form of the skill's dry-run
  bound ("bound any data-driven hyperparameter so the instrument's
  mechanism survives the worst allowed value"; the worst value was p=1, so
  the rule is removed entirely). Cost accepted up front: a less
  parsimonious VAR loses per-test power; that is the honest price of
  frequency resolution, and a null at p=22 is a real null.
- **Pair→cohort map (each pair runs on a cohort that CONTAINS it)**:
  - `DCOILWTICO_ret → DGS10_diff` (the missed edge) — **C40** (1986+)
  - `DGS10_diff → DCOILWTICO_ret` (direction control) — **C40**
  - `VIXCLS_diff → NASDAQCOM_ret` (positive control) — **C36** (1990+)
  - `NASDAQCOM_ret → VIXCLS_diff` — **C36**
- **Bands**: unchanged from v1 (`studylib/bcfreq.py` BANDS, 5 bands × 3
  grid points; band p = max over its grid points — conservative).
- **Multiplicity**: BH q<0.10 across the FULL 20-cell grid, pooled across
  both cohorts. The runner must assert exactly 20 rows with non-NaN p
  before applying BH; fewer is an abort, not a result.
- **Era stability**: the headline claim (oil→DGS10 in a low-frequency
  band) must hold with the same sign in **≥3 of the 4 eras C40 covers**
  (volcker 1986-89, moderation, zirp, covid_inflation — all verified
  ≥750 days in the dry-run). Aligned with the main study's H7 bar.
- Seeds 7; BC restriction F-test as implemented and calibrated in
  `studylib/bcfreq.py` (`bc_freq_pvalue` with explicit `p=22`).

## Decision gate (frozen — same 5 conditions as v1, cohorts corrected)

Promote the frequency tier into PRISM's nightly causality scan only if ALL:

1. **Recovery**: oil→DGS10 survives BH (q<0.10) in ≥1 pre-registered
   low-frequency band (period ≥ 1 month: `over_1y`, `quarterly_1y`, or
   `monthly_quarterly`) on the full C40 sample;
2. **Specificity**: the same edge does NOT appear in `sub_weekly`;
3. **Positive control**: VIX→NASDAQ survives BH in ≥1 band on C36 — an
   instrument blind to the confirmed edge cannot be trusted for new ones.
   (Control failure ⇒ verdict "instrument invalid on real data", which
   under the one-shot clause still terminally closes the candidate.)
4. **Direction control**: DGS10→oil does NOT survive BH in the same
   low-frequency bands where condition 1 fires;
5. **Era stability**: condition 1's band holds same-sign in ≥3/4 C40 eras.

## Protocol dry-run (mandatory per skill v3 — EXECUTED before freezing)

Results recorded 2026-08-11, before this file was tagged:

- (a) **Variable presence**: all 4 pairs' columns asserted present in
  their assigned cohort panels (C40: 10,482 rows; C36: 9,546 rows) ✓
- (b) **Hyperparameter bound**: no data-driven rule remains (p fixed 22) ✓
- (c) **Degenerate conditions**: restriction matrix rank = 2 at all 15
  grid points with p=22 (worst condition number 31.5 at ω=0.005);
  every era slice of both cohorts satisfies T−p ≥ 10p (min: volcker,
  T−22=912); positive control runnable on C36 ✓

## Self-calibration prerequisites (before real data)

The three v1 calibration tests in `tests/unit/test_studylib.py` remain,
re-pointed at the production path: they must exercise **`band_scan` with
the fixed lag** (v1's blind spot: calibration tests passed `p` explicitly
while the production path used BIC — the tested instrument was not the
shipped instrument). Additionally:

4. **Band distinguishability (the v1 failure mode, now a permanent
   regression test)**: on planted band-limited causality, the 5 band
   p-values must NOT all be identical, and the planted band's p must be
   the minimum.

An instrument that fails calibration disqualifies the TEST, not the
hypothesis — but under the one-shot clause a non-repairable instrument
also terminally closes the candidate.

## Outputs

`research/results/bcfreq_v2_test.json` + addendum verdict (win or lose) +
PR. If promoted: monthly "frequency tier" in the nightly PRISM causality
payload, separate PR referencing this protocol.
