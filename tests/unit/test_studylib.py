"""Self-calibration tests for the study's statistical tools.

A test statistic that judges PRISM must first prove itself: correctly
calibrated inputs must NOT be rejected, planted miscalibration MUST be.
Skipped when the scientific stack is absent (zip-only CI).
"""

import sys
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pd = pytest.importorskip("pandas")
pytest.importorskip("scipy")

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "research"))

from studylib.backtests import (  # noqa: E402
    basel_traffic_light,
    christoffersen_independence,
    conditional_coverage,
    kupiec_pof,
)
from studylib.forecast_tests import diebold_mariano, spa_test  # noqa: E402
from studylib.metrics import auroc, detection_lags, event_hit_test  # noqa: E402
from studylib.breaks import sup_chow  # noqa: E402


# ---------------- VaR backtests ----------------


def test_kupiec_accepts_calibrated_rejects_miscalibrated():
    rng = np.random.default_rng(7)
    calibrated = rng.random(2000) < 0.01
    assert kupiec_pof(calibrated, 0.01)["p"] > 0.05
    broken = rng.random(2000) < 0.04  # 4x too many violations
    assert kupiec_pof(broken, 0.01)["p"] < 0.01


def test_christoffersen_detects_clustering():
    rng = np.random.default_rng(7)
    independent = rng.random(3000) < 0.02
    assert christoffersen_independence(independent)["p"] > 0.05
    # planted clustering: violations come in runs of 4
    clustered = np.zeros(3000, dtype=bool)
    starts = rng.choice(2990, size=15, replace=False)
    for s in starts:
        clustered[s : s + 4] = True
    assert christoffersen_independence(clustered)["p"] < 0.01


def test_conditional_coverage_combines_both():
    rng = np.random.default_rng(7)
    good = rng.random(2500) < 0.01
    assert conditional_coverage(good, 0.01)["p"] > 0.05


def test_basel_zones():
    n = 250
    green = np.zeros(n, dtype=bool)
    green[:2] = True  # 2 violations in 250d @99% is comfortably green
    assert basel_traffic_light(green, 0.01) == "green"
    red = np.zeros(n, dtype=bool)
    red[:12] = True
    assert basel_traffic_light(red, 0.01) == "red"


# ---------------- forecast tests ----------------


def test_dm_no_difference_and_clear_difference():
    rng = np.random.default_rng(7)
    base = rng.normal(1.0, 0.2, 500)
    same_a, same_b = base + rng.normal(0, 0.05, 500), base + rng.normal(0, 0.05, 500)
    assert diebold_mariano(same_a, same_b)["p"] > 0.05
    worse = base + 0.3 + rng.normal(0, 0.05, 500)
    r = diebold_mariano(base, worse)
    assert r["p"] < 0.01 and r["dm"] < 0  # base clearly better


def test_spa_rejects_snooping_and_finds_real_skill():
    rng = np.random.default_rng(7)
    T, K = 1000, 40
    # pure noise universe: best of 40 looks good nominally, SPA must not
    noise = rng.normal(0, 0.01, (T, K))
    assert spa_test(noise, n_boot=300)["p"] > 0.10
    # one genuinely skilled strategy amid noise: SPA must detect
    skilled = noise.copy()
    skilled[:, 3] += 0.002  # strong daily edge
    assert spa_test(skilled, n_boot=300)["p"] < 0.05


# ---------------- metrics ----------------


def test_auroc_known_values():
    labels = np.array([0, 0, 0, 0, 1, 1, 1, 1], dtype=bool)
    perfect = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])
    assert auroc(perfect, labels) == 1.0
    inverted = 1.0 - perfect
    assert auroc(inverted, labels) == 0.0
    rng = np.random.default_rng(7)
    random_scores = rng.random(4000)
    random_labels = rng.random(4000) < 0.3
    assert abs(auroc(random_scores, random_labels) - 0.5) < 0.03


def test_detection_lag():
    labels = np.array([0, 0, 1, 1, 1, 1, 0, 0], dtype=bool)
    scores = np.array([0.1, 0.1, 0.2, 0.3, 0.9, 0.9, 0.1, 0.1])
    assert detection_lags(scores, labels) == [2]  # detected on 3rd day of run
    never = np.full(8, 0.1)
    assert detection_lags(never, labels) == [4]  # full run length, conservative


def test_event_hit_test_calibration():
    rng = np.random.default_rng(7)
    n = 5000
    spikes = rng.random(n) < 0.02
    # events placed ON spike days => high hit rate, significant
    spike_positions = np.where(spikes)[0][:10].tolist()
    r = event_hit_test(spikes, spike_positions, window=3)
    assert r["hit_rate"] == 1.0 and r["p"] < 0.01
    # random events => insignificant
    random_pos = rng.choice(n, 10, replace=False).tolist()
    r2 = event_hit_test(spikes, random_pos, window=3)
    assert r2["p"] > 0.01 or r2["hit_rate"] < 0.5


# ---------------- structural breaks ----------------


def test_sup_chow_detects_planted_break_and_not_stability():
    rng = np.random.default_rng(7)
    n = 600
    x = rng.normal(0, 1, n)
    X = np.column_stack([np.ones(n), x])
    # stable relationship
    y_stable = 1.0 + 0.5 * x + rng.normal(0, 0.5, n)
    assert sup_chow(y_stable, X)["reject_5pct"] is False
    # coefficient flips at midpoint
    beta = np.where(np.arange(n) < n // 2, 0.5, -0.5)
    y_break = 1.0 + beta * x + rng.normal(0, 0.5, n)
    r = sup_chow(y_break, X)
    assert r["reject_5pct"] is True
    assert abs(r["break_idx"] - n // 2) < 60


# ---------------- QIS/shrinkage (protocol_qis.md self-calibration) ----------------


def test_shrinkage_reduces_frobenius_loss_vs_sample_cov():
    from studylib.qis import shrunk_covariance

    rng = np.random.default_rng(7)
    p = 5
    A = rng.normal(0, 1, (p, p))
    true_cov = A @ A.T + p * np.eye(p)
    L = np.linalg.cholesky(true_cov)
    wins_short = 0
    trials = 40
    for t in range(trials):
        rng_t = np.random.default_rng(100 + t)
        X = (L @ rng_t.normal(0, 1, (p, 30))).T  # n=30: p/n ~ 0.17, noisy
        S = np.cov(X, rowvar=False, bias=True)
        Sh = shrunk_covariance(X)
        loss_s = np.sum((S - true_cov) ** 2)
        loss_sh = np.sum((Sh - true_cov) ** 2)
        if loss_sh < loss_s:
            wins_short += 1
    # shrinkage must help in the clear majority of noisy-sample trials
    assert wins_short >= 0.7 * trials, f"only {wins_short}/{trials} wins"


def test_shrinkage_does_not_fabricate_structure_on_identity():
    from studylib.qis import shrunk_covariance

    rng = np.random.default_rng(11)
    X = rng.normal(0, 1, (2000, 5))  # true cov = I, n >> p
    Sh = shrunk_covariance(X)
    off = Sh - np.diag(np.diag(Sh))
    assert np.abs(off).max() < 0.08  # no invented correlations
    assert np.abs(np.diag(Sh) - 1.0).max() < 0.15


def test_shrinkage_always_positive_definite_and_weighted():
    from studylib.qis import shrunk_covariance

    rng = np.random.default_rng(13)
    # degenerate: fewer effective observations than dimensions
    X = rng.normal(0, 1, (50, 5))
    w = np.zeros(50)
    w[:3] = 1.0  # only 3 effective rows for p=5
    Sh = shrunk_covariance(X, weights=w)
    eigvals = np.linalg.eigvalsh(Sh)
    assert eigvals.min() > 0, "shrunk covariance must be PD even when degenerate"


# ---------------- signature features (protocol_signature.md self-calibration) ----------------


def test_levy_area_detects_planted_lead_and_flips_sign():
    from studylib.signature import levy_area

    rng = np.random.default_rng(7)
    n = 3000
    k = 3
    x = pd.Series(
        rng.normal(0, 1, n), name="x", index=pd.bdate_range("2015-01-01", periods=n)
    )
    y_lag = x.shift(k).fillna(0).rename("y")  # x leads y
    y_lead = x.shift(-k).fillna(0).rename("y")  # y leads x

    a_xy_lag = levy_area(x, y_lag).dropna().mean()
    a_xy_lead = levy_area(x, y_lead).dropna().mean()
    # planted lead produces a systematically signed area; reversing the
    # lead flips the sign
    assert a_xy_lag * a_xy_lead < 0, f"{a_xy_lag} vs {a_xy_lead}"
    assert abs(a_xy_lag) > 1.0


def test_levy_area_no_drift_on_independent_noise():
    from studylib.signature import levy_area, zscore_causal

    rng = np.random.default_rng(9)
    n = 4000
    idx = pd.bdate_range("2010-01-01", periods=n)
    x = pd.Series(rng.normal(0, 1, n), name="x", index=idx)
    y = pd.Series(rng.normal(0, 1, n), name="y", index=idx)
    z = zscore_causal(levy_area(x, y)).dropna()
    assert abs(z.mean()) < 0.15
    assert 0.6 < z.std() < 1.6


def test_levy_area_strictly_causal():
    from studylib.signature import levy_area

    rng = np.random.default_rng(11)
    n = 600
    idx = pd.bdate_range("2020-01-01", periods=n)
    x = pd.Series(rng.normal(0, 1, n), name="x", index=idx)
    y = pd.Series(rng.normal(0, 1, n), name="y", index=idx)
    a_full = levy_area(x, y)
    # mutate the FUTURE beyond t0; values at <= t0 must be bit-identical
    t0 = 400
    x2 = x.copy()
    x2.iloc[t0 + 1 :] = 99.0
    a_mut = levy_area(x2, y)
    assert np.allclose(
        a_full.iloc[: t0 + 1].dropna(), a_mut.iloc[: t0 + 1].dropna()
    ), "future data leaked into past features"


# ---------------- change-point instruments (protocol_bocpd.md Phase 3) ----------------


def _bocpd_alarms(scores, tau):
    """Alarm dates from a score series at threshold tau, 20-day deadtime."""
    alarms = []
    cool = 0
    for i, s in enumerate(scores):
        if cool > 0:
            cool -= 1
            continue
        if s > tau:
            alarms.append(i)
            cool = 20
    return alarms


def test_bocpd_detects_planted_mean_shifts_quickly():
    """3-sigma planted shifts (stress-onset scale in standardized panel
    space) must all be caught within 5 steps. The robust arm's measured
    power curve at production FA budget: 1.5σ ≈ 40%, 2σ ≈ 80%, 3σ = 100%
    — the small-shift blindness is the documented price of Student-t
    robustness, recorded here so the back-test reads it knowingly."""
    from studylib.changepoint import bocpd_alarm_series

    rng = np.random.default_rng(7)
    segs, breaks = [], []
    pos = 0
    for j in range(6):
        n = 400
        mu = 0.0 if j % 2 == 0 else 3.0
        segs.append(rng.normal(mu, 1.0, n))
        pos += n
        if j < 5:
            breaks.append(pos)
    x = np.concatenate(segs)
    scores = bocpd_alarm_series(x)
    alarms = _bocpd_alarms(scores, tau=0.3)
    detected = 0
    for b in breaks:
        if any(b <= a <= b + 5 for a in alarms):
            detected += 1
    assert detected == 5, f"only {detected}/5 planted 3-sigma breaks found"


def test_bocpd_silent_on_pure_noise():
    from studylib.changepoint import bocpd_alarm_series

    rng = np.random.default_rng(9)
    x = rng.normal(0, 1, 3000)
    alarms = _bocpd_alarms(bocpd_alarm_series(x), tau=0.5)
    # budget: at most ~1 false alarm per 750 obs at this threshold
    assert len(alarms) <= 4, f"{len(alarms)} false alarms on pure noise"


def test_student_t_arm_robust_where_gaussian_overfires():
    """The decisive calibration: on t(3) noise with NO breaks, the robust
    arm stays quiet and the Gaussian control MUST overfire (reproducing the
    literature's failure mode before we trust the cure)."""
    from studylib.changepoint import GaussianBOCPD, StudentTBOCPD

    rng = np.random.default_rng(11)
    x = rng.standard_t(3, 3000)

    def run(det):
        scores = np.empty(len(x))
        for i, xi in enumerate(x):
            scores[i] = det.update(float(xi))
        return _bocpd_alarms(scores, tau=0.5)

    robust_alarms = run(StudentTBOCPD())
    gaussian_alarms = run(GaussianBOCPD())
    assert len(robust_alarms) <= 6, f"robust arm fired {len(robust_alarms)}x on t(3)"
    assert len(gaussian_alarms) > 2 * max(len(robust_alarms), 1), (
        f"Gaussian control did not overfire ({len(gaussian_alarms)} vs "
        f"{len(robust_alarms)}) — literature failure mode did not reproduce"
    )


def test_bocpd_vol_burst_distractor():
    """GARCH-style vol clustering with NO mean break — the daily-returns
    trap. Robust arm must stay within budget."""
    from studylib.changepoint import bocpd_alarm_series

    rng = np.random.default_rng(13)
    n = 3000
    sigma = np.zeros(n)
    x = np.zeros(n)
    sigma[0] = 1.0
    for t in range(1, n):
        sigma[t] = np.sqrt(0.05 + 0.10 * x[t - 1] ** 2 + 0.85 * sigma[t - 1] ** 2)
        x[t] = rng.normal(0, sigma[t])
    alarms = _bocpd_alarms(bocpd_alarm_series(x / x.std()), tau=0.5)
    assert len(alarms) <= 8, f"{len(alarms)} alarms on vol-burst distractor"


def test_bocpd_strictly_causal():
    from studylib.changepoint import bocpd_alarm_series

    rng = np.random.default_rng(17)
    x = rng.normal(0, 1, 800)
    full = bocpd_alarm_series(x)
    x_mut = x.copy()
    x_mut[500:] = 50.0  # violent future mutation
    mut = bocpd_alarm_series(x_mut)
    assert np.allclose(full[:500], mut[:500]), "future data leaked into past scores"


def test_cusum_detects_and_stays_quiet():
    from studylib.changepoint import cusum_alarm_series

    rng = np.random.default_rng(19)
    # planted shift
    x = np.concatenate([rng.normal(0, 1, 800), rng.normal(1.5, 1, 200)])
    stat = cusum_alarm_series(x)
    first_alarm = int(np.argmax(stat[800:] > 8.0))
    assert (stat[800:] > 8.0).any() and first_alarm < 30
    # pure noise: statistic rarely crosses at h=8
    x2 = rng.normal(0, 1, 5000)
    crossings = int((cusum_alarm_series(x2) > 8.0).sum())
    assert crossings <= 2, f"{crossings} CUSUM false alarms on noise"


# ------- BC frequency-domain causality (protocol_bc_freq.md + _v2.md) -------


def test_bc_flags_planted_lowfreq_causality_in_correct_band():
    """Plant realizable low-frequency causality: y responds to the trailing
    20-day MEAN of x (a finite-lag transfer function a VAR can represent —
    an ideal FFT brick-wall filter is an infinite-lag operator no VAR(22)
    can capture, which is why the first fixture version failed)."""
    from studylib.bcfreq import bc_freq_pvalue

    rng = np.random.default_rng(7)
    n = 4000
    x = rng.normal(0, 1, n)
    ma = np.convolve(x, np.ones(20) / 20, mode="full")[:n]
    y = np.zeros(n)
    y[1:] = 1.5 * ma[:-1] + rng.normal(0, 0.5, n - 1)
    # low-frequency points: must reject non-causality decisively
    assert bc_freq_pvalue(y, x, omega=0.03, p=22) < 0.01
    assert bc_freq_pvalue(y, x, omega=0.10, p=22) < 0.01
    # high-frequency point: must NOT reject (20-day MA kills sub-weekly)
    assert bc_freq_pvalue(y, x, omega=2.5, p=22) > 0.05


def test_bc_allfreq_causality_flags_everywhere():
    from studylib.bcfreq import bc_freq_pvalue

    rng = np.random.default_rng(9)
    n = 3000
    x = rng.normal(0, 1, n)
    y = np.zeros(n)
    y[1:] = 0.5 * x[:-1] + rng.normal(0, 1, n - 1)
    for w in (0.03, 0.3, 1.5, 2.8):
        assert bc_freq_pvalue(y, x, omega=w) < 0.01, f"missed at omega={w}"


def test_bc_band_scan_distinguishes_bands_at_fixed_lag():
    """v1's fatal defect as a permanent regression test: BIC chose lag 1,
    at which every band returned the SAME p-value. The production path
    (band_scan, fixed p=22 per protocol_bc_freq_v2.md) must produce
    band-distinguishable p-values, with the planted low-frequency band
    strictly the most significant."""
    from studylib.bcfreq import band_scan

    rng = np.random.default_rng(7)
    n = 4000
    x = rng.normal(0, 1, n)
    ma = np.convolve(x, np.ones(20) / 20, mode="full")[:n]
    y = np.zeros(n)
    y[1:] = 1.5 * ma[:-1] + rng.normal(0, 0.5, n - 1)
    idx = pd.bdate_range("2010-01-01", periods=n)
    panel = pd.DataFrame({"x": x, "y": y}, index=idx)

    scan = band_scan(panel, [("x", "y")]).set_index("band")["p"]
    assert scan.nunique() > 1, "all bands identical — lag collapse regressed"
    low = min(scan["quarterly_1y"], scan["monthly_quarterly"])
    assert low < 0.01
    assert scan["sub_weekly"] > 0.05
    assert low < scan["sub_weekly"]


def test_bc_band_scan_raises_on_missing_column():
    """v1's second defect: pairs absent from the cohort panel were silently
    dropped, voiding the positive control. Must now raise."""
    from studylib.bcfreq import band_scan

    rng = np.random.default_rng(7)
    idx = pd.bdate_range("2015-01-01", periods=300)
    panel = pd.DataFrame({"a": rng.normal(0, 1, 300)}, index=idx)
    with pytest.raises(KeyError):
        band_scan(panel, [("a", "missing_col")])


def test_bc_silent_on_pure_noise_grid():
    from studylib.bcfreq import band_scan
    from prism.causality import _bh_qvalues

    fp_grids = 0
    for seed in range(8):
        rng = np.random.default_rng(100 + seed)
        idx = pd.bdate_range("2010-01-01", periods=2000)
        panel = pd.DataFrame(
            {c: rng.normal(0, 1, 2000) for c in ("a", "b", "c", "d")}, index=idx
        )
        scan = band_scan(panel, [("a", "b"), ("b", "a"), ("c", "d"), ("d", "c")])
        ok = scan["p"].notna()
        q = np.full(len(scan), np.nan)
        q[ok.to_numpy()] = _bh_qvalues(scan.loc[ok, "p"].to_numpy())
        if np.nansum(q < 0.10) > 0:
            fp_grids += 1
    assert fp_grids <= 2, f"{fp_grids}/8 noise grids had BH survivors"
