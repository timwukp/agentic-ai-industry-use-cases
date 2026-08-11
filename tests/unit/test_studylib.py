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
