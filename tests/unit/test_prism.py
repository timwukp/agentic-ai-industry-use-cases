"""PRISM math on synthetic data with KNOWN ground truth.

Every test plants a property and asserts the model recovers it — the
mutation-check philosophy: a validator that cannot find planted truth
(or that finds truth in pure noise) is worse than none.

Skipped wholesale when the scientific stack is absent (CI runs the zip-only
env); the repo venv has it installed.
"""

import sys
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pd = pytest.importorskip("pandas")
pytest.importorskip("scipy")
pytest.importorskip("statsmodels")
pytest.importorskip("hmmlearn")

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))

from prism import (  # noqa: E402
    build_panel,
    causality_scan,
    confirm,
    ewma_sigma,
    factor_series,
    fit_gpd_by_regime,
    fit_gpd_pot,
    fit_regimes,
    fit_vol_filtered_var,
    granger_pvalue,
    local_projection,
    regime_conditional,
    te_pvalue,
    walk_forward,
)


# ---------------- fixtures: planted-truth simulators ----------------


def _regime_sim(n=2000, seed=11):
    """2-state sticky chain: calm (+0.1%, 0.5%) vs stress (-0.2%, 2%)."""
    rng = np.random.default_rng(seed)
    states = np.zeros(n, dtype=int)
    for t in range(1, n):
        stay = 0.97 if states[t - 1] == 0 else 0.94
        states[t] = states[t - 1] if rng.random() < stay else 1 - states[t - 1]
    mu = np.where(states == 0, 0.001, -0.002)
    sd = np.where(states == 0, 0.005, 0.02)
    ret = rng.normal(mu, sd)
    idx = pd.bdate_range("2018-01-01", periods=n)
    return pd.DataFrame({"ret": ret}, index=idx), states


def _causal_pair(n=1500, beta=0.6, seed=13):
    """y[t] = beta*x[t-1] + noise; x is AR(0.3)."""
    rng = np.random.default_rng(seed)
    x = np.zeros(n)
    for t in range(1, n):
        x[t] = 0.3 * x[t - 1] + rng.normal(0, 1)
    noise = rng.normal(0, 1, n)
    y = np.zeros(n)
    y[1:] = beta * x[:-1] + noise[1:]
    idx = pd.bdate_range("2018-01-01", periods=n)
    return pd.DataFrame({"x": x, "y": y}, index=idx)


# ---------------- regime ----------------


def test_hmm_recovers_planted_regimes():
    df, true_states = _regime_sim()
    res = fit_regimes(df, n_states=2)
    assert res.converged
    # label alignment: state 0 must be the worst-mean ("stress") by contract
    pred = (res.viterbi == "stress").to_numpy().astype(int)
    truth = (true_states == 1).astype(int)  # sim state 1 = stress
    acc = max((pred == truth).mean(), (pred != truth).mean())
    assert acc > 0.8
    assert res.state_means["stress"]["ret"] < res.state_means["risk-on"]["ret"]
    assert res.persistence["risk-on"] > 5  # sticky chain => multi-day duration


# ---------------- causality ----------------


def test_transfer_entropy_detects_planted_direction():
    df = _causal_pair()
    p_xy = te_pvalue(df.x.to_numpy(), df.y.to_numpy(), seed=5)
    p_yx = te_pvalue(df.y.to_numpy(), df.x.to_numpy(), seed=5)
    assert p_xy < 0.05
    assert p_yx > 0.05


def test_granger_same_direction():
    df = _causal_pair()
    assert granger_pvalue(df.x.to_numpy(), df.y.to_numpy(), maxlag=1) < 0.01
    assert granger_pvalue(df.y.to_numpy(), df.x.to_numpy(), maxlag=1) > 0.05


def test_bh_false_positive_rate_on_pure_noise_within_fdr_bound():
    """Under all-null, BH at q<0.10 bounds P(any false discovery) by ~q.
    The original zero-FP assertion encoded the max-rule's over-conservatism
    (power 10-55% on realistic effects — validation study H2 audit), not a
    theoretical guarantee. Fisher combination restores power; this test
    checks the actual FDR contract across seeds: few grids may show one
    discovery, most must show none."""
    grids_with_fp = 0
    n_seeds = 8
    for seed in range(n_seeds):
        rng = np.random.default_rng(100 + seed)
        idx = pd.bdate_range("2018-01-01", periods=800)
        panel = pd.DataFrame(
            {f"n{i}": rng.normal(0, 1, 800) for i in range(8)}, index=idx
        )
        scan = causality_scan(
            panel, sources=["n0", "n1", "n2", "n3"], targets=["n4", "n5", "n6", "n7"]
        )
        if int(scan["significant"].sum()) > 0:
            grids_with_fp += 1
    # binomial(8, 0.10): P(>=3) < 4% — 3+ signals a broken FDR control
    assert grids_with_fp <= 2, f"{grids_with_fp}/{n_seeds} noise grids had discoveries"


def test_scan_finds_planted_edge_amid_noise():
    df = _causal_pair()
    rng = np.random.default_rng(4)
    df["z"] = rng.normal(0, 1, len(df))
    scan = causality_scan(df, sources=["x", "z"], targets=["y"], horizons=(1,))
    planted = scan[(scan.source == "x") & (scan.horizon == 1)]
    assert bool(planted["significant"].iloc[0])
    noise = scan[(scan.source == "z")]
    assert not noise["significant"].any()


# ---------------- impact ----------------


def test_local_projection_recovers_planted_response():
    # y responds to x with a decaying impulse: 0.5, 0.3, 0.15 at lags 1..3
    rng = np.random.default_rng(21)
    n = 2000
    x = rng.normal(0, 1, n)
    y = np.zeros(n)
    for t in range(3, n):
        y[t] = 0.5 * x[t - 1] + 0.3 * x[t - 2] + 0.15 * x[t - 3] + rng.normal(0, 0.5)
    idx = pd.bdate_range("2015-01-01", periods=n)
    panel = pd.DataFrame({"x": x, "y": y}, index=idx)
    imp = local_projection(panel, "x", "y", horizons=range(1, 6))
    # cumulative truth at each horizon (x has unit variance already)
    truth = [0.5, 0.8, 0.95, 0.95, 0.95]
    for h_i, (b, (lo95, hi95)) in enumerate(zip(imp.beta_mean, imp.band95)):
        assert hi95 > lo95  # bands have width
        # posterior mean within a loose tolerance of planted cumulative effect
        assert abs(b - truth[h_i]) < 0.25, f"h={h_i+1}: {b} vs {truth[h_i]}"
    assert imp.prob_positive_20d > 0.9


def test_credible_bands_calibrated_at_daily_return_scale():
    # The sigma^2 prior must not dominate when the response is daily-return
    # magnitude (~1e-2): an absolute-scale prior inflated 95% bands ~3x at
    # h=1. Guard: band half-width stays within 30% of the frequentist oracle
    # 1.96 * sqrt(h) * sigma / sqrt(n) at the scale the pipeline actually runs.
    n, sigma, beta = 2600, 0.01, 0.002
    horizons = [1, 5]
    for seed in (7, 21, 42):
        rng = np.random.default_rng(seed)
        shock = rng.normal(0, 1, n)
        eps = rng.normal(0, sigma, n)
        resp = beta * np.roll(shock, 1) + eps
        resp[0] = eps[0]
        idx = pd.bdate_range("2015-01-01", periods=n)
        panel = pd.DataFrame({"x": shock, "y": resp}, index=idx)
        imp = local_projection(panel, "x", "y", horizons=horizons)
        for h_i, h in enumerate(horizons):
            lo95, hi95 = imp.band95[h_i]
            half = (hi95 - lo95) / 2
            oracle = 1.96 * np.sqrt(h) * sigma / np.sqrt(n)
            assert half < 1.3 * oracle, (
                f"seed={seed} h={h}: band half-width {half:.5f} vs oracle "
                f"{oracle:.5f} — sigma^2 prior is dominating again"
            )
            # lower bound too: a collapsed prior would shrink bands BELOW the
            # frequentist floor, silently overstating certainty
            assert half > 0.7 * oracle, (
                f"seed={seed} h={h}: band half-width {half:.5f} suspiciously "
                f"narrow vs oracle {oracle:.5f}"
            )


def test_constant_response_is_refused_not_certain():
    # A stale/forward-filled (constant) response carries no information; the
    # honest output is the NaN refusal path, never a near-zero-width band
    # presented as certainty.
    rng = np.random.default_rng(5)
    n = 500
    panel = pd.DataFrame(
        {"x": rng.normal(0, 1, n), "y": np.full(n, 0.0123)},
        index=pd.bdate_range("2019-01-01", periods=n),
    )
    imp = local_projection(panel, "x", "y", horizons=[1, 5])
    for b, (lo, hi) in zip(imp.beta_mean, imp.band95):
        assert np.isnan(b) and np.isnan(lo) and np.isnan(hi)
    assert np.isnan(imp.prob_positive_20d)


def test_regime_conditional_counts_effective_sample():
    # A regime active ~5% of days holds ~5% of the information but 100% of
    # the rows; without the n_eff correction the sigma^2 update divides by n
    # and shrinks bands ~sqrt(20)x too far. Guard: weighted bands stay within
    # a factor ~2 of a fit on the in-regime rows alone.
    rng = np.random.default_rng(11)
    n = 4000
    x = rng.normal(0, 1, n)
    y = 0.002 * np.roll(x, 1) + rng.normal(0, 0.01, n)
    y[0] = 0.0
    idx = pd.bdate_range("2010-01-01", periods=n)
    panel = pd.DataFrame({"x": x, "y": y}, index=idx)
    probs = pd.Series(0.0, index=idx)
    probs.iloc[::20] = 1.0  # hard 5% regime
    imp_w = regime_conditional(panel, "x", "y", probs, horizons=[1])
    imp_sub = local_projection(panel[probs == 1.0], "x", "y", horizons=[1])
    hw_w = (imp_w.band95[0][1] - imp_w.band95[0][0]) / 2
    hw_sub = (imp_sub.band95[0][1] - imp_sub.band95[0][0]) / 2
    ratio = hw_w / hw_sub
    assert 0.4 < ratio < 2.5, (
        f"weighted/in-regime band ratio {ratio:.3f} — effective-sample "
        "correction is broken (old bug gave ~0.05)"
    )


# ---------------- tails ----------------


def test_gpd_recovers_heavy_tail_from_student_t():
    rng = np.random.default_rng(31)
    ret = pd.Series(rng.standard_t(3, 5000) * 0.01)
    tr = fit_gpd_pot(ret)
    assert tr.valid
    assert 0.1 < tr.xi < 0.7  # t(3) tail index ~ 1/3
    losses = -ret
    assert tr.var_99 > float(np.quantile(losses, 0.95))
    assert tr.es_99 > tr.var_99


def test_regime_conditional_gpd_separates_planted_tails():
    """Two planted regimes with different tail fatness: the conditional fit
    must recover a fatter tail in the stress state than the calm state —
    the property the validation study's H4/H8 failures demand."""
    rng = np.random.default_rng(17)
    n = 4000
    # calm: thin normal tail; stress: fat t(2.5) tail, in two long blocks
    stress_mask = np.zeros(n, dtype=bool)
    stress_mask[1000:1800] = True
    stress_mask[3000:3600] = True
    ret = np.where(
        stress_mask,
        rng.standard_t(2.5, n) * 0.02,
        rng.normal(0, 0.005, n),
    )
    idx = pd.bdate_range("2010-01-01", periods=n)
    returns = pd.Series(ret, index=idx)
    probs = pd.DataFrame(
        {
            "stress": stress_mask.astype(float),
            "risk-on": (~stress_mask).astype(float),
        },
        index=idx,
    )
    by = fit_gpd_by_regime(returns, probs)
    assert by["stress"].valid and by["risk-on"].valid
    # stress tail must be fatter AND its VaR materially larger
    assert by["stress"].xi > by["risk-on"].xi
    assert by["stress"].var_99 > 2 * by["risk-on"].var_99


def test_ewma_sigma_is_strictly_causal_and_tracks_vol():
    rng = np.random.default_rng(23)
    n = 2000
    # planted vol step: sigma jumps 4x at midpoint
    sd = np.where(np.arange(n) < n // 2, 0.005, 0.02)
    r = pd.Series(rng.normal(0, sd), index=pd.bdate_range("2018-01-01", periods=n))
    sigma = ewma_sigma(r)
    # causality: sigma at the step day must NOT yet reflect the step
    assert sigma.iloc[n // 2] < 0.010
    # adaptation: within ~30 days the filter reaches the new level
    assert sigma.iloc[n // 2 + 30] > 0.013
    # long-run levels approximately correct in both halves
    assert abs(sigma.iloc[n // 4] - 0.005) < 0.002
    assert abs(sigma.iloc[-1] - 0.02) < 0.006


def test_vol_filtered_var_calibrates_on_planted_garch():
    """Back-to-back on synthetic vol-clustered returns: violations ~1%."""
    rng = np.random.default_rng(29)
    n = 3000
    sigma = np.zeros(n)
    r = np.zeros(n)
    sigma[0] = 0.01
    for t in range(1, n):
        # GARCH(1,1)-ish: strong clustering
        sigma[t] = np.sqrt(
            0.02 * 0.01**2 + 0.10 * r[t - 1] ** 2 + 0.88 * sigma[t - 1] ** 2
        )
        r[t] = rng.normal(0, sigma[t])
    returns = pd.Series(r, index=pd.bdate_range("2014-01-01", periods=n))
    out = fit_vol_filtered_var(returns)
    assert out["valid"]
    # OOS-style check on the last 500 days using the frozen quantile
    sig = ewma_sigma(returns)
    z_q = out["var_99"] / out["sigma_next"]  # recovered residual quantile
    var_series = sig.iloc[-500:] * z_q
    losses = -returns.iloc[-500:]
    rate = float((losses > var_series).mean())
    assert 0.002 < rate < 0.03  # near the 1% target, not wildly off


def test_regime_conditional_gpd_rejects_thin_slices():
    rng = np.random.default_rng(18)
    n = 1000
    returns = pd.Series(
        rng.normal(0, 0.01, n), index=pd.bdate_range("2020-01-01", periods=n)
    )
    probs = pd.DataFrame(
        {"stress": np.full(n, 0.05), "risk-on": np.full(n, 0.95)},
        index=returns.index,
    )
    by = fit_gpd_by_regime(returns, probs, min_weight_days=250)
    assert by["stress"].valid is False  # 5% of 1000 days is not enough
    assert by["risk-on"].valid is True


# ---------------- validation ----------------


def test_walk_forward_confirms_planted_and_rejects_noise():
    df = _causal_pair(n=2500)
    wf = walk_forward(df, "x", "y", train_years=3, test_months=6, horizon=1)
    assert len(wf) >= 4
    scan_row = {"q_value": 0.01}
    assert confirm(scan_row, wf) == "CONFIRMED"

    rng = np.random.default_rng(41)
    noise = pd.DataFrame(
        {"x": rng.normal(0, 1, 2500), "y": rng.normal(0, 1, 2500)},
        index=pd.bdate_range("2015-01-01", periods=2500),
    )
    wf_noise = walk_forward(noise, "x", "y", train_years=3, test_months=6, horizon=1)
    # noise fails EITHER at the q-gate or the OOS gate
    assert confirm({"q_value": 0.5}, wf_noise) == "HYPOTHESIS"
    assert confirm({"q_value": None}, wf_noise) == "HYPOTHESIS"


# ---------------- data ----------------


def test_build_panel_ffill_policy():
    rows = {
        "A": [
            {"date": "2026-01-05", "value": 1.0},
            {"date": "2026-01-12", "value": 2.0},
        ],
        "B": [
            {"date": d.strftime("%Y-%m-%d"), "value": float(i)}
            for i, d in enumerate(pd.bdate_range("2026-01-05", "2026-01-12"))
        ],
    }
    panel = build_panel(rows)
    # A forward-fills the gap week (<=5 bdays), so all B days survive
    assert len(panel) == 6
    assert panel["A"].iloc[2] == 1.0


def test_factor_series_tiny_input_ok():
    rows = [
        {"date": "2026-08-08", "factor": "war-conflict", "loading": 0.4},
        {"date": "2026-08-09", "factor": "war-conflict", "loading": 0.5},
    ]
    fs = factor_series(rows)
    assert len(fs) == 2
    assert factor_series([]).empty
