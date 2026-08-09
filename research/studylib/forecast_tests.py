"""Forecast comparison: Diebold-Mariano (HAC + Harvey) and Hansen SPA.

References: Diebold & Mariano (1995); Harvey, Leybourne & Newbold (1997);
Hansen (2005) "A Test for Superior Predictive Ability"; White (2000).
Stationary bootstrap follows Politis & Romano (1994) — same idiom as
PRISM's te_pvalue block bootstrap.
"""

import numpy as np
from scipy import stats


def diebold_mariano(loss_a: np.ndarray, loss_b: np.ndarray, horizon: int = 1) -> dict:
    """DM test on the loss differential d = loss_a - loss_b.
    Negative statistic => a beats b. Newey-West HAC with lag = horizon-1,
    Harvey et al. small-sample correction, t distribution with n-1 df."""
    d = np.asarray(loss_a, float) - np.asarray(loss_b, float)
    d = d[~np.isnan(d)]
    n = len(d)
    if n < 10:
        return {"dm": np.nan, "p": np.nan, "n": n}
    dbar = d.mean()
    lags = max(0, horizon - 1)
    gamma0 = np.var(d, ddof=0)
    var_d = gamma0
    for k in range(1, lags + 1):
        w = 1.0 - k / (lags + 1)
        cov = np.mean((d[k:] - dbar) * (d[:-k] - dbar))
        var_d += 2.0 * w * cov
    var_d = max(var_d, 1e-16)
    dm = dbar / np.sqrt(var_d / n)
    # Harvey small-sample adjustment
    h = horizon
    adj = np.sqrt((n + 1 - 2 * h + h * (h - 1) / n) / n)
    dm_adj = dm * adj
    p = 2.0 * stats.t.sf(abs(dm_adj), df=n - 1)
    return {"dm": float(dm_adj), "p": float(p), "n": n, "mean_diff": float(dbar)}


def _stationary_bootstrap_indices(n: int, block: int, rng) -> np.ndarray:
    """Politis-Romano stationary bootstrap index sequence of length n."""
    p_new = 1.0 / block
    idx = np.empty(n, dtype=int)
    idx[0] = rng.integers(n)
    for t in range(1, n):
        if rng.random() < p_new:
            idx[t] = rng.integers(n)
        else:
            idx[t] = (idx[t - 1] + 1) % n
    return idx


def spa_test(
    performance: np.ndarray,
    n_boot: int = 1000,
    block: int = 20,
    seed: int = 7,
) -> dict:
    """Hansen SPA consistent p-value.

    performance: (T, K) matrix of period returns (net of costs) for K
    candidate strategies vs the zero-skill benchmark (benchmark return
    already subtracted, i.e. these ARE the relative performances).
    H0: no strategy has positive expected relative performance.
    """
    perf = np.atleast_2d(np.asarray(performance, float))
    if perf.shape[0] < perf.shape[1] and perf.shape[0] < 30:
        perf = perf.T
    T, K = perf.shape
    if T < 30 or K == 0:
        return {"t_spa": np.nan, "p": np.nan, "T": T, "K": K}

    mu = perf.mean(axis=0)
    omega = perf.std(axis=0, ddof=1) / np.sqrt(T)
    omega = np.where(omega <= 0, 1e-12, omega)
    t_stats = mu / omega
    t_spa = max(0.0, float(t_stats.max()))

    # Hansen's recentering: mu_k kept only if not "too negative"
    threshold = -np.sqrt(2.0 * np.log(np.log(max(T, 3)))) * omega
    mu_center = np.where(mu >= threshold, mu, 0.0)

    rng = np.random.default_rng(seed)
    exceed = 0
    for _ in range(n_boot):
        idx = _stationary_bootstrap_indices(T, block, rng)
        boot = perf[idx]
        mu_b = boot.mean(axis=0) - mu_center  # recentered under H0
        omega_b = boot.std(axis=0, ddof=1) / np.sqrt(T)
        omega_b = np.where(omega_b <= 0, 1e-12, omega_b)
        t_b = max(0.0, float((mu_b / omega_b).max()))
        if t_b >= t_spa:
            exceed += 1
    return {
        "t_spa": t_spa,
        "p": (exceed + 1) / (n_boot + 1),
        "T": T,
        "K": K,
        "best_k": int(np.argmax(t_stats)),
        "best_mean": float(mu.max()),
    }
