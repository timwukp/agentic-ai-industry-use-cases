"""Breitung-Candelon (2006) frequency-domain Granger causality.

Tests H0: x does not Granger-cause y AT frequency omega, within a bivariate
VAR(p) for (y, x). BC's insight: the spectral non-causality condition
|sum_k a_k e^{-ik omega}| = 0 (a_k = coefficients of x-lags in the y
equation) is equivalent to TWO linear restrictions on the a_k:

    sum_k a_k cos(k omega) = 0   and   sum_k a_k sin(k omega) = 0

so an ordinary F-test on the restricted vs unrestricted y-equation does the
job. Pure statsmodels/numpy; self-calibration gates in test_studylib.py.
"""

import numpy as np
import pandas as pd
from scipy import stats


def bc_freq_pvalue(
    y: np.ndarray, x: np.ndarray, omega: float, p: int | None = None, p_max: int = 22
) -> float:
    """P-value of BC's F-test for 'x does not cause y at frequency omega'.

    y, x: stationary series (returns/diffs). p: VAR lag order (BIC-chosen
    over 1..p_max when None). omega in (0, pi).
    """
    y = np.asarray(y, float)
    x = np.asarray(x, float)
    n = min(len(y), len(x))
    y, x = y[:n], x[:n]

    if p is None:
        p = _bic_lag(y, x, p_max)

    # unrestricted y-equation: y_t on [1, y_{t-1..t-p}, x_{t-1..t-p}]
    T = n - p
    if T < 10 * p:
        return float("nan")
    Y = y[p:]
    cols = [np.ones(T)]
    for k in range(1, p + 1):
        cols.append(y[p - k : n - k])
    for k in range(1, p + 1):
        cols.append(x[p - k : n - k])
    X = np.column_stack(cols)

    beta, *_ = np.linalg.lstsq(X, Y, rcond=None)
    resid_u = Y - X @ beta
    ssr_u = float(resid_u @ resid_u)

    # restrictions: R beta = 0, on the x-lag block (last p coefficients)
    R = np.zeros((2, X.shape[1]))
    for k in range(1, p + 1):
        R[0, 1 + p + (k - 1)] = np.cos(k * omega)
        R[1, 1 + p + (k - 1)] = np.sin(k * omega)
    # at omega=pi the sine row vanishes -> rank 1
    ranks = np.linalg.matrix_rank(R)
    q = int(ranks)
    if q == 0:
        return float("nan")

    # F-test via restricted least squares (Amemiya form)
    XtX_inv = np.linalg.pinv(X.T @ X)
    Rb = R @ beta
    middle = np.linalg.pinv(R @ XtX_inv @ R.T)
    ssr_diff = float(Rb.T @ middle @ Rb)
    dof = T - X.shape[1]
    if dof <= 0 or ssr_u <= 0:
        return float("nan")
    F = (ssr_diff / q) / (ssr_u / dof)
    return float(stats.f.sf(F, q, dof))


def _bic_lag(y: np.ndarray, x: np.ndarray, p_max: int) -> int:
    n = len(y)
    best_p, best_bic = 1, np.inf
    for p in range(1, p_max + 1):
        T = n - p
        Y = y[p:]
        cols = [np.ones(T)]
        for k in range(1, p + 1):
            cols.append(y[p - k : n - k])
        for k in range(1, p + 1):
            cols.append(x[p - k : n - k])
        X = np.column_stack(cols)
        beta, *_ = np.linalg.lstsq(X, Y, rcond=None)
        ssr = float(np.sum((Y - X @ beta) ** 2))
        if ssr <= 0:
            continue
        bic = T * np.log(ssr / T) + X.shape[1] * np.log(T)
        if bic < best_bic:
            best_bic, best_p = bic, p
    return best_p


# Pre-registered bands (radians/day), 3 grid points each — protocol §Method.
BANDS = {
    "over_1y": (0.005, 0.015, 0.025),
    "quarterly_1y": (0.03, 0.06, 0.10),
    "monthly_quarterly": (0.12, 0.20, 0.30),
    "weekly_monthly": (0.40, 0.80, 1.25),
    "sub_weekly": (1.5, 2.2, 3.0),
}


def band_scan(panel: pd.DataFrame, pairs: list[tuple[str, str]]) -> pd.DataFrame:
    """BC p-value per (pair, band): band p = max over its grid points
    (conservative — the whole band must show causality)."""
    rows = []
    for src, tgt in pairs:
        y = panel[tgt].to_numpy()
        x = panel[src].to_numpy()
        p_lag = _bic_lag(y, x, 22)
        for band, omegas in BANDS.items():
            ps = [bc_freq_pvalue(y, x, w, p=p_lag) for w in omegas]
            ps = [p for p in ps if not np.isnan(p)]
            rows.append(
                {
                    "source": src,
                    "target": tgt,
                    "band": band,
                    "p": max(ps) if ps else np.nan,
                    "var_lag": p_lag,
                }
            )
    return pd.DataFrame(rows)
