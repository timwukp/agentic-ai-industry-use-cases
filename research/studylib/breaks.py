"""Structural break test: sup-Chow (Quandt-Andrews) with 15% trimming.

Deliberately not full Bai-Perron — the pre-registered era splits carry the
main stability burden (protocol §H7); sup-Chow supplements them with an
agnostic single-break scan. Critical values: Andrews (1993) Table 1
approximations for common regressor counts.
"""

import numpy as np

# Andrews (1993) 5% critical values for sup-Wald with 15% trimming, by
# number of coefficients tested (k = 1..5).
_ANDREWS_CV_5PCT = {1: 8.85, 2: 11.79, 3: 14.15, 4: 16.45, 5: 18.35}


def _ols_ssr(X: np.ndarray, y: np.ndarray) -> float:
    beta, *_ = np.linalg.lstsq(X, y, rcond=None)
    resid = y - X @ beta
    return float(resid @ resid)


def sup_chow(y: np.ndarray, X: np.ndarray, trim: float = 0.15) -> dict:
    """Sup-Chow over candidate breakpoints in the trimmed interior.

    Returns the max Chow F-statistic (Wald form: k * F), its location, and
    whether it exceeds the Andrews 5% critical value.
    """
    y = np.asarray(y, float)
    X = np.atleast_2d(np.asarray(X, float))
    if X.shape[0] != len(y):
        X = X.T
    n, k = X.shape
    lo, hi = int(n * trim), int(n * (1 - trim))
    if hi - lo < 10 or n < 40:
        return {"sup_wald": np.nan, "break_idx": None, "reject_5pct": None}

    ssr_full = _ols_ssr(X, y)
    best_w, best_i = -np.inf, None
    for i in range(lo, hi):
        ssr1 = _ols_ssr(X[:i], y[:i])
        ssr2 = _ols_ssr(X[i:], y[i:])
        denom = (ssr1 + ssr2) / max(1, n - 2 * k)
        if denom <= 0:
            continue
        wald = (ssr_full - ssr1 - ssr2) / denom
        if wald > best_w:
            best_w, best_i = wald, i
    cv = _ANDREWS_CV_5PCT.get(min(k, 5), 18.35)
    return {
        "sup_wald": float(best_w),
        "break_idx": best_i,
        "cv_5pct": cv,
        "reject_5pct": bool(best_w > cv),
    }
