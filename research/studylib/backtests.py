"""VaR backtesting: Kupiec POF, Christoffersen, Basel traffic light.

Standard references: Kupiec (1995), Christoffersen (1998), Basel Committee
(1996 supervisory framework). Pure numpy/scipy.
"""

import numpy as np
from scipy.stats import chi2


def kupiec_pof(violations: np.ndarray, alpha: float = 0.01) -> dict:
    """Proportion-of-failures LR test. violations: boolean array (1 = loss
    exceeded VaR). H0: violation probability == alpha."""
    v = np.asarray(violations, dtype=bool)
    n, x = len(v), int(v.sum())
    if n == 0:
        return {"n": 0, "violations": 0, "rate": np.nan, "lr": np.nan, "p": np.nan}
    pi_hat = x / n
    if x == 0:
        lr = -2.0 * n * np.log(1 - alpha)
    elif x == n:
        lr = -2.0 * n * np.log(alpha)
    else:
        lr = -2.0 * (
            x * np.log(alpha / pi_hat) + (n - x) * np.log((1 - alpha) / (1 - pi_hat))
        )
    return {
        "n": n,
        "violations": x,
        "rate": pi_hat,
        "lr": float(lr),
        "p": float(chi2.sf(lr, df=1)),
    }


def christoffersen_independence(violations: np.ndarray) -> dict:
    """LR test of first-order independence of violations (clustering)."""
    v = np.asarray(violations, dtype=int)
    if len(v) < 2:
        return {"lr": np.nan, "p": np.nan}
    pairs = np.stack([v[:-1], v[1:]], axis=1)
    n00 = int(((pairs[:, 0] == 0) & (pairs[:, 1] == 0)).sum())
    n01 = int(((pairs[:, 0] == 0) & (pairs[:, 1] == 1)).sum())
    n10 = int(((pairs[:, 0] == 1) & (pairs[:, 1] == 0)).sum())
    n11 = int(((pairs[:, 0] == 1) & (pairs[:, 1] == 1)).sum())
    if (n01 + n11) == 0:  # no violations at all — independence vacuous
        return {"lr": 0.0, "p": 1.0}
    pi01 = n01 / max(1, n00 + n01)
    pi11 = n11 / max(1, n10 + n11)
    pi = (n01 + n11) / max(1, n00 + n01 + n10 + n11)

    def _ll(p, k, n_):
        if p in (0.0, 1.0):
            return 0.0
        return k * np.log(p) + (n_ - k) * np.log(1 - p)

    ll_h0 = _ll(pi, n01 + n11, n00 + n01 + n10 + n11)
    ll_h1 = _ll(pi01, n01, n00 + n01) + _ll(pi11, n11, n10 + n11)
    lr = -2.0 * (ll_h0 - ll_h1)
    return {"lr": float(max(0.0, lr)), "p": float(chi2.sf(max(0.0, lr), df=1))}


def conditional_coverage(violations: np.ndarray, alpha: float = 0.01) -> dict:
    """Christoffersen conditional coverage: POF + independence jointly."""
    pof = kupiec_pof(violations, alpha)
    ind = christoffersen_independence(violations)
    if np.isnan(pof["lr"]) or np.isnan(ind["lr"]):
        return {"lr": np.nan, "p": np.nan, "pof": pof, "independence": ind}
    lr = pof["lr"] + ind["lr"]
    return {
        "lr": float(lr),
        "p": float(chi2.sf(lr, df=2)),
        "pof": pof,
        "independence": ind,
    }


def basel_traffic_light(violations: np.ndarray, alpha: float = 0.01) -> str:
    """Basel zones scaled from the canonical 250-day/99% design: green ≤
    binomial 95th pct, red > 99.99th pct, amber between."""
    from scipy.stats import binom

    v = np.asarray(violations, dtype=bool)
    n, x = len(v), int(v.sum())
    if n == 0:
        return "no-data"
    green_max = int(binom.ppf(0.95, n, alpha))
    red_min = int(binom.ppf(0.9999, n, alpha)) + 1
    if x <= green_max:
        return "green"
    if x >= red_min:
        return "red"
    return "amber"
