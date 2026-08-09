"""Lead-lag discovery: transfer entropy + Granger, BH-controlled.

The combined p-value per edge is max(TE p, Granger p) — an edge must look
causal to BOTH a nonlinear information measure and a linear predictive test.
Conservative by design: the cost of a false CONFIRMED (someone trades on it)
far exceeds the cost of a missed edge (it stays HYPOTHESIS a while longer).
"""

import numpy as np
import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests


def _quantile_bins(v: np.ndarray, bins: int) -> np.ndarray:
    edges = np.quantile(v, np.linspace(0, 1, bins + 1)[1:-1])
    return np.digitize(v, edges)


def transfer_entropy(
    x: np.ndarray, y: np.ndarray, bins: int = 6, lag: int = 1
) -> float:
    """TE(x -> y) in nats: I(y_t ; x_{t-lag} | y_{t-lag}), quantile-binned."""
    x, y = np.asarray(x, float), np.asarray(y, float)
    n = min(len(x), len(y))
    if n < 100:
        return float("nan")
    x, y = x[:n], y[:n]
    xb, yb = _quantile_bins(x, bins), _quantile_bins(y, bins)

    yt, ylag, xlag = yb[lag:], yb[:-lag], xb[:-lag]
    m = len(yt)

    def counts(*arrs):
        key = np.stack(arrs, axis=1)
        _, inv, cnt = np.unique(key, axis=0, return_inverse=True, return_counts=True)
        return cnt[inv] / m

    p_yyx = counts(yt, ylag, xlag)
    p_yx = counts(ylag, xlag)
    p_yy = counts(yt, ylag)
    p_y = counts(ylag)
    # TE = E[log( p(yt|ylag,xlag) / p(yt|ylag) )]
    te = np.mean(np.log((p_yyx * p_y) / (p_yx * p_yy)))
    return float(max(0.0, te))


def te_pvalue(
    x: np.ndarray,
    y: np.ndarray,
    n_boot: int = 200,
    block: int = 20,
    seed: int = 7,
    bins: int = 6,
    lag: int = 1,
) -> float:
    """Block-bootstrap null: shuffle x in blocks (preserves its autocorrelation
    while destroying cross-dependence), p = P(null TE >= observed)."""
    obs = transfer_entropy(x, y, bins=bins, lag=lag)
    if np.isnan(obs):
        return float("nan")
    rng = np.random.default_rng(seed)
    x = np.asarray(x, float)
    n = len(x)
    n_blocks = int(np.ceil(n / block))
    ge = 0
    for _ in range(n_boot):
        starts = rng.integers(0, n - block + 1, size=n_blocks)
        xs = np.concatenate([x[s : s + block] for s in starts])[:n]
        if transfer_entropy(xs, y, bins=bins, lag=lag) >= obs:
            ge += 1
    return (ge + 1) / (n_boot + 1)


def granger_pvalue(x: np.ndarray, y: np.ndarray, maxlag: int) -> float:
    """ssr F-test p-value for 'x Granger-causes y' at the given lag."""
    df = pd.DataFrame({"y": np.asarray(y, float), "x": np.asarray(x, float)}).dropna()
    if len(df) < 20 * maxlag:
        return float("nan")
    try:
        res = grangercausalitytests(df[["y", "x"]], maxlag=[maxlag], verbose=False)
        return float(res[maxlag][0]["ssr_ftest"][1])
    except Exception:  # noqa: BLE001 — singular matrices on degenerate input
        return float("nan")


def _bh_qvalues(pvals: np.ndarray) -> np.ndarray:
    """Benjamini-Hochberg adjusted p-values (monotone step-up)."""
    n = len(pvals)
    order = np.argsort(pvals)
    ranked = pvals[order] * n / (np.arange(n) + 1)
    ranked = np.minimum.accumulate(ranked[::-1])[::-1]
    q = np.empty(n)
    q[order] = np.minimum(ranked, 1.0)
    return q


def causality_scan(
    panel: pd.DataFrame,
    sources: list[str],
    targets: list[str],
    horizons: tuple = (1, 5, 20),
    q_threshold: float = 0.10,
    seed: int = 7,
) -> pd.DataFrame:
    """All source->target x horizon edges, BH-controlled across the FULL grid.

    BH runs over every hypothesis ever tested in the scan — controlling FDR
    per-pair instead would let the grid size silently inflate false positives.
    """
    rows = []
    for src in sources:
        for tgt in targets:
            if src == tgt or src not in panel or tgt not in panel:
                continue
            x, y = panel[src].to_numpy(), panel[tgt].to_numpy()
            for h in horizons:
                te = transfer_entropy(x, y, lag=h)
                te_p = te_pvalue(x, y, seed=seed, lag=h)
                g_p = granger_pvalue(x, y, maxlag=h)
                combined = np.nanmax([te_p, g_p])
                rows.append(
                    {
                        "source": src,
                        "target": tgt,
                        "horizon": h,
                        "te": round(te, 6) if not np.isnan(te) else None,
                        "te_p": round(te_p, 4) if not np.isnan(te_p) else None,
                        "granger_p": round(g_p, 4) if not np.isnan(g_p) else None,
                        "p_combined": combined,
                    }
                )
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    valid = df["p_combined"].notna()
    q = np.full(len(df), np.nan)
    if valid.any():
        q[valid.to_numpy()] = _bh_qvalues(df.loc[valid, "p_combined"].to_numpy())
    df["q_value"] = q
    df["significant"] = df["q_value"] < q_threshold
    df["p_combined"] = df["p_combined"].round(4)
    df["q_value"] = df["q_value"].round(4)
    return df
