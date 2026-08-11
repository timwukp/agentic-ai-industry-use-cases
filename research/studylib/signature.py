"""Depth-2 signature (Lévy area) features for the signature regime test.

The Lévy area A(x,y) over a window is the antisymmetric depth-2 term of the
path signature — the only depth-2 content not already spanned by levels and
squares. Positive area = x tends to lead y around the loop; it captures
lead-lag/rotational structure invisible to pointwise features.

Strictly causal by construction: the window at date t ends at t, and the
z-scoring baseline is shifted one day.
"""

import numpy as np
import pandas as pd


def levy_area(x: pd.Series, y: pd.Series, window: int = 22) -> pd.Series:
    """Rolling Lévy area of the cumulative paths of two increment series.

    A_t = 0.5 * sum_{s in window} (X_s dy_s - Y_s dx_s), computed on paths
    X, Y re-based to zero at the window start (translation invariance of
    the area integral).
    """
    dx = x.fillna(0.0).to_numpy()
    dy = y.fillna(0.0).to_numpy()
    X = np.cumsum(dx)
    Y = np.cumsum(dy)
    n = len(dx)
    out = np.full(n, np.nan)
    for t in range(window, n):
        sl = slice(t - window + 1, t + 1)
        Xw = X[sl] - X[t - window]
        Yw = Y[sl] - Y[t - window]
        dxw = dx[sl]
        dyw = dy[sl]
        # midpoint (Stratonovich-style) increments for path-integral fidelity
        Xm = Xw - 0.5 * dxw
        Ym = Yw - 0.5 * dyw
        out[t] = 0.5 * float(np.sum(Xm * dyw - Ym * dxw))
    return pd.Series(out, index=x.index, name=f"levy_{x.name}_{y.name}")


def zscore_causal(s: pd.Series, window: int = 250) -> pd.Series:
    """Z-score vs trailing window statistics, shifted 1 day (no same-day
    leakage into the baseline)."""
    mu = s.rolling(window).mean().shift(1)
    sd = s.rolling(window).std().shift(1)
    return ((s - mu) / sd.replace(0, np.nan)).clip(-8, 8)


def signature_features(panel: pd.DataFrame, window: int = 22) -> pd.DataFrame:
    """The protocol's three depth-2 features from the market panel.

    Pairs: (equity, vol-proxy), (equity, slope), (vol-proxy, slope) —
    vol-proxy is VIXCLS_diff when present, else |NASDAQCOM_ret|.
    """
    eq = panel["NASDAQCOM_ret"]
    slope = panel["slope_diff"]
    vol = panel["VIXCLS_diff"] if "VIXCLS_diff" in panel else eq.abs().rename("absret")
    feats = pd.DataFrame(index=panel.index)
    feats["sig_eq_vol"] = zscore_causal(levy_area(eq, vol, window))
    feats["sig_eq_slope"] = zscore_causal(levy_area(eq, slope, window))
    feats["sig_vol_slope"] = zscore_causal(levy_area(vol, slope, window))
    return feats
