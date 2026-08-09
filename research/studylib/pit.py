"""Point-in-time wrappers around frozen PRISM functions.

fit_regimes returns SMOOTHED probabilities (full-sample predict_proba) —
look-ahead if used for detection claims. These wrappers refit on expanding/
rolling windows and keep only the last-observation filtered value, so the
series at date t uses information ≤ t. PRISM itself is never modified.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))

from prism import fit_gpd_pot, fit_regimes  # noqa: E402


def pit_regime_probs(
    X: pd.DataFrame,
    min_train_years: int = 3,
    refit_freq: str = "ME",
    n_states: int = 3,
    seed: int = 7,
) -> pd.DataFrame:
    """Expanding-window monthly refits; between refits, the last fitted
    model's smoothed probability AT THE WINDOW END is carried forward for
    each new day by refitting the probability on data ≤ t via the stored
    month-end model? No — hmmlearn models can't filter incrementally
    without exposure to future data through re-smoothing. Pragmatic PIT
    scheme (pre-registered): refit at each month-end on data ≤ that date,
    take the smoothed probability of the LAST observation (which for the
    final row equals the filtered probability), and assign it to all days
    in the FOLLOWING month. Coarser than daily filtering but strictly
    point-in-time."""
    month_ends = X.resample(refit_freq).last().index
    start = X.index.min() + pd.DateOffset(years=min_train_years)
    labels = ["stress", "neutral", "risk-on"][:n_states]
    rows = []
    for i, me in enumerate(month_ends):
        if me < start:
            continue
        train = X.loc[:me]
        if len(train) < 250:
            continue
        try:
            res = fit_regimes(train, n_states=n_states, seed=seed)
            last_probs = res.state_probs.iloc[-1]
        except Exception:  # noqa: BLE001 — non-convergence on odd windows
            continue
        nxt = month_ends[i + 1] if i + 1 < len(month_ends) else X.index.max()
        days = X.index[(X.index > me) & (X.index <= nxt)]
        for d in days:
            rows.append({"date": d, **{k: float(last_probs[k]) for k in labels}})
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).set_index("date")


def rolling_var_series(
    returns: pd.Series,
    window_years: int = 5,
    refit_freq: str = "ME",
    threshold_q: float = 0.95,
    level: float = 0.99,
) -> pd.DataFrame:
    """Rolling GPD refit at month-ends on trailing window; the fitted VaR
    applies to every day of the FOLLOWING month (strictly out-of-sample).
    Returns DataFrame(date, var, violation) where violation = realized loss
    exceeded the pre-committed VaR."""
    r = returns.dropna()
    month_ends = r.resample(refit_freq).last().index
    rows = []
    for i, me in enumerate(month_ends):
        train = r.loc[me - pd.DateOffset(years=window_years) : me]
        if len(train) < 500:
            continue
        tr = fit_gpd_pot(train, threshold_q=threshold_q)
        if not np.isfinite(tr.var_99):
            continue
        var_val = tr.var_99 if level == 0.99 else tr.var_999
        nxt = month_ends[i + 1] if i + 1 < len(month_ends) else r.index.max()
        days = r.index[(r.index > me) & (r.index <= nxt)]
        for d in days:
            loss = -float(r.loc[d])
            rows.append({"date": d, "var": var_val, "violation": loss > var_val})
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).set_index("date")
