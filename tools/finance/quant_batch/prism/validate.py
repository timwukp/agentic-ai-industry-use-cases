"""Validation protocol: walk-forward out-of-sample + CONFIRMED gate.

CONFIRMED is deliberately hard to earn: FDR-surviving in-sample significance
AND a positive out-of-sample edge over an AR(1) baseline in >= 70% of folds.
An empty CONFIRMED list early on is the expected, honest state.
"""

import numpy as np
import pandas as pd

from .impact import local_projection


def _ar1_forecast(train: pd.Series, test: pd.Series, horizon: int) -> np.ndarray:
    """AR(1)-implied cumulative h-step forecast, sign only is compared."""
    r = train.dropna()
    if len(r) < 30 or r.std(ddof=0) == 0:
        return np.zeros(len(test))
    phi = float(r.autocorr(lag=1) or 0.0)
    # cumulative h-step ahead from current value: r_t * (phi + ... + phi^h)
    mult = sum(phi**k for k in range(1, horizon + 1))
    return test.to_numpy() * mult


def walk_forward(
    panel: pd.DataFrame,
    shock_col: str,
    response_col: str,
    train_years: int = 3,
    test_months: int = 6,
    horizon: int = 5,
) -> pd.DataFrame:
    """Expanding-window walk-forward: fit local projection on train, predict
    the sign of the h-day cumulated response on test, score vs baselines."""
    idx = panel.index
    start = idx.min()
    first_cut = start + pd.DateOffset(years=train_years)
    rows = []
    cut = first_cut
    fold = 0
    while cut + pd.DateOffset(months=test_months) <= idx.max():
        test_end = cut + pd.DateOffset(months=test_months)
        train = panel.loc[:cut]
        test = panel.loc[cut:test_end]
        if len(train) < 200 or len(test) < 30:
            cut = test_end
            continue
        imp = local_projection(train, shock_col, response_col, horizons=[horizon])
        beta = imp.beta_mean[0]
        if beta is None or np.isnan(beta):
            cut = test_end
            continue

        shock_sd = train[shock_col].std(ddof=0) or 1.0
        shock_z = test[shock_col] / shock_sd
        realized = test[response_col].rolling(horizon).sum().shift(-horizon)
        pred = beta * shock_z
        ar1 = _ar1_forecast(train[response_col], test[response_col], horizon)

        df = pd.DataFrame({"pred": pred, "ar1": ar1, "real": realized}).dropna()
        if len(df) < 20:
            cut = test_end
            continue
        sign_acc = float((np.sign(df.pred) == np.sign(df.real)).mean())
        ar1_acc = float((np.sign(df.ar1) == np.sign(df.real)).mean())
        mse = float(((df.pred - df.real) ** 2).mean())
        mse_zero = float((df.real**2).mean())  # random-walk (zero) baseline
        rows.append(
            {
                "fold": fold,
                "train_end": str(cut.date()),
                "n_test": len(df),
                "sign_acc": round(sign_acc, 4),
                "ar1_sign_acc": round(ar1_acc, 4),
                "edge_vs_ar1": round(sign_acc - ar1_acc, 4),
                "mse": round(mse, 8),
                "mse_zero_baseline": round(mse_zero, 8),
                "beats_zero": mse < mse_zero,
            }
        )
        fold += 1
        cut = test_end
    return pd.DataFrame(rows)


def confirm(scan_row: dict, wf_results: pd.DataFrame) -> str:
    """CONFIRMED iff (a) q<0.10 in the causality scan AND (b) positive
    sign-accuracy edge over AR(1) in >=70% of folds with >=4 folds."""
    q = scan_row.get("q_value")
    if q is None or (isinstance(q, float) and np.isnan(q)) or q >= 0.10:
        return "HYPOTHESIS"
    if wf_results is None or len(wf_results) < 4:
        return "HYPOTHESIS"
    frac_positive = float((wf_results["edge_vs_ar1"] > 0).mean())
    return "CONFIRMED" if frac_positive >= 0.70 else "HYPOTHESIS"
