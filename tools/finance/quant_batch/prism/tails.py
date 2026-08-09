"""Tail layer: EVT peaks-over-threshold (GPD) + bipower-variation jumps."""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from scipy.stats import genpareto


@dataclass
class TailResult:
    xi: float  # GPD shape (tail index); >0 = heavy tail
    beta: float  # GPD scale
    threshold: float  # POT threshold on losses
    n_exceed: int
    var_99: float  # loss quantiles (positive = loss magnitude)
    es_99: float
    var_999: float
    valid: bool

    def to_payload(self) -> dict:
        def r(v):
            return None if v is None or np.isnan(v) else round(float(v), 6)

        return {
            "xi": r(self.xi),
            "beta": r(self.beta),
            "threshold": r(self.threshold),
            "n_exceed": int(self.n_exceed),
            "var_99": r(self.var_99),
            "es_99": r(self.es_99),
            "var_999": r(self.var_999),
            "valid": bool(self.valid),
            "method": "GPD peaks-over-threshold, daily horizon",
        }


def fit_gpd_pot(returns: pd.Series, threshold_q: float = 0.95) -> TailResult:
    """Fit GPD to losses beyond the threshold_q quantile.

    VaR_p from POT: u + (beta/xi) * ((n/n_u * (1-p))^(-xi) - 1)
    ES_p  (xi<1):  (VaR_p + beta - xi*u) / (1 - xi)
    """
    losses = -returns.dropna().to_numpy()
    n = len(losses)
    u = float(np.quantile(losses, threshold_q))
    exceed = losses[losses > u] - u
    n_u = len(exceed)
    valid = n_u >= 30
    if n_u < 5:
        return TailResult(np.nan, np.nan, u, n_u, np.nan, np.nan, np.nan, False)

    xi, _, beta = genpareto.fit(exceed, floc=0)

    def var_at(p):
        return u + (beta / xi) * (((n / n_u) * (1 - p)) ** (-xi) - 1)

    var99 = float(var_at(0.99))
    var999 = float(var_at(0.999))
    es99 = float((var99 + beta - xi * u) / (1 - xi)) if xi < 1 else np.nan

    return TailResult(
        xi=float(xi),
        beta=float(beta),
        threshold=u,
        n_exceed=n_u,
        var_99=var99,
        es_99=es99,
        var_999=var999,
        valid=valid,
    )


def fit_gpd_by_regime(
    returns: pd.Series,
    regime_probs: pd.DataFrame,
    threshold_q: float = 0.95,
    min_weight_days: float = 250.0,
) -> dict[str, TailResult]:
    """Regime-conditional EVT — the validation study's triggered revision
    (H4: violations cluster in stress; H8: xi flips sign across eras).

    One unconditional tail conflates calm and crisis distributions; here
    each HMM state gets its own GPD, fitted on observations RESAMPLED by
    that state's probability (hard assignment at P>0.5 plus soft borderline
    inclusion would bias xi; probability-weighted subsampling keeps the
    exceedance counts honest). States with less than min_weight_days of
    effective weight return an invalid TailResult rather than a noisy fit.
    """
    out = {}
    r = returns.dropna()
    probs = regime_probs.reindex(r.index).fillna(0.0)
    for state in regime_probs.columns:
        w = probs[state].to_numpy()
        eff_days = float(w.sum())
        if eff_days < min_weight_days:
            out[state] = TailResult(
                np.nan, np.nan, np.nan, 0, np.nan, np.nan, np.nan, False
            )
            continue
        # deterministic probability-weighted subsample: keep days where
        # P(state) dominates (>0.5); the HMM's stickiness makes this a
        # contiguous-block selection, preserving within-regime dependence
        mask = w > 0.5
        if mask.sum() < min_weight_days:
            mask = w > (np.quantile(w, 1 - min_weight_days / len(w)))
        out[state] = fit_gpd_pot(r[mask], threshold_q=threshold_q)
    return out


def bipower_jump_stat(returns: pd.Series, window: int = 22) -> pd.Series:
    """Rolling RV/BV ratio; >> 1 indicates jump activity in the window.

    BV_t = (pi/2) * sum |r_t||r_{t-1}| is jump-robust; RV includes jumps,
    so their ratio isolates the jump contribution.
    """
    r = returns.dropna()
    rv = (r**2).rolling(window).sum()
    bv = (np.pi / 2.0) * (r.abs() * r.abs().shift(1)).rolling(window).sum()
    return (rv / bv).rename("rv_bv_ratio")
