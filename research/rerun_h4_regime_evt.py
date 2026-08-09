"""Post-study verification of the triggered revision (exploratory appendix).

Re-runs the H4 back-to-back VaR test with REGIME-CONDITIONAL EVT: at each
month-end, fit the HMM on data <= t, fit per-regime GPDs on data <= t, and
use the CURRENT regime's VaR for the following month. Same Kupiec/
Christoffersen/Basel judging as the study. Comparison target: the study's
unconditional numbers (C36: NASDAQCOM 31 violations/1.38%, CC p=0.046).

Labeled exploratory: run after the pre-registered study, per protocol §6.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

RESEARCH = Path(__file__).resolve().parent
REPO = RESEARCH.parent
sys.path.insert(0, str(RESEARCH))
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))

from prism import fit_gpd_by_regime, fit_regimes  # noqa: E402
from studylib.backtests import basel_traffic_light, conditional_coverage  # noqa: E402
from run_study import build_cohort_panel, REGIME_BASE, REGIME_EXTRA  # noqa: E402

SEED = 7


def _gpd_tail_prob(tr, v: float, n: int, n_u: int) -> float:
    """P(loss > v) under a fitted GPD-POT model (v above threshold)."""
    if not np.isfinite(tr.xi) or v <= tr.threshold:
        return np.nan
    z = 1.0 + tr.xi * (v - tr.threshold) / tr.beta
    if z <= 0:
        return 0.0
    return (n_u / n) * z ** (-1.0 / tr.xi)


def _mixture_var(by, probs_now, pooled, level=0.99):
    """Solve P(loss > v) = 1-level under the regime-probability mixture,
    falling back to the pooled tail for invalid regime slices."""
    states = [s for s in probs_now.index if s in by]
    if not states or not np.isfinite(pooled.var_99):
        return pooled.var_99 if np.isfinite(pooled.var_99) else None

    def exceed_prob(v):
        total, wsum = 0.0, 0.0
        for s in states:
            w = float(probs_now[s])
            tr = by[s]
            if tr.valid and np.isfinite(tr.xi):
                p = _gpd_tail_prob(tr, v, n=max(tr.n_exceed * 20, 1), n_u=tr.n_exceed)
            else:
                p = _gpd_tail_prob(
                    pooled, v, n=max(pooled.n_exceed * 20, 1), n_u=pooled.n_exceed
                )
            if np.isnan(p):
                continue
            total += w * p
            wsum += w
        return total / wsum if wsum > 0 else np.nan

    # bisect on v between pooled var_99/2 and pooled var_999*3
    lo, hi = pooled.var_99 * 0.5, max(pooled.var_999 * 3.0, pooled.var_99 * 2.0)
    target = 1.0 - level
    for _ in range(60):
        mid = 0.5 * (lo + hi)
        p = exceed_prob(mid)
        if np.isnan(p):
            return pooled.var_99
        if p > target:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def rolling_regime_var(
    rets: pd.DataFrame,
    col: str,
    window_years: int = 5,
    min_train_years: int = 4,
) -> pd.DataFrame:
    cols = [c for c in REGIME_BASE + REGIME_EXTRA if c in rets]
    r = rets[col].dropna()
    month_ends = r.resample("ME").last().index
    start = rets.index.min() + pd.DateOffset(years=min_train_years)
    rows = []
    for i, me in enumerate(month_ends):
        if me < start:
            continue
        hist = rets.loc[:me]
        tail_hist = r.loc[me - pd.DateOffset(years=window_years) : me]
        if len(tail_hist) < 500 or len(hist) < 750:
            continue
        try:
            reg = fit_regimes(hist[cols], n_states=3, seed=SEED)
        except Exception:  # noqa: BLE001
            continue
        current = str(reg.viterbi.iloc[-1])
        by = fit_gpd_by_regime(tail_hist, reg.state_probs.loc[tail_hist.index.min() :])
        # MIXTURE VaR, not current-regime VaR: first attempt used the current
        # regime's tail and WORSENED calibration (3.64% violations — regime
        # transitions are exactly when violations strike). The forward-looking
        # loss distribution is a probability-weighted mixture over next-period
        # regimes; solve P(loss > v) = sum_s P(s) * P_s(loss > v) = 1%.
        probs_now = reg.state_probs.iloc[-1]
        from prism import fit_gpd_pot

        pooled = fit_gpd_pot(tail_hist)
        var_val = _mixture_var(by, probs_now, pooled, level=0.99)
        if var_val is None:
            continue
        nxt = month_ends[i + 1] if i + 1 < len(month_ends) else r.index.max()
        for d in r.index[(r.index > me) & (r.index <= nxt)]:
            loss = -float(r.loc[d])
            rows.append(
                {
                    "date": d,
                    "var": var_val,
                    "regime": current,
                    "violation": loss > var_val,
                }
            )
    return pd.DataFrame(rows).set_index("date")


def main() -> None:
    rets = build_cohort_panel("C36")
    for asset, col in (("NASDAQCOM", "NASDAQCOM_ret"), ("DGS10", "DGS10_diff")):
        vs = rolling_regime_var(rets, col)
        if vs.empty:
            print(f"{asset}: no OOS VaR produced")
            continue
        v = vs["violation"].to_numpy()
        cc = conditional_coverage(v, alpha=0.01)
        zone = basel_traffic_light(v, alpha=0.01)
        print(
            f"{asset}: n={cc['pof']['n']} violations={cc['pof']['violations']} "
            f"rate={cc['pof']['rate']:.4f} kupiec_p={cc['pof']['p']:.4f} "
            f"cc_p={cc['p']:.4f} basel={zone}"
        )
        by_regime = vs.groupby("regime")["violation"].agg(["sum", "count"])
        print(f"  violations by regime:\n{by_regime}")


if __name__ == "__main__":
    main()
