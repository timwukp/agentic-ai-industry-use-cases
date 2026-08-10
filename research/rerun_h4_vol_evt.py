"""H4 candidate 2: volatility-filtered EVT (McNeil-Frey), back-tested
point-in-time before any production code changes (exploratory appendix).

Why this can work where regime-conditional failed: the regime estimate lags
transitions by >10bd (H1b), so conditioning on it runs a calm tail into a
storm. Conditional volatility needs no hidden-state inference — EWMA sigma
reacts within days because volatility clusters, the one robustly forecastable
property of daily returns. Method:

  1. sigma_t: EWMA (RiskMetrics lambda=0.94) of squared returns, data <= t
  2. standardized residuals z = r/sigma over the trailing window
  3. GPD-POT on residual losses -> q_99 residual quantile (monthly refit)
  4. VaR for each day of the next month: sigma_{t+1|t} * q99_residual
     (sigma updated DAILY point-in-time; only the residual quantile is
     refit monthly)

Judged with the study's exact protocol: Kupiec POF + Christoffersen CC +
Basel zones. Comparison: unconditional 1.38% (study), regime-conditional
3.0-3.6% (refuted).
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

RESEARCH = Path(__file__).resolve().parent
REPO = RESEARCH.parent
sys.path.insert(0, str(RESEARCH))
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))

from prism import fit_gpd_pot  # noqa: E402
from studylib.backtests import basel_traffic_light, conditional_coverage  # noqa: E402
from run_study import build_cohort_panel  # noqa: E402

LAMBDA_EWMA = 0.94
WINDOW_YEARS = 5


def ewma_sigma(returns: pd.Series) -> pd.Series:
    """RiskMetrics EWMA volatility, strictly causal: sigma_t uses r_{<t}."""
    r2 = returns.fillna(0.0) ** 2
    var = r2.ewm(alpha=1 - LAMBDA_EWMA, adjust=False).mean()
    # shift(1): sigma for day t is known at t-1 close — no same-day leakage
    return np.sqrt(var).shift(1)


def rolling_vol_var(returns: pd.Series, level: float = 0.99) -> pd.DataFrame:
    r = returns.dropna()
    sigma = ewma_sigma(r)
    z = (r / sigma).dropna()
    month_ends = r.resample("ME").last().index
    rows = []
    for i, me in enumerate(month_ends):
        z_train = z.loc[me - pd.DateOffset(years=WINDOW_YEARS) : me]
        if len(z_train) < 500:
            continue
        tr = fit_gpd_pot(z_train)  # GPD on standardized residual losses
        q_resid = tr.var_99 if level == 0.99 else tr.var_999
        if not np.isfinite(q_resid):
            continue
        nxt = month_ends[i + 1] if i + 1 < len(month_ends) else r.index.max()
        days = r.index[(r.index > me) & (r.index <= nxt)]
        for d in days:
            s = sigma.get(d)
            if s is None or not np.isfinite(s):
                continue
            var_d = float(s * q_resid)  # daily-updated sigma x monthly quantile
            loss = -float(r.loc[d])
            rows.append({"date": d, "var": var_d, "violation": loss > var_d})
    return pd.DataFrame(rows).set_index("date")


def main() -> None:
    rets = build_cohort_panel("C36")
    print("candidate: vol-filtered EVT (EWMA lambda=0.94, monthly GPD refit)")
    for asset, col in (("NASDAQCOM", "NASDAQCOM_ret"), ("DGS10", "DGS10_diff")):
        vs = rolling_vol_var(rets[col])
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
        # clustering diagnostic: max violations in any 22bd window
        viol_series = vs["violation"].astype(int)
        max_cluster = int(viol_series.rolling(22).sum().max())
        print(f"  max violations in any 22bd window: {max_cluster}")


if __name__ == "__main__":
    main()
