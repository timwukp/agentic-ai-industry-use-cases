"""Execute the pre-registered RFSV-vs-EWMA test (protocol_rfsv.md).

Both arms share everything except sigma_next: incumbent uses EWMA(0.94),
challenger uses the RFSV kernel forecast over log realized vol. Judged by
the frozen 3-part gate (parity on Kupiec/CC/Basel, strictly better point
calibration, no clustering regression).
"""

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

RESEARCH = Path(__file__).resolve().parent
REPO = RESEARCH.parent
sys.path.insert(0, str(RESEARCH))
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))

from prism import fit_gpd_pot  # noqa: E402
from prism.tails import ewma_sigma  # noqa: E402
from studylib.backtests import basel_traffic_light, conditional_coverage  # noqa: E402
from run_study import build_cohort_panel  # noqa: E402

H_MIN, H_MAX = 0.02, 0.45
KERNEL_LEN = 500
VOL_WINDOW = 5


def realized_vol(returns: pd.Series) -> pd.Series:
    """5-day rolling std — the pre-registered daily-data vol proxy.
    shift(1): v_t known at t-1 close, no same-day leakage."""
    return returns.rolling(VOL_WINDOW).std(ddof=0).shift(1)


def estimate_hurst(log_v: np.ndarray) -> float:
    """q=2 structure-function scaling: m(2,d) ~ d^(2H)."""
    deltas = np.arange(1, 21)
    m2 = []
    for d in deltas:
        diff = log_v[d:] - log_v[:-d]
        m2.append(np.mean(diff**2))
    m2 = np.asarray(m2)
    ok = m2 > 0
    if ok.sum() < 5:
        return 0.1
    slope = np.polyfit(np.log(deltas[ok]), np.log(m2[ok]), 1)[0]
    return float(np.clip(slope / 2.0, H_MIN, H_MAX))


def rfsv_sigma_series(returns: pd.Series) -> pd.Series:
    """Point-in-time RFSV forecast of next-day vol for every day.

    H re-estimated monthly on the trailing 2y of log vol; the forecast
    kernel (Nuzman-Poor weights over trailing KERNEL_LEN log-vol values)
    is applied daily. Strictly causal: everything at date t uses <= t.
    """
    v = realized_vol(returns).dropna()
    log_v = np.log(v.replace(0, np.nan).dropna())
    month_ends = log_v.resample("ME").last().index
    out = {}
    H = 0.1
    lv = log_v.to_numpy()
    dates = log_v.index
    date_pos = {d: i for i, d in enumerate(dates)}
    for mi, me in enumerate(month_ends):
        window = log_v.loc[me - pd.DateOffset(years=2) : me]
        if len(window) >= 250:
            H = estimate_hurst(window.to_numpy())
        nxt = month_ends[mi + 1] if mi + 1 < len(month_ends) else dates.max()
        # Nuzman-Poor style weights for this month's H
        i_arr = np.arange(KERNEL_LEN, dtype=float)
        w = 1.0 / (((i_arr + 1.0) ** (H + 0.5)) * (i_arr + 1.0))
        w /= w.sum()
        for d in dates[(dates > me) & (dates <= nxt)]:
            pos = date_pos[d]
            if pos < KERNEL_LEN + 1:
                continue
            hist = lv[pos - KERNEL_LEN : pos][::-1]  # most recent first
            mean_log = float(np.dot(w, hist))
            resid = hist[:60] - mean_log
            var_log = float(np.var(resid))
            out[d] = float(np.exp(mean_log + 0.5 * var_log))
    return pd.Series(out, name="rfsv_sigma")


def backtest_arm(returns: pd.Series, sigma: pd.Series, label: str) -> dict:
    """Standardize by the arm's sigma, GPD on residuals (monthly refit,
    5y window), VaR = sigma_t x q99, judged out-of-sample."""
    r = returns.dropna()
    z = (r / sigma).replace([np.inf, -np.inf], np.nan).dropna()
    month_ends = r.resample("ME").last().index
    rows = []
    for i, me in enumerate(month_ends):
        z_train = z.loc[me - pd.DateOffset(years=5) : me]
        if len(z_train) < 500:
            continue
        tr = fit_gpd_pot(z_train)
        if not np.isfinite(tr.var_99):
            continue
        nxt = month_ends[i + 1] if i + 1 < len(month_ends) else r.index.max()
        for d in r.index[(r.index > me) & (r.index <= nxt)]:
            s = sigma.get(d)
            if s is None or not np.isfinite(s):
                continue
            var_d = float(s * tr.var_99)
            rows.append({"date": d, "violation": (-float(r.loc[d])) > var_d})
    vs = pd.DataFrame(rows).set_index("date")
    v = vs["violation"].to_numpy()
    cc = conditional_coverage(v, alpha=0.01)
    zone = basel_traffic_light(v, alpha=0.01)
    max_cluster = int(vs["violation"].astype(int).rolling(22).sum().max())
    return {
        "arm": label,
        "n": int(cc["pof"]["n"]),
        "violations": int(cc["pof"]["violations"]),
        "rate": round(float(cc["pof"]["rate"]), 5),
        "kupiec_p": round(float(cc["pof"]["p"]), 4),
        "cc_p": None if np.isnan(cc["p"]) else round(float(cc["p"]), 4),
        "basel": zone,
        "max_cluster_22bd": max_cluster,
    }


def main() -> None:
    t0 = time.time()
    rets = build_cohort_panel("C36")
    results = {}
    for asset, col in (("NASDAQCOM", "NASDAQCOM_ret"), ("DGS10", "DGS10_diff")):
        r = rets[col]
        arms = {}
        for label, sig in (
            ("ewma", ewma_sigma(r.dropna())),
            ("rfsv", rfsv_sigma_series(r)),
        ):
            arms[label] = backtest_arm(r, sig, label)
            print(asset, json.dumps(arms[label]), flush=True)
        results[asset] = arms
    results["runtime_s"] = round(time.time() - t0, 1)
    Path("research/results/rfsv_test.json").write_text(json.dumps(results, indent=2))
    print("saved research/results/rfsv_test.json")


if __name__ == "__main__":
    main()
