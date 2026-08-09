"""Power audit of causality_scan's combined-p rule (exploratory appendix).

The validation study's H2 found the scan missed the literature-documented
oil→10Y edge. Pre-registered suspicion: combined p = max(TE_p, Granger_p)
is doubly conservative. This audit quantifies detection power of three
combination rules on synthetic panels with planted effects of varying
strength, at the study's exact settings (BH q<0.10, horizons {1,5,20}).

Rules compared:
  max    — current PRISM rule (edge must convince BOTH tests)
  fisher — Fisher's combined chi-square (either test contributes)
  min    — most liberal (either test alone suffices) with Bonferroni x2

Also probes the monthly-frequency question: does oil→DGS10 emerge at
monthly aggregation where the literature actually operates?
"""

import sys
from pathlib import Path

import numpy as np
from scipy import stats

RESEARCH = Path(__file__).resolve().parent
REPO = RESEARCH.parent
sys.path.insert(0, str(RESEARCH))
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))

from prism.causality import granger_pvalue, te_pvalue, _bh_qvalues  # noqa: E402
from run_study import build_cohort_panel  # noqa: E402

SEED = 7


def planted_pair(n, beta, seed):
    rng = np.random.default_rng(seed)
    x = np.zeros(n)
    for t in range(1, n):
        x[t] = 0.3 * x[t - 1] + rng.normal(0, 1)
    y = np.zeros(n)
    y[1:] = beta * x[:-1] + rng.normal(0, 1, n - 1)
    return x, y


def combined(p_te, p_g, rule):
    ps = [p for p in (p_te, p_g) if not np.isnan(p)]
    if not ps:
        return np.nan
    if rule == "max":
        return max(ps)
    if rule == "fisher":
        stat = -2.0 * sum(np.log(max(p, 1e-12)) for p in ps)
        return float(stats.chi2.sf(stat, df=2 * len(ps)))
    if rule == "min":
        return min(1.0, 2.0 * min(ps))  # Bonferroni for cherry-pick
    raise ValueError(rule)


def synthetic_power() -> None:
    print("=== synthetic power: detection rate at BH q<0.10 (20 seeds each) ===")
    print(f"{'beta':>6} {'n':>6} | {'max':>6} {'fisher':>7} {'min':>6}")
    for beta in (0.10, 0.15, 0.20, 0.30):
        for n in (1500,):
            hits = {"max": 0, "fisher": 0, "min": 0}
            n_seeds = 20
            for seed in range(n_seeds):
                x, y = planted_pair(n, beta, seed)
                # grid mimics the study: 1 planted + 5 noise edges, 3 horizons
                rng = np.random.default_rng(1000 + seed)
                rows = []
                for h in (1, 5, 20):
                    rows.append(
                        (
                            "planted",
                            h,
                            te_pvalue(x, y, seed=SEED, lag=h),
                            granger_pvalue(x, y, maxlag=h),
                        )
                    )
                for j in range(5):
                    z = rng.normal(0, 1, n)
                    for h in (1, 5, 20):
                        rows.append(
                            (
                                f"noise{j}",
                                h,
                                te_pvalue(z, y, seed=SEED, lag=h),
                                granger_pvalue(z, y, maxlag=h),
                            )
                        )
                for rule in hits:
                    ps = np.array([combined(t, g, rule) for _, _, t, g in rows])
                    ok = ~np.isnan(ps)
                    q = np.full(len(ps), np.nan)
                    q[ok] = _bh_qvalues(ps[ok])
                    for (name, h, _, _), qv in zip(rows, q):
                        if name == "planted" and h == 1 and qv < 0.10:
                            hits[rule] += 1
                            break
            print(
                f"{beta:>6} {n:>6} | "
                f"{hits['max']/n_seeds:>6.0%} {hits['fisher']/n_seeds:>7.0%} "
                f"{hits['min']/n_seeds:>6.0%}"
            )


def false_positive_check() -> None:
    print("=== false positives on pure noise grids (must stay ~0) ===")
    fp = {"max": 0, "fisher": 0, "min": 0}
    n_seeds = 20
    for seed in range(n_seeds):
        rng = np.random.default_rng(2000 + seed)
        series = [rng.normal(0, 1, 1000) for _ in range(6)]
        rows = []
        for i in range(3):
            for j in range(3, 6):
                for h in (1, 5, 20):
                    rows.append(
                        (
                            te_pvalue(series[i], series[j], seed=SEED, lag=h),
                            granger_pvalue(series[i], series[j], maxlag=h),
                        )
                    )
        for rule in fp:
            ps = np.array([combined(t, g, rule) for t, g in rows])
            ok = ~np.isnan(ps)
            q = np.full(len(ps), np.nan)
            q[ok] = _bh_qvalues(ps[ok])
            if np.nansum(q < 0.10) > 0:
                fp[rule] += 1
    for rule, k in fp.items():
        print(f"  {rule}: {k}/{n_seeds} grids with >=1 false positive")


def monthly_oil_yields() -> None:
    print("=== literature edge at monthly frequency (C40 real data) ===")
    rets = build_cohort_panel("C40")
    if "DCOILWTICO_ret" not in rets:
        print("  oil series absent")
        return
    monthly = rets[["DCOILWTICO_ret", "DGS10_diff"]].resample("ME").sum().dropna()
    x = monthly["DCOILWTICO_ret"].to_numpy()
    y = monthly["DGS10_diff"].to_numpy()
    for h in (1, 3):
        te_p = te_pvalue(x, y, seed=SEED, lag=h)
        g_p = granger_pvalue(x, y, maxlag=h)
        print(
            f"  monthly h={h}: te_p={te_p:.4f} granger_p={g_p:.4f} "
            f"max={combined(te_p, g_p, 'max'):.4f} "
            f"fisher={combined(te_p, g_p, 'fisher'):.4f}"
        )


if __name__ == "__main__":
    synthetic_power()
    false_positive_check()
    monthly_oil_yields()
