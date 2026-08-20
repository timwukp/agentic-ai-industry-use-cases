"""Real-data test for protocol_enso_farmppi.md (FROZEN 2026-08-20, tag
enso-farmppi-test-preregistered). Written AFTER the freeze per the
lifecycle; gates are evaluated exactly as frozen, verdict is mechanical.

Data (see protocol "Data & reproduction"): NOAA CPC ONI + FRED WPU01,
mirror under research/data/enso/ (refetch instructions in
run_enso_power_check.py). Point-in-time handling per the frozen
limitation: the ONI regressor is lagged ONE additional month beyond its
season-center date (conservative publication-delay proxy).

Frozen-text ambiguity resolutions (recorded, reviewer-checkable):
- Gate 3 "gates 1-2 direction agrees in both halves" is read as: the LP
  point estimate is positive at EVERY h in {6,9,12} in BOTH era halves
  (the strictest natural reading; chosen before results were seen).
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))
from prism import granger_pvalue  # noqa: E402
from prism.impact import local_projection  # noqa: E402
from prism.validate import walk_forward  # noqa: E402

SEAS = [
    "DJF",
    "JFM",
    "FMA",
    "MAM",
    "AMJ",
    "MJJ",
    "JJA",
    "JAS",
    "ASO",
    "SON",
    "OND",
    "NDJ",
]
DATA = REPO / "research" / "data" / "enso"
FREEZE_END = "2026-06"


def load_panel():
    rows = []
    for line in (DATA / "oni.txt").read_text().splitlines()[1:]:
        p = line.split()
        if len(p) == 4 and p[0] in SEAS:
            rows.append((int(p[1]), SEAS.index(p[0]) + 1, float(p[3])))
    oni = pd.DataFrame(rows, columns=["y", "m", "anom"])
    oni["date"] = pd.to_datetime(dict(year=oni.y, month=oni.m, day=1))
    oni = oni.set_index("date")["anom"].sort_index()
    # point-in-time: one extra month of lag beyond season-center
    oni = oni.shift(1, freq="MS")

    obs = json.loads((DATA / "WPU01.json").read_text())["observations"]
    ppi = pd.Series(
        [float(o["value"]) for o in obs if o["value"] != "."],
        index=pd.to_datetime([o["date"] for o in obs if o["value"] != "."]),
    )
    dlog = np.log(ppi).diff()

    panel = pd.DataFrame({"oni": oni, "y": dlog}).dropna()["1974-06":FREEZE_END]
    return panel


def lp_betas_bands(panel):
    imp = local_projection(panel, "oni", "y", horizons=list(range(1, 13)))
    return imp.beta_mean, imp.band95


def main():
    assert (REPO / "research" / "protocol_enso_farmppi.md").exists(), "not frozen"
    panel = load_panel()
    n = len(panel)

    # Gate 1: Granger p < 0.05, maxlag 3
    g1_p = float(
        granger_pvalue(panel["oni"].to_numpy(), panel["y"].to_numpy(), maxlag=3)
    )
    g1 = g1_p < 0.05

    # Gate 2: LP band95 positive at any h in {6,9,12}
    betas, bands = lp_betas_bands(panel)
    g2_detail = {
        h: dict(beta=betas[h - 1], lo95=bands[h - 1][0], hi95=bands[h - 1][1])
        for h in (6, 9, 12)
    }
    g2 = any(bands[h - 1][0] > 0 for h in (6, 9, 12))

    # Gate 3: direction (positive LP beta at every h in {6,9,12}) in both halves
    halves = {"h1_1974_2000": panel[:"1999-12"], "h2_2000_freeze": panel["2000-01":]}
    g3_detail = {}
    g3 = True
    for name, sub in halves.items():
        b, _ = lp_betas_bands(sub)
        g3_detail[name] = {h: b[h - 1] for h in (6, 9, 12)}
        ok = all(isinstance(b[h - 1], float) and b[h - 1] > 0 for h in (6, 9, 12))
        g3 = g3 and ok

    # Gate 4: walk-forward pooled n_test-weighted edge_vs_ar1 > 0.0903 at h=6
    wf = walk_forward(panel, "oni", "y", train_years=17, test_months=48, horizon=6)
    w = wf["n_test"].to_numpy(dtype=float)
    pooled = (
        float(np.average(wf["edge_vs_ar1"], weights=w))
        if len(wf) >= 4
        else float("nan")
    )
    g4 = len(wf) >= 4 and pooled > 0.0903

    verdict = "PROMOTE" if (g1 and g2 and g3 and g4) else "FAST FAIL"
    out = dict(
        n_months=n,
        window=[str(panel.index.min().date()), str(panel.index.max().date())],
        gate1=dict(granger_p=round(g1_p, 6), passes=g1),
        gate2=dict(
            detail={
                str(k): {kk: round(float(vv), 6) for kk, vv in v.items()}
                for k, v in g2_detail.items()
            },
            passes=g2,
        ),
        gate3=dict(
            detail={
                k: {str(h): round(float(x), 6) for h, x in v.items()}
                for k, v in g3_detail.items()
            },
            passes=g3,
        ),
        gate4=dict(
            n_folds=int(len(wf)),
            pooled_edge=round(pooled, 4),
            threshold=0.0903,
            passes=g4,
        ),
        verdict=verdict,
    )
    (REPO / "research" / "results" / "enso_test.json").write_text(
        json.dumps(out, indent=1)
    )
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
