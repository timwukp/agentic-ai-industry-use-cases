"""Pre-freeze power check for DRAFT_protocol_enso_farmppi.md.

Data setup (once):
  mkdir -p research/data/enso && cd research/data/enso
  curl -sO https://www.cpc.ncep.noaa.gov/data/indices/oni.ascii.txt && mv oni.ascii.txt oni.txt
  KEY=$(aws ssm get-parameter --name /agentic/finance/fred-api-key --with-decryption --query Parameter.Value --output text)
  for S in WPU01 CPIUFDSL; do curl -s "https://api.stlouisfed.org/fred/series/observations?series_id=$S&api_key=$KEY&file_type=json&observation_start=1974-01-01" -o $S.json; done
Run: python3 research/run_enso_power_check.py
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))
from prism.impact import local_projection  # noqa: E402
from prism import granger_pvalue  # noqa: E402

SEEDS = 200
HORIZONS = list(range(1, 13))
DETECT_H = [6, 9, 12]

# ---- real ONI (monthly, use season center month) --------------------------
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
rows = []
for line in (
    open(REPO / "research" / "data" / "enso" / "oni.txt").read().splitlines()[1:]
):
    p = line.split()
    if len(p) == 4 and p[0] in SEAS:
        rows.append((int(p[1]), SEAS.index(p[0]) + 1, float(p[3])))
oni = pd.DataFrame(rows, columns=["y", "m", "anom"])
oni["date"] = pd.to_datetime(dict(year=oni.y, month=oni.m, day=1))
oni = oni.set_index("date")["anom"].sort_index()["1974-06":"2026-06"]
oni_z = (oni - oni.mean()) / oni.std(ddof=0)


# ---- real outcome vols -----------------------------------------------------
def fred_logdiff(path):
    obs = json.load(open(path))["observations"]
    s = pd.Series(
        [float(o["value"]) for o in obs if o["value"] != "."],
        index=pd.to_datetime([o["date"] for o in obs if o["value"] != "."]),
    )
    return np.log(s).diff().dropna()


sig = {
    "farm_ppi": float(
        fred_logdiff(REPO / "research" / "data" / "enso" / "WPU01.json").std(ddof=0)
    ),
    "food_cpi": float(
        fred_logdiff(REPO / "research" / "data" / "enso" / "CPIUFDSL.json").std(ddof=0)
    ),
}

# ---- calibrate the monthly coefficient so the TRUE LP slope at h=12 == target
x = oni_z.to_numpy()
n = len(x)
cum12 = np.array([x[t + 1 : t + 13].sum() for t in range(n - 13)])
K = float(np.cov(cum12, x[: n - 13])[0, 1] / np.var(x[: n - 13]))
print(
    f"n={n} months | ONI cum-12 transmission factor K={K:.2f} "
    f"| sigma farm_ppi={sig['farm_ppi']:.4f} food_cpi={sig['food_cpi']:.4f}"
)

CASES = {
    "A_farm_ppi_3.5pct": dict(target=0.035, sigma=sig["farm_ppi"]),
    "B_food_cpi_0.14pct": dict(target=0.0014, sigma=sig["food_cpi"]),
}


def run_case(target, sigma, seeds=SEEDS, null=False):
    c = 0.0 if null else target / K
    det_lp = det_gr = det_both = 0
    for seed in range(seeds):
        rng = np.random.default_rng(seed)
        y = np.empty(n)
        y[0] = rng.normal(0, sigma)
        for t in range(1, n):
            y[t] = c * x[t - 1] + rng.normal(0, sigma)
        panel = pd.DataFrame({"oni": x, "y": y}, index=oni_z.index)
        imp = local_projection(panel, "oni", "y", horizons=HORIZONS)
        lp_hit = (
            any(imp.band95[h - 1][0] > 0 for h in DETECT_H)
            if not null
            else any(
                imp.band95[h - 1][0] > 0 or imp.band95[h - 1][1] < 0 for h in DETECT_H
            )
        )
        g_p = granger_pvalue(x, y, maxlag=3)
        gr_hit = g_p < 0.05
        det_lp += lp_hit
        det_gr += gr_hit
        det_both += lp_hit and gr_hit
    return det_lp / seeds, det_gr / seeds, det_both / seeds


results = {}
for name, cfg in CASES.items():
    lp, gr, both = run_case(cfg["target"], cfg["sigma"])
    results[name] = dict(lp=lp, granger=gr, both=both)
    print(f"{name}: LP={lp:.2f}  Granger={gr:.2f}  BOTH={both:.2f}")

fp_lp, fp_gr, fp_both = run_case(0.0, sig["farm_ppi"], seeds=SEEDS, null=True)
results["null_false_positive"] = dict(lp=fp_lp, granger=fp_gr, both=fp_both)
print(
    f"NULL (beta=0): LP-any-side={fp_lp:.2f}  Granger={fp_gr:.2f}  BOTH={fp_both:.2f}"
)

json.dump(
    results,
    open(REPO / "research" / "results" / "enso_power_check.json", "w"),
    indent=1,
)
print("GATE: power >= 0.80 on BOTH for an endpoint -> instrument valid for it")
