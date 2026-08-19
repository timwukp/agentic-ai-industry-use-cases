"""Gate-4 (walk-forward OOS) power exploration for
DRAFT_protocol_enso_farmppi.md — the joint design-space simulation behind
the revised gate. Reproduces research/results/enso_gate4_power.json
(fixed seeds). Data setup: see run_enso_power_check.py docstring.

Findings this encodes (durable):
  1. The production confirm() fold-vote rule is degenerate at monthly
     frequency with default windows, and has power 0.61 / FP 0.17 with
     monthly-tuned windows (train_years=17, test_months=48, h=12).
  2. NO rule reaches 80% power at h=12 (~50 independent draws in 50y).
  3. The pooled n_test-weighted edge_vs_ar1 rule reaches power 0.817 at
     FP 0.05 with h=6 (threshold 0.0903 = null 95th percentile).
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))
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
SIGMA, TARGET, SEEDS = 0.0283, 0.035, 120
WF_WINDOWS = dict(train_years=17, test_months=48)


def load_oni():
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
    return (oni - oni.mean()) / oni.std(ddof=0)


def main():
    oni_z = load_oni()
    x = oni_z.to_numpy()
    n = len(x)
    cum12 = np.array([x[t + 1 : t + 13].sum() for t in range(n - 13)])
    k12 = float(np.cov(cum12, x[: n - 13])[0, 1] / np.var(x[: n - 13]))
    c = TARGET / k12

    def wf_run(h, seed, beta_c):
        rng = np.random.default_rng(seed)
        y = np.empty(n)
        y[0] = rng.normal(0, SIGMA)
        for t in range(1, n):
            y[t] = beta_c * x[t - 1] + rng.normal(0, SIGMA)
        panel = pd.DataFrame({"oni": x, "y": y}, index=oni_z.index)
        return walk_forward(panel, "oni", "y", horizon=h, **WF_WINDOWS)

    def pooled_edge(wf):
        if len(wf) < 4:
            return None
        w = wf["n_test"].to_numpy(dtype=float)
        return float(np.average(wf["edge_vs_ar1"], weights=w))

    out = {}
    for h in (3, 6, 12):
        planted, nulls = [], []
        for s in range(SEEDS):
            pe = pooled_edge(wf_run(h, s, c))
            ne = pooled_edge(wf_run(h, s, 0.0))
            if pe is not None:
                planted.append(pe)
            if ne is not None:
                nulls.append(ne)
        planted, nulls = np.array(planted), np.array(nulls)
        thr = float(np.quantile(nulls, 0.95))
        out[f"h={h}"] = dict(
            threshold=round(thr, 4),
            power=round(float((planted > thr).mean()), 3),
            fp=round(float((nulls > thr).mean()), 3),
        )
        # production fold-vote rule, for the record
        if h == 12:
            fv_p = [
                float((wf_run(h, s, c)["edge_vs_ar1"] > 0).mean()) >= 0.70
                for s in range(SEEDS)
            ]
            fv_n = [
                float((wf_run(h, s, 0.0)["edge_vs_ar1"] > 0).mean()) >= 0.70
                for s in range(SEEDS)
            ]
            out["fold_vote_h12"] = dict(
                power=round(float(np.mean(fv_p)), 3), fp=round(float(np.mean(fv_n)), 3)
            )
        print(h, out[f"h={h}"])

    json.dump(
        out,
        open(REPO / "research" / "results" / "enso_gate4_power_rerun.json", "w"),
        indent=1,
    )


if __name__ == "__main__":
    main()
