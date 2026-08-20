"""Governance ablation runner for DRAFT_protocol_ablation.md.

Pre-freeze: only `--calibrate` may run (asserts regime R4 == the recorded
scoreboard). Post-freeze (tag ablation-preregistered): full run computes
R0-R3 from committed artifacts and writes
research/results/ablation_matrix.json.

All rules are the protocol's type-generic operationalizations; nothing
here is tuned per candidate.
"""

import argparse
import json
import math
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RES = REPO / "research" / "results"

# recorded scoreboard (regime R4 control) — from findings_addendum.md
R4_VERDICTS = {
    "regime_evt": False,
    "fisher_combination": True,
    "vol_filtered_var": True,
    "qis": False,
    "rfsv": False,
    "signature": False,
    "bocpd_v1": False,
    "bocpd_v2": False,
    "bcfreq_v1": False,
    "bcfreq_v2": False,
}


def bh_q(pvals):
    """Benjamini-Hochberg adjusted q-values (monotone step-up)."""
    m = len(pvals)
    order = sorted(range(m), key=lambda i: pvals[i])
    q = [0.0] * m
    prev = 1.0
    for rank_from_end, idx in enumerate(reversed(order)):
        rank = m - rank_from_end
        val = min(prev, pvals[idx] * m / rank)
        q[idx] = val
        prev = val
    return q


def is_num(x):
    return isinstance(x, (int, float)) and not (isinstance(x, float) and math.isnan(x))


def majority(flags):
    valid = [f for f in flags if f is not None]
    return bool(valid) and sum(valid) > len(valid) / 2


# ---- type-generic evaluators ------------------------------------------------


def eval_comparison(data):
    cohorts = [
        v for k, v in data.items() if isinstance(v, dict) and "paired_mean_diff" in v
    ]
    diffs = [c["paired_mean_diff"] for c in cohorts]
    ps = [c.get("bootstrap_p") for c in cohorts]
    era_cells = [
        bool(e.get("improved"))
        for c in cohorts
        for e in c.get("eras", {}).values()
        if isinstance(e, dict) and "improved" in e
    ]
    r0 = majority([d > 0 for d in diffs])
    r1 = any(is_num(p) and p < 0.05 and d > 0 for p, d in zip(ps, diffs))
    valid = [(p, d) for p, d in zip(ps, diffs) if is_num(p)]
    r2 = False
    if valid:
        qs = bh_q([p for p, _ in valid])
        r2 = any(q < 0.05 and d > 0 for q, (_, d) in zip(qs, valid))
    r3 = majority(era_cells) and not any(d < 0 for d in diffs)
    return dict(R0=r0, R1=r1, R2=r2, R3=r3)


def eval_calibration(data, cand_arm, inc_arm):
    assets = {k: v for k, v in data.items() if isinstance(v, dict) and cand_arm in v}
    improve, pfam, era_cells = [], [], []
    for a in assets.values():
        c, i = a[cand_arm], a[inc_arm]
        improve.append(abs(c["rate"] - 0.01) < abs(i["rate"] - 0.01))
        pfam += [c["kupiec_p"], c["cc_p"]]
        era_cells.append(abs(c["rate"] - 0.01) < abs(i["rate"] - 0.01))
    r0 = majority(improve)
    r1 = all(p >= 0.05 for p in [a[cand_arm]["kupiec_p"] for a in assets.values()])
    qs = bh_q(pfam)
    r2 = not any(q < 0.05 for q in qs)  # adopt iff nothing rejects after BH
    r3 = majority(era_cells) and all(improve)
    return dict(R0=r0, R1=r1, R2=r2, R3=r3)


def eval_detector(data, cand, inc, pooled_p=None, pooled_gain=None):
    cohorts = {k: v for k, v in data.items() if isinstance(v, dict) and cand in v}
    lag_better, ps, era_cells, fa_ok = [], [], [], []
    for c in cohorts.values():
        cl, il = c[cand].get("median_lag"), c[inc].get("median_lag")
        if cl is None and il is None:
            lag_better.append(None)
        elif cl is None:
            lag_better.append(False)
        elif il is None:
            lag_better.append(True)
        else:
            lag_better.append(cl < il)
        budget = c.get("train_budget_fa_per_250bd")
        fa_ok.append(
            c[cand].get("fa_within_budget")
            if "fa_within_budget" in c[cand]
            else (budget is None or c[cand].get("fa_per_250bd", 0) <= budget * 1.5)
        )
        ps.append(c[cand].get("bootstrap_p"))
        for e in c.get("eras", {}).values():
            ce, ie = e.get(cand), e.get(inc)
            if ce is None and ie is None:
                continue
            era_cells.append(
                ie is None if ce is not None else False if ce is None else ce < ie
            )
    within = [b for b, ok in zip(lag_better, fa_ok) if ok or b is None]
    r0 = majority(within)
    p_candidates = [p for p in ps if is_num(p)] + (
        [pooled_p] if is_num(pooled_p) else []
    )
    r1 = any(p < 0.05 for p in p_candidates) and (
        majority(lag_better) or (is_num(pooled_gain) and pooled_gain > 0)
    )
    r2 = (
        bool(p_candidates)
        and any(q < 0.05 for q in bh_q(p_candidates))
        and majority(lag_better)
    )
    r3 = majority(era_cells) and not any(b is False for b in lag_better)
    return dict(R0=r0, R1=r1, R2=r2, R3=r3)


def eval_scan(rows):
    ps = [r["p"] for r in rows if is_num(r.get("p"))]
    qs = [r["q"] for r in rows if is_num(r.get("q"))]
    sig = [bool(r.get("significant")) for r in rows]
    r0 = any(p < 0.05 for p in ps)  # a scan's "point estimate" is a raw hit
    r1 = r0
    r2 = any(q < 0.05 for q in qs) or any(sig)
    r3 = False  # discovery scans store no direction-consistency cells here
    return dict(R0=r0, R1=r1, R2=r2, R3=r3)


# ---- assembly ----------------------------------------------------------------


def load(name):
    return json.loads((RES / name).read_text())


def full_matrix():
    m = {}
    m["qis"] = eval_comparison(load("qis_test.json"))
    m["signature"] = eval_comparison(load("signature_test.json"))
    m["rfsv"] = eval_calibration(load("rfsv_test.json"), "rfsv", "ewma")
    m["bocpd_v1"] = eval_detector(load("bocpd_test.json"), "bocpd", "incumbent")
    v2 = load("bocpd_v2_test.json")
    m["bocpd_v2"] = eval_detector(
        v2["per_cohort"],
        "bocpd",
        "incumbent",
        pooled_p=v2.get("sign_permutation_p"),
        pooled_gain=v2.get("pooled_mean_lag_gain_bd"),
    )
    m["bcfreq_v1"] = eval_scan(load("bcfreq_test.json")["full_sample"])
    m["bcfreq_v2"] = eval_scan(load("bcfreq_v2_test.json")["full_sample"])
    # excluded / nested rows per protocol
    m["regime_evt"] = dict(R0=None, R1=None, R2=None, R3=None)
    m["fisher_combination"] = dict(R0=True, R1=True, R2=True, R3=True, nested=True)
    m["vol_filtered_var"] = dict(R0=True, R1=True, R2=True, R3=True, nested=True)
    for k in m:
        m[k]["R4"] = R4_VERDICTS[k]
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--calibrate", action="store_true", help="pre-freeze R4 check only")
    args = ap.parse_args()

    if args.calibrate:
        addendum = (REPO / "research" / "findings_addendum.md").read_text()
        assert "2 promoted / 8 fast-failed" in addendum, "scoreboard line missing"
        promoted = [k for k, v in R4_VERDICTS.items() if v]
        assert promoted == ["fisher_combination", "vol_filtered_var"]
        assert sum(1 for v in R4_VERDICTS.values() if not v) == 8
        print(
            "R4 calibration OK: 2 promoted / 8 rejected matches the recorded scoreboard"
        )
        return

    tag_ok = (REPO / "research" / "protocol_ablation.md").exists()
    assert tag_ok, "REFUSING full run: protocol not frozen (still DRAFT)"
    matrix = full_matrix()
    out = RES / "ablation_matrix.json"
    out.write_text(json.dumps(matrix, indent=1))
    print(f"wrote {out}")
    for k, v in matrix.items():
        print(k, {r: v.get(r) for r in ("R0", "R1", "R2", "R3", "R4")})


if __name__ == "__main__":
    main()
