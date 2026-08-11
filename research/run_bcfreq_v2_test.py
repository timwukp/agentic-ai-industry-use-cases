"""Execute the pre-registered BC frequency-causality v2 test
(protocol_bc_freq_v2.md, tag bcfreq-v2-test-preregistered).

v2 fixes vs v1: VAR lag FIXED at 22 (no BIC), and each pair runs on a
cohort that contains its variables (oil pairs on C40, VIX pairs on C36).
BH q<0.10 pooled across the full 20-cell grid; the runner ABORTS if the
grid is not exactly 20 non-NaN rows (v1 silently ran 10).
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

RESEARCH = Path(__file__).resolve().parent
sys.path.insert(0, str(RESEARCH))
sys.path.insert(0, str(RESEARCH.parent / "tools" / "finance" / "quant_batch"))

from prism.causality import _bh_qvalues  # noqa: E402
from studylib.bcfreq import band_scan  # noqa: E402
from run_study import _era_slices, build_cohort_panel  # noqa: E402

# Pre-registered pair -> cohort map (protocol_bc_freq_v2.md §Method)
COHORT_PAIRS = {
    "C40": [
        ("DCOILWTICO_ret", "DGS10_diff"),  # the missed literature edge
        ("DGS10_diff", "DCOILWTICO_ret"),  # direction control
    ],
    "C36": [
        ("VIXCLS_diff", "NASDAQCOM_ret"),  # positive control (confirmed edge)
        ("NASDAQCOM_ret", "VIXCLS_diff"),
    ],
}
LOW_BANDS = ("over_1y", "quarterly_1y", "monthly_quarterly")


def pooled_scan(panels: dict[str, pd.DataFrame]) -> pd.DataFrame:
    frames = []
    for cohort, pairs in COHORT_PAIRS.items():
        s = band_scan(panels[cohort], pairs)
        s["cohort"] = cohort
        frames.append(s)
    scan = pd.concat(frames, ignore_index=True)
    n_ok = int(scan["p"].notna().sum())
    if len(scan) != 20 or n_ok != 20:
        raise RuntimeError(f"grid must be 20 non-NaN rows, got {len(scan)}/{n_ok}")
    scan["q"] = _bh_qvalues(scan["p"].to_numpy())
    scan["significant"] = scan["q"] < 0.10
    return scan


def main() -> None:
    panels = {c: build_cohort_panel(c) for c in COHORT_PAIRS}
    full = pooled_scan(panels)
    out = {"full_sample": full.to_dict("records")}

    # Era scans on C40 for the headline edge's stability (gate condition 5).
    eras = {}
    for era, sub in _era_slices(panels["C40"]).items():
        if len(sub) < 750:
            continue
        s = band_scan(sub, COHORT_PAIRS["C40"])
        s["q"] = _bh_qvalues(s["p"].to_numpy())
        eras[era] = s.to_dict("records")
    out["eras_c40"] = eras

    # Mechanical gate evaluation (protocol_bc_freq_v2.md §Decision gate)
    def cell(df, src, band):
        r = df[(df["source"] == src) & (df["band"] == band)]
        return r.iloc[0] if len(r) else None

    oil = "DCOILWTICO_ret"
    c1_bands = [
        b for b in LOW_BANDS if (c := cell(full, oil, b)) is not None and c["significant"]
    ]
    c1 = len(c1_bands) > 0
    c2 = not cell(full, oil, "sub_weekly")["significant"]
    c3 = bool(
        full[(full["source"] == "VIXCLS_diff") & full["significant"]].shape[0] > 0
    )
    c4 = all(
        not cell(full, "DGS10_diff", b)["significant"] for b in c1_bands
    ) if c1 else None
    c5 = None
    if c1:
        hits = 0
        for era, rows in eras.items():
            df = pd.DataFrame(rows)
            if any(
                (r := cell(df, oil, b)) is not None and r["q"] < 0.10
                for b in c1_bands
            ):
                hits += 1
        c5 = hits >= 3
    gate = {
        "c1_recovery": c1,
        "c1_bands": c1_bands,
        "c2_specificity": c2,
        "c3_positive_control": c3,
        "c4_direction_control": c4,
        "c5_era_stability": c5,
        "promote": bool(c1 and c2 and c3 and (c4 is True) and (c5 is True)),
    }
    out["gate"] = gate

    Path("research/results/bcfreq_v2_test.json").write_text(
        json.dumps(out, indent=2, default=str)
    )
    print(full.to_string(index=False))
    print("\ngate:", json.dumps(gate, indent=2, default=str))
    print("saved research/results/bcfreq_v2_test.json")


if __name__ == "__main__":
    main()
