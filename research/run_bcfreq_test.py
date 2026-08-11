"""Execute the pre-registered BC frequency-domain causality test
(protocol_bc_freq.md). Full C40 sample + era splits, 20-cell grid
(4 pairs x 5 bands), BH across the whole grid.
"""

import json
import sys
from pathlib import Path

import numpy as np

RESEARCH = Path(__file__).resolve().parent
sys.path.insert(0, str(RESEARCH))
sys.path.insert(0, str(RESEARCH.parent / "tools" / "finance" / "quant_batch"))

from prism.causality import _bh_qvalues  # noqa: E402
from studylib.bcfreq import band_scan  # noqa: E402
from run_study import _era_slices, build_cohort_panel  # noqa: E402

PAIRS = [
    ("DCOILWTICO_ret", "DGS10_diff"),  # the missed literature edge
    ("DGS10_diff", "DCOILWTICO_ret"),  # direction control
    ("VIXCLS_diff", "NASDAQCOM_ret"),  # positive control (confirmed edge)
    ("NASDAQCOM_ret", "VIXCLS_diff"),
]


def scan_with_bh(panel) -> list[dict]:
    scan = band_scan(panel, [p for p in PAIRS if p[0] in panel and p[1] in panel])
    ok = scan["p"].notna()
    q = np.full(len(scan), np.nan)
    if ok.any():
        q[ok.to_numpy()] = _bh_qvalues(scan.loc[ok, "p"].to_numpy())
    scan["q"] = q
    scan["significant"] = scan["q"] < 0.10
    return scan.to_dict("records")


def main() -> None:
    rets = build_cohort_panel("C40")
    out = {"full_sample": scan_with_bh(rets)}
    eras = {}
    for era, sub in _era_slices(rets).items():
        if len(sub) < 750:
            continue
        eras[era] = scan_with_bh(sub)
    out["eras"] = eras
    Path("research/results/bcfreq_test.json").write_text(
        json.dumps(out, indent=2, default=str)
    )
    sig = [r for r in out["full_sample"] if r["significant"]]
    print(f"full-sample significant cells: {len(sig)}")
    for r in sig:
        print(f"  {r['source']} -> {r['target']} @ {r['band']}: q={r['q']:.4f}")
    print("saved research/results/bcfreq_test.json")


if __name__ == "__main__":
    main()
