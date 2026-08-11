"""Execute the pre-registered signature-features regime test
(protocol_signature.md). Arms differ ONLY in the HMM input panel:
baseline = standard columns; treatment = standard + 3 Lévy-area features.
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

from studylib.metrics import auroc, detection_lags  # noqa: E402
from studylib.signature import signature_features  # noqa: E402
from run_qis_test import block_bootstrap_p, pit_stress_probs  # noqa: E402
from run_study import (  # noqa: E402
    REGIME_BASE,
    REGIME_EXTRA,
    _era_slices,
    _stress_labels,
    build_cohort_panel,
)

SEED = 7


def run_cohort(cohort: str) -> dict:
    t0 = time.time()
    rets = build_cohort_panel(cohort)
    cols = [c for c in REGIME_BASE + REGIME_EXTRA if c in rets]
    X_base = rets[cols]
    sig = signature_features(rets)
    X_treat = X_base.join(sig).dropna()
    # align both arms to the treated index so the comparison is like-for-like
    X_base_aligned = X_base.loc[X_treat.index]
    labels_all = pd.Series(_stress_labels(rets.index), index=rets.index)

    out = {"cohort": cohort, "base_cols": cols, "sig_cols": list(sig.columns)}
    series = {}
    for arm, X in (("baseline", X_base_aligned), ("signature", X_treat)):
        pit = pit_stress_probs(X, treated=False)  # same untreated HMM pipeline
        joined = pit.join(labels_all.rename("label"), how="inner").dropna()
        a = auroc(joined["stress"].to_numpy(), joined["label"].to_numpy())
        lags = detection_lags(joined["stress"].to_numpy(), joined["label"].to_numpy())
        series[arm] = joined
        out[arm] = {
            "h1b_auroc": round(float(a), 4),
            "median_lag": float(np.median(lags)) if lags else None,
            "n_days": len(joined),
        }

    b, q = series["baseline"], series["signature"]
    common = b.index.intersection(q.index)
    lab = b.loc[common, "label"].to_numpy().astype(bool)
    score_b = np.where(lab, b.loc[common, "stress"], 1 - b.loc[common, "stress"])
    score_q = np.where(lab, q.loc[common, "stress"], 1 - q.loc[common, "stress"])
    diff = (score_q - score_b).astype(float)
    out["paired_mean_diff"] = round(float(diff.mean()), 6)
    out["bootstrap_p"] = round(block_bootstrap_p(diff), 4)

    eras = {}
    for era, sub in _era_slices(rets).items():
        idx = common.intersection(sub.index)
        if len(idx) < 250:
            continue
        lab_e = b.loc[idx, "label"].to_numpy().astype(bool)
        if lab_e.sum() == 0 or (~lab_e).sum() == 0:
            continue
        a_b = auroc(b.loc[idx, "stress"].to_numpy(), lab_e)
        a_q = auroc(q.loc[idx, "stress"].to_numpy(), lab_e)
        eras[era] = {
            "baseline": round(a_b, 4),
            "signature": round(a_q, 4),
            "improved": bool(a_q > a_b),
        }
    out["eras"] = eras
    out["runtime_s"] = round(time.time() - t0, 1)
    return out


def main() -> None:
    results = {}
    for cohort in ("C10", "C20", "C36"):
        print(f"=== {cohort} ===", flush=True)
        results[cohort] = run_cohort(cohort)
        print(json.dumps(results[cohort], indent=1, default=str), flush=True)
    Path("research/results/signature_test.json").write_text(
        json.dumps(results, indent=2, default=str)
    )
    print("saved research/results/signature_test.json")


if __name__ == "__main__":
    main()
