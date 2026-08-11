"""Execute BOCPD v2 (protocol_bocpd_v2.md) — identical arms to v1, judged
under the fixed gate: absolute FA budget (<=2.0/250bd) and exact paired
sign-permutation significance.

Reuses run_bocpd_test.run_cohort verbatim (arms/data/thresholds unchanged);
only the judging layer differs. The permutation test enumerates all 2^n
sign assignments exactly for pooled n <= 22, else falls back to 200k
Monte Carlo signs (seed 7).
"""

import json
import sys
from itertools import product
from pathlib import Path

import numpy as np

RESEARCH = Path(__file__).resolve().parent
sys.path.insert(0, str(RESEARCH))
sys.path.insert(0, str(RESEARCH.parent / "tools" / "finance" / "quant_batch"))

from run_bocpd_test import (  # noqa: E402
    alarms_from_scores,
    episode_lags,
    run_cohort,
)

FA_BUDGET = 2.0  # per 250bd, absolute (defect-1 fix)


def exact_sign_permutation_p(diffs: np.ndarray, seed: int = 7) -> float:
    """P(mean >= observed) under random sign flips (H0: exchangeable signs)."""
    d = np.asarray(diffs, float)
    d = d[d != 0]
    n = len(d)
    if n == 0:
        return float("nan")
    obs = d.mean()
    if n <= 22:
        count = 0
        total = 2**n
        for signs in product((1.0, -1.0), repeat=n):
            if (d * np.array(signs)).mean() >= obs:
                count += 1
        return count / total
    rng = np.random.default_rng(seed)
    signs = rng.choice([1.0, -1.0], size=(200_000, n))
    return float(((signs * d).mean(axis=1) >= obs).mean() + 1 / 200_000)


def main() -> None:
    v1_path = RESEARCH / "results" / "bocpd_test.json"
    # arms unchanged -> v1 per-cohort results are the v2 measurements;
    # re-run only if missing (protocol: same code, same seeds)
    if v1_path.exists():
        results = json.loads(v1_path.read_text())
        print("reusing v1 measurements (arms identical by protocol)")
    else:
        results = {c: run_cohort(c) for c in ("C10", "C20", "C36")}

    verdict = {"protocol": "bocpd_v2", "fa_budget_per_250bd": FA_BUDGET}
    pooled_diffs = []
    per_cohort = {}
    for cohort, d in results.items():
        if not isinstance(d, dict) or "incumbent" not in d:
            continue
        row = {}
        for arm in ("incumbent", "bocpd", "cusum"):
            row[arm] = {
                "detected": d[arm]["detected"],
                "episodes": d[arm]["episodes"],
                "median_lag": d[arm]["median_lag"],
                "fa_per_250bd": d[arm]["fa_per_250bd"],
                "fa_within_budget": d[arm]["fa_per_250bd"] <= FA_BUDGET,
            }
        per_cohort[cohort] = row
    verdict["per_cohort"] = per_cohort

    # pooled paired lag differences (incumbent - bocpd), missed = worst+1,
    # reconstructed from the stored per-cohort summaries is not possible —
    # so recompute the episode vectors for the pooled test.
    print("recomputing episode-level pairs for the permutation test…")
    for cohort in ("C10", "C20", "C36"):
        d = run_cohort(cohort)  # deterministic (seed 7), same as v1 numbers
        # recompute inline pairs exactly as v1's paired_diff
        # run_cohort doesn't return raw lags, so replicate its final step:
        # (we re-derive from its printed members)
        pooled_diffs.append(d)  # placeholder replaced below
    # NOTE: run_cohort returns summaries; recompute pairs directly:
    from run_bocpd_test import (  # noqa: E402
        TRAIN_FRAC,
        false_alarm_rate,
        match_threshold,
    )
    import pandas as pd  # noqa: E402
    from studylib.changepoint import bocpd_alarm_series  # noqa: E402
    from run_qis_test import pit_stress_probs  # noqa: E402
    from run_study import (  # noqa: E402
        REGIME_BASE,
        REGIME_EXTRA,
        _stress_labels,
        build_cohort_panel,
    )

    pooled_diffs = []
    for cohort in ("C10", "C20", "C36"):
        rets = build_cohort_panel(cohort)
        cols = [c for c in REGIME_BASE + REGIME_EXTRA if c in rets]
        X = rets[cols]
        labels_full = pd.Series(_stress_labels(rets.index), index=rets.index)
        pit = pit_stress_probs(X, treated=False)
        joined = pit.join(labels_full.rename("label"), how="inner").dropna()
        idx = joined.index
        labels = joined["label"].to_numpy().astype(bool)
        inc_scores = joined["stress"].to_numpy()
        eq = rets["NASDAQCOM_ret"]
        mu = eq.rolling(250).mean().shift(1)
        sd = eq.rolling(250).std().shift(1)
        z = ((eq - mu) / sd.replace(0, np.nan)).reindex(idx).fillna(0.0).to_numpy()
        z = np.clip(z, -10, 10)
        b_scores = bocpd_alarm_series(z)
        n_train = int(len(idx) * TRAIN_FRAC)
        budget = false_alarm_rate(
            alarms_from_scores(inc_scores[:n_train], 0.5), labels[:n_train]
        )
        tau_b = match_threshold(
            b_scores[:n_train], labels[:n_train], budget, 0.05, 0.95
        )
        oos = slice(n_train, len(idx))
        ol = labels[oos]
        inc_lags = episode_lags(alarms_from_scores(inc_scores[oos], 0.5), ol)
        b_lags = episode_lags(alarms_from_scores(b_scores[oos], tau_b), ol)
        worst = max([x for x in inc_lags + b_lags if x is not None] or [0]) + 1
        for i, b in zip(inc_lags, b_lags):
            pooled_diffs.append(
                (i if i is not None else worst) - (b if b is not None else worst)
            )

    diffs = np.array(pooled_diffs, dtype=float)
    p_perm = exact_sign_permutation_p(diffs)
    verdict["pooled_episodes"] = int(len(diffs))
    verdict["pooled_mean_lag_gain_bd"] = round(float(diffs.mean()), 2)
    verdict["sign_permutation_p"] = round(p_perm, 5)

    Path("research/results/bocpd_v2_test.json").write_text(
        json.dumps(verdict, indent=2, default=str)
    )
    print(json.dumps(verdict, indent=1, default=str))


if __name__ == "__main__":
    main()
