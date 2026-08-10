"""Execute the pre-registered BOCPD/CUSUM fast-alarm test (protocol_bocpd.md).

Three alarm arms on identical PIT data:
  incumbent — HMM filtered P(stress) > 0.5 (exactly the study's H1b arm)
  bocpd     — Student-t BOCPD P(run<=5) > tau
  cusum     — two-sided CUSUM statistic > h

Fairness core: tau and h are chosen ON THE TRAINING SEGMENT (first 40% of
each cohort) so each challenger's training false-alarm rate is <= the
incumbent's on the same segment, with a production ARL floor (>=250bd).
Lag is then compared out-of-sample only.
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

from studylib.changepoint import bocpd_alarm_series, cusum_alarm_series  # noqa: E402
from run_qis_test import pit_stress_probs, block_bootstrap_p  # noqa: E402
from run_study import (  # noqa: E402
    REGIME_BASE,
    REGIME_EXTRA,
    _era_slices,
    _stress_labels,
    build_cohort_panel,
)

SEED = 7
DEADTIME = 20
TRAIN_FRAC = 0.40
ARL_FLOOR = 250  # min business days between false alarms (production grade)


def alarms_from_scores(scores: np.ndarray, tau: float) -> list[int]:
    out, cool = [], 0
    for i, v in enumerate(scores):
        if cool:
            cool -= 1
            continue
        if v > tau:
            out.append(i)
            cool = DEADTIME
    return out


def false_alarm_rate(alarm_idx: list[int], labels: np.ndarray) -> float:
    """False alarms per 250bd among non-stress days."""
    fa = sum(1 for a in alarm_idx if not labels[a])
    calm_days = int((~labels).sum())
    return fa * 250.0 / max(calm_days, 1)


def episode_lags(alarm_idx: list[int], labels: np.ndarray) -> list[int | None]:
    """Per stress episode: business days from onset to first alarm inside
    the episode window (None = missed)."""
    lags, t, n = [], 0, len(labels)
    aset = sorted(alarm_idx)
    while t < n:
        if labels[t] and (t == 0 or not labels[t - 1]):
            end = t
            while end < n and labels[end]:
                end += 1
            hit = next((a for a in aset if t <= a < end), None)
            lags.append(None if hit is None else hit - t)
            t = end
        else:
            t += 1
    return lags


def match_threshold(
    scores: np.ndarray,
    labels: np.ndarray,
    budget: float,
    lo: float,
    hi: float,
    steps: int = 60,
) -> float:
    """Highest sensitivity threshold whose TRAINING false-alarm rate stays
    within the incumbent's budget AND the ARL floor."""
    best = hi
    hard_cap = 250.0 / ARL_FLOOR  # max false alarms per 250bd
    target = min(budget, hard_cap)
    for tau in np.linspace(hi, lo, steps):  # descend = increase sensitivity
        fa = false_alarm_rate(alarms_from_scores(scores, tau), labels)
        if fa <= target:
            best = tau
        else:
            break
    return float(best)


def run_cohort(cohort: str) -> dict:
    t0 = time.time()
    rets = build_cohort_panel(cohort)
    cols = [c for c in REGIME_BASE + REGIME_EXTRA if c in rets]
    X = rets[cols]
    labels_full = pd.Series(_stress_labels(rets.index), index=rets.index)

    # ---- incumbent: PIT HMM filtered stress probability ----
    pit = pit_stress_probs(X, treated=False)
    joined = pit.join(labels_full.rename("label"), how="inner").dropna()
    idx = joined.index
    labels = joined["label"].to_numpy().astype(bool)
    inc_scores = joined["stress"].to_numpy()

    # ---- challengers: causal scores on standardized equity returns ----
    # z-scored with trailing 250d stats (shifted), same info set as arms
    eq = rets["NASDAQCOM_ret"]
    mu = eq.rolling(250).mean().shift(1)
    sd = eq.rolling(250).std().shift(1)
    z = ((eq - mu) / sd.replace(0, np.nan)).reindex(idx).fillna(0.0).to_numpy()
    z = np.clip(z, -10, 10)
    bocpd_scores = bocpd_alarm_series(z)
    cusum_scores = cusum_alarm_series(np.abs(z), k=0.5, h=1e9)  # statistic only

    # ---- threshold matching on the training segment ----
    n_train = int(len(idx) * TRAIN_FRAC)
    tr_labels = labels[:n_train]
    inc_alarms_tr = alarms_from_scores(inc_scores[:n_train], 0.5)
    budget = false_alarm_rate(inc_alarms_tr, tr_labels)

    tau_b = match_threshold(bocpd_scores[:n_train], tr_labels, budget, 0.05, 0.95)
    tau_c = match_threshold(cusum_scores[:n_train], tr_labels, budget, 1.0, 40.0)

    # ---- out-of-sample evaluation ----
    oos = slice(n_train, len(idx))
    oos_labels = labels[oos]
    arms = {
        "incumbent": alarms_from_scores(inc_scores[oos], 0.5),
        "bocpd": alarms_from_scores(bocpd_scores[oos], tau_b),
        "cusum": alarms_from_scores(cusum_scores[oos], tau_c),
    }
    out = {
        "cohort": cohort,
        "n_oos_days": int(len(oos_labels)),
        "train_budget_fa_per_250bd": round(budget, 3),
        "thresholds": {"bocpd_tau": round(tau_b, 3), "cusum_h": round(tau_c, 2)},
    }
    lag_vectors = {}
    for arm, alarm_idx in arms.items():
        lags = episode_lags(alarm_idx, oos_labels)
        detected = [x for x in lags if x is not None]
        lag_vectors[arm] = lags
        out[arm] = {
            "episodes": len(lags),
            "detected": len(detected),
            "median_lag": float(np.median(detected)) if detected else None,
            "fa_per_250bd": round(false_alarm_rate(alarm_idx, oos_labels), 3),
        }

    # paired per-episode lag differences vs incumbent (missed = worst lag+1)
    def paired_diff(challenger):
        inc = lag_vectors["incumbent"]
        cha = lag_vectors[challenger]
        worst = max([x for x in inc + cha if x is not None] or [0]) + 1
        pairs = [
            ((i if i is not None else worst) - (c if c is not None else worst))
            for i, c in zip(inc, cha)
        ]
        return np.array(pairs, dtype=float)  # positive = challenger faster

    for challenger in ("bocpd", "cusum"):
        d = paired_diff(challenger)
        out[challenger]["paired_mean_lag_gain"] = (
            round(float(d.mean()), 2) if len(d) else None
        )
        out[challenger]["bootstrap_p"] = (
            round(block_bootstrap_p(d), 4) if len(d) >= 5 else None
        )

    # era stability (sign of median-lag improvement per era)
    eras = {}
    era_map = _era_slices(rets)
    oos_index = idx[oos]
    for era, sub in era_map.items():
        mask = oos_index.isin(sub.index)
        if mask.sum() < 250:
            continue
        el = oos_labels[mask]
        if el.sum() == 0:
            continue
        era_entry = {}
        for arm, alarm_idx in arms.items():

            # remap alarms into the era-restricted frame
            posmap = {g: li for li, g in enumerate(np.where(mask)[0])}
            a_local = [posmap[a] for a in alarm_idx if a in posmap]
            lags = [x for x in episode_lags(a_local, el) if x is not None]
            era_entry[arm] = float(np.median(lags)) if lags else None
        eras[era] = era_entry
    out["eras"] = eras
    out["runtime_s"] = round(time.time() - t0, 1)
    return out


def main() -> None:
    results = {}
    for cohort in ("C10", "C20", "C36"):
        print(f"=== {cohort} ===", flush=True)
        results[cohort] = run_cohort(cohort)
        print(json.dumps(results[cohort], indent=1, default=str), flush=True)
    Path("research/results/bocpd_test.json").write_text(
        json.dumps(results, indent=2, default=str)
    )
    print("saved research/results/bocpd_test.json")


if __name__ == "__main__":
    main()
