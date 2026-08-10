"""Execute the pre-registered QIS-in-HMM regime test (protocol_qis.md).

Baseline vs treatment differ in exactly one thing: after each HMM fit, the
treatment replaces per-state covariances with their shrunk counterparts and
re-scores probabilities under the modified emission model. Everything else
(EM fit, seeds, PIT discipline, chronology) is identical, isolating the
covariance-estimation effect.
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

from prism import fit_regimes  # noqa: E402
from prism.regime import _state_labels  # noqa: E402
from studylib.metrics import auroc, detection_lags  # noqa: E402
from studylib.qis import shrunk_covariance  # noqa: E402
from run_study import (  # noqa: E402
    REGIME_BASE,
    REGIME_EXTRA,
    _era_slices,
    _stress_labels,
    build_cohort_panel,
)

SEED = 7
N_BOOT = 1000
BLOCK = 20


def _gaussian_logpdf(X: np.ndarray, mean: np.ndarray, cov: np.ndarray) -> np.ndarray:
    p = len(mean)
    L = np.linalg.cholesky(cov)
    diff = X - mean
    sol = np.linalg.solve_tri = np.linalg.solve(L, diff.T)
    maha = np.sum(sol**2, axis=0)
    logdet = 2.0 * np.sum(np.log(np.diag(L)))
    return -0.5 * (p * np.log(2 * np.pi) + logdet + maha)


def _forward_probs(logB: np.ndarray, startprob, transmat) -> np.ndarray:
    """Filtered state probabilities via the forward algorithm (log-space)."""
    T, K = logB.shape
    log_start = np.log(np.maximum(startprob, 1e-300))
    log_trans = np.log(np.maximum(transmat, 1e-300))
    alpha = np.zeros((T, K))
    a = log_start + logB[0]
    a -= a.max()
    alpha[0] = a
    for t in range(1, T):
        m = alpha[t - 1][:, None] + log_trans
        a = logB[t] + np.logaddexp.reduce(m, axis=0)
        a -= a.max()
        alpha[t] = a
    probs = np.exp(alpha)
    return probs / probs.sum(axis=1, keepdims=True)


def pit_stress_probs(X: pd.DataFrame, treated: bool) -> pd.DataFrame:
    """Point-in-time filtered P(state) series, baseline or QIS-treated.

    Same scheme as studylib.pit: monthly expanding refits, the last filtered
    probability applied to the following month. Treatment recomputes the
    emission covariances with shrinkage and re-runs ONLY the forward filter
    (transition matrix and means kept from EM) — the protocol's isolation of
    the covariance effect.
    """
    month_ends = X.resample("ME").last().index
    start = X.index.min() + pd.DateOffset(years=3)
    labels = _state_labels(3)
    rows = []
    for i, me in enumerate(month_ends):
        if me < start:
            continue
        train = X.loc[:me]
        if len(train) < 250:
            continue
        try:
            res = fit_regimes(train, n_states=3, seed=SEED)
        except Exception:  # noqa: BLE001
            continue
        if not treated:
            last = res.state_probs.iloc[-1]
            probs_last = {k: float(last[k]) for k in labels}
        else:
            # rebuild emission model with shrunk per-state covariances
            mu = train.mean()
            sd = train.std(ddof=0).replace(0, 1.0)
            Z = ((train - mu) / sd).to_numpy()
            resp = res.state_probs.to_numpy()  # (T, K) smoothed responsibilities
            K = resp.shape[1]
            means = np.zeros((K, Z.shape[1]))
            covs = []
            for k in range(K):
                w = resp[:, k]
                wsum = max(w.sum(), 1e-12)
                means[k] = (w[:, None] * Z).sum(axis=0) / wsum
                covs.append(shrunk_covariance(Z - 0.0, weights=w))
            # forward-filter under modified emissions; empirical start/trans
            logB = np.column_stack(
                [_gaussian_logpdf(Z, means[k], covs[k]) for k in range(K)]
            )
            # transition matrix from viterbi path of the original fit
            path = res.viterbi.map({lab: j for j, lab in enumerate(labels)}).to_numpy()
            trans = np.full((K, K), 1e-6)
            for a, b in zip(path[:-1], path[1:]):
                trans[a, b] += 1
            trans /= trans.sum(axis=1, keepdims=True)
            start_p = np.bincount(path, minlength=K) / len(path)
            probs = _forward_probs(logB, start_p, trans)
            probs_last = {lab: float(probs[-1, j]) for j, lab in enumerate(labels)}
        nxt = month_ends[i + 1] if i + 1 < len(month_ends) else X.index.max()
        for d in X.index[(X.index > me) & (X.index <= nxt)]:
            rows.append({"date": d, **probs_last})
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).set_index("date")


def block_bootstrap_p(diff: np.ndarray, seed: int = SEED) -> float:
    """P(pooled improvement <= 0) via stationary block bootstrap on the
    paired daily score differences (treated - baseline stress prob signed
    by the label: higher stress prob on stress days = better)."""
    rng = np.random.default_rng(seed)
    n = len(diff)
    if n < 100:
        return float("nan")
    obs = diff.mean()
    n_blocks = int(np.ceil(n / BLOCK))
    count = 0
    for _ in range(N_BOOT):
        starts = rng.integers(0, n - BLOCK + 1, size=n_blocks)
        sample = np.concatenate([diff[s : s + BLOCK] for s in starts])[:n]
        # center under H0: no improvement
        if (sample - obs).mean() >= obs:
            count += 1
    return (count + 1) / (N_BOOT + 1)


def run_cohort(cohort: str) -> dict:
    t0 = time.time()
    rets = build_cohort_panel(cohort)
    cols = [c for c in REGIME_BASE + REGIME_EXTRA if c in rets]
    X = rets[cols]
    labels_all = pd.Series(_stress_labels(rets.index), index=rets.index)

    out = {"cohort": cohort, "cols": cols}
    series = {}
    for arm, treated in (("baseline", False), ("qis", True)):
        pit = pit_stress_probs(X, treated=treated)
        joined = pit.join(labels_all.rename("label"), how="inner").dropna()
        a = auroc(joined["stress"].to_numpy(), joined["label"].to_numpy())
        lags = detection_lags(joined["stress"].to_numpy(), joined["label"].to_numpy())
        series[arm] = joined
        out[arm] = {
            "h1b_auroc": round(float(a), 4),
            "median_lag": float(np.median(lags)) if lags else None,
            "n_days": len(joined),
        }
    # paired daily "correctness" scores: stress prob on stress days,
    # (1 - stress prob) on calm days — higher = better either way
    b, q = series["baseline"], series["qis"]
    common = b.index.intersection(q.index)
    lab = b.loc[common, "label"].to_numpy().astype(bool)
    score_b = np.where(lab, b.loc[common, "stress"], 1 - b.loc[common, "stress"])
    score_q = np.where(lab, q.loc[common, "stress"], 1 - q.loc[common, "stress"])
    diff = (score_q - score_b).astype(float)
    out["paired_mean_diff"] = round(float(diff.mean()), 6)
    out["bootstrap_p"] = round(block_bootstrap_p(diff), 4)

    # era stability of the AUROC sign
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
            "qis": round(a_q, 4),
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
    Path("research/results/qis_test.json").write_text(
        json.dumps(results, indent=2, default=str)
    )
    print("saved research/results/qis_test.json")


if __name__ == "__main__":
    main()
