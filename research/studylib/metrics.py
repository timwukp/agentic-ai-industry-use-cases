"""Evaluation metrics: AUROC, confusion, detection lag, event-hit test."""

import numpy as np
from scipy.stats import binomtest


def auroc(scores: np.ndarray, labels: np.ndarray) -> float:
    """Rank-based AUROC (Mann-Whitney): P(score_pos > score_neg)."""
    s = np.asarray(scores, float)
    y = np.asarray(labels, dtype=bool)
    mask = ~np.isnan(s)
    s, y = s[mask], y[mask]
    n_pos, n_neg = int(y.sum()), int((~y).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    ranks = np.argsort(np.argsort(s)) + 1.0  # average-rank ties ignored (ok at n large)
    u = ranks[y].sum() - n_pos * (n_pos + 1) / 2.0
    return float(u / (n_pos * n_neg))


def confusion_at(scores, labels, threshold: float = 0.5) -> dict:
    s = np.asarray(scores, float)
    y = np.asarray(labels, dtype=bool)
    pred = s > threshold
    return {
        "tp": int((pred & y).sum()),
        "fp": int((pred & ~y).sum()),
        "fn": int((~pred & y).sum()),
        "tn": int((~pred & ~y).sum()),
    }


def detection_lags(scores, labels, threshold: float = 0.5) -> list[int]:
    """For each contiguous True-run in labels, business days from run start
    until scores first exceeds threshold (within the run). Runs never
    detected contribute the run length (conservative)."""
    s = np.asarray(scores, float)
    y = np.asarray(labels, dtype=bool)
    lags = []
    t = 0
    n = len(y)
    while t < n:
        if y[t] and (t == 0 or not y[t - 1]):
            end = t
            while end < n and y[end]:
                end += 1
            hit = (
                np.argmax(s[t:end] > threshold)
                if (s[t:end] > threshold).any()
                else None
            )
            lags.append(int(hit) if hit is not None else end - t)
            t = end
        else:
            t += 1
    return lags


def event_hit_test(
    spike_days: np.ndarray, event_positions: list[int], window: int = 3
) -> dict:
    """H5b: fraction of events with a spike within ±window positions,
    binomial-tested against the base rate of spike days."""
    spikes = np.asarray(spike_days, dtype=bool)
    n = len(spikes)
    if n == 0 or not event_positions:
        return {"hits": 0, "events": 0, "hit_rate": np.nan, "p": np.nan}
    hits = 0
    for pos in event_positions:
        lo, hi = max(0, pos - window), min(n, pos + window + 1)
        if spikes[lo:hi].any():
            hits += 1
    base = float(spikes.mean())
    # probability a ±window neighborhood contains ≥1 spike by chance
    p_window = 1.0 - (1.0 - base) ** (2 * window + 1)
    res = binomtest(hits, len(event_positions), p_window, alternative="greater")
    return {
        "hits": hits,
        "events": len(event_positions),
        "hit_rate": hits / len(event_positions),
        "base_window_prob": p_window,
        "p": float(res.pvalue),
    }
