"""Regime layer: Gaussian HMM over standardized market state variables."""

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from hmmlearn.hmm import GaussianHMM


@dataclass
class RegimeResult:
    state_probs: pd.DataFrame  # date x state label
    viterbi: pd.Series  # date -> state label
    state_means: dict  # label -> {col: mean in original units}
    persistence: dict  # label -> expected duration (days)
    labels: list = field(default_factory=list)
    converged: bool = False
    log_likelihood: float = float("nan")

    def to_payload(self) -> dict:
        latest = self.state_probs.iloc[-1]
        return {
            "current_state": str(self.viterbi.iloc[-1]),
            "state_probs": {k: round(float(v), 4) for k, v in latest.items()},
            "states": {
                label: {
                    "means": {
                        c: round(float(m), 6)
                        for c, m in self.state_means[label].items()
                    },
                    "expected_duration_days": round(float(self.persistence[label]), 1),
                }
                for label in self.labels
            },
            "converged": bool(self.converged),
            "log_likelihood": round(float(self.log_likelihood), 1),
            "as_of": str(self.state_probs.index[-1].date()),
        }


def _state_labels(n: int) -> list[str]:
    if n == 2:
        return ["stress", "risk-on"]
    if n == 3:
        return ["stress", "neutral", "risk-on"]
    return [f"state-{i}" for i in range(n)]


def fit_regimes(X: pd.DataFrame, n_states: int = 3, seed: int = 7) -> RegimeResult:
    """Fit a Gaussian HMM on standardized columns.

    States are relabeled by ascending mean of the FIRST column (assumed to be
    the equity-return series), so 'stress' is always the worst-mean state —
    hmmlearn's arbitrary state numbering would otherwise flip labels between
    nightly runs and make the dashboard ribbon incoherent day-to-day.
    """
    mu, sigma = X.mean(), X.std(ddof=0).replace(0, 1.0)
    Z = ((X - mu) / sigma).to_numpy()

    hmm = GaussianHMM(
        n_components=n_states,
        covariance_type="full",
        n_iter=200,
        random_state=seed,
    )
    hmm.fit(Z)
    order = np.argsort(hmm.means_[:, 0])  # ascending first-column mean
    labels = _state_labels(n_states)
    raw_to_label = {int(raw): labels[pos] for pos, raw in enumerate(order)}

    probs = hmm.predict_proba(Z)
    viterbi_raw = hmm.predict(Z)

    state_probs = pd.DataFrame(
        {labels[pos]: probs[:, raw] for pos, raw in enumerate(order)},
        index=X.index,
    )[labels]
    viterbi = pd.Series(
        [raw_to_label[int(s)] for s in viterbi_raw], index=X.index, name="state"
    )

    state_means = {}
    persistence = {}
    for pos, raw in enumerate(order):
        label = labels[pos]
        # de-standardize back to original units
        state_means[label] = dict(zip(X.columns, hmm.means_[raw] * sigma + mu))
        p_stay = float(hmm.transmat_[raw, raw])
        persistence[label] = 1.0 / max(1e-9, 1.0 - p_stay)

    return RegimeResult(
        state_probs=state_probs,
        viterbi=viterbi,
        state_means=state_means,
        persistence=persistence,
        labels=labels,
        converged=bool(hmm.monitor_.converged),
        log_likelihood=float(hmm.score(Z)),
    )
