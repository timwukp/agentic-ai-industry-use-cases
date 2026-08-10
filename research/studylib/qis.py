"""Ledoit-Wolf shrinkage covariance for the QIS regime test.

At the QIS-literature scale (p in the hundreds) the full quadratic-inverse
machinery matters; at PRISM's p≈5 the analytical linear-shrinkage estimator
(Ledoit-Wolf 2004, the same family the QIS paper generalizes) is the
appropriate faithful representative: it shares the Stein-shrinkage core,
is provably well-conditioned, and avoids kernel-estimation noise that the
nonlinear variant introduces when p is tiny. The protocol names this file
as the implementation of record; the synthetic self-calibration tests below
gate its use (a cleaner that fails its own calibration disqualifies the
TEST, not the hypothesis).

Weighted variant: HMM states weight observations by responsibility, so the
estimator accepts per-row weights (the state's posterior probabilities).
"""

import numpy as np


def shrunk_covariance(X: np.ndarray, weights: np.ndarray | None = None) -> np.ndarray:
    """Ledoit-Wolf (2004) linear shrinkage toward scaled identity, with
    optional observation weights. Returns a positive-definite matrix.

    Sigma_hat = (1-rho) * S + rho * mu * I
    where mu = tr(S)/p and rho minimizes expected Frobenius loss.
    """
    X = np.asarray(X, dtype=float)
    n, p = X.shape
    if weights is None:
        w = np.full(n, 1.0 / n)
    else:
        w = np.asarray(weights, dtype=float)
        w = w / max(w.sum(), 1e-300)

    mean = w @ X
    Xc = X - mean
    # weighted sample covariance (biased normalization, matching hmmlearn)
    S = (Xc * w[:, None]).T @ Xc

    mu = np.trace(S) / p
    delta2 = float(np.sum((S - mu * np.eye(p)) ** 2))  # dispersion of S
    if delta2 <= 1e-300:
        return S + 1e-9 * np.eye(p)

    # beta2: estimation error of S, estimated from the data
    # sum_i w_i^2 * || x_i x_i^T - S ||_F^2  (weighted analog of LW2004)
    beta2 = 0.0
    for i in range(n):
        if w[i] == 0.0:
            continue
        outer = np.outer(Xc[i], Xc[i])
        beta2 += (w[i] ** 2) * float(np.sum((outer - S) ** 2))
    beta2 = min(beta2, delta2)

    rho = beta2 / delta2
    sigma = (1.0 - rho) * S + rho * mu * np.eye(p)
    # numerical floor: PD guarantee
    return sigma + 1e-10 * np.eye(p)
