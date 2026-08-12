"""Impact functions: Bayesian local projections (Jordà-style) with a
normal-inverse-gamma conjugate prior.

The deliverable: response of an asset at horizons 1..H to a +1σ shock in a
driver, with posterior credible bands — the mathematical function the user
asked for, with uncertainty honestly attached.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass
class ImpactResult:
    shock: str
    response: str
    horizons: list
    beta_mean: list  # response per +1σ shock, cumulated to each horizon
    band68: list  # (lo, hi) per horizon
    band95: list
    prob_positive_20d: float
    n_obs: int
    grade: str = "HYPOTHESIS"

    def to_payload(self) -> dict:
        def r(v):
            return None if v is None or np.isnan(v) else round(float(v), 6)

        return {
            "shock": self.shock,
            "response": self.response,
            "horizons": list(self.horizons),
            "beta_mean": [r(b) for b in self.beta_mean],
            "band68": [[r(lo), r(hi)] for lo, hi in self.band68],
            "band95": [[r(lo), r(hi)] for lo, hi in self.band95],
            "prob_positive_20d": r(self.prob_positive_20d),
            "n_obs": int(self.n_obs),
            "grade": self.grade,
            "unit": "response units per +1 sigma shock",
        }


def _nig_posterior(
    X: np.ndarray,
    y: np.ndarray,
    ridge_lambda: float,
    prior_a0: float = 1e-3,
    n_eff: float | None = None,
):
    """Normal-inverse-gamma conjugate regression: returns (mean, cov_scale,
    df, s2) so the shock coefficient's marginal is a scaled Student-t.

    n_eff overrides the row count in the sigma^2 update for weighted designs
    where many rows carry near-zero weight (see regime_conditional)."""
    n, k = X.shape
    n_stat = n if n_eff is None else n_eff
    prior_prec = ridge_lambda * np.eye(k)
    prec = X.T @ X + prior_prec
    cov = np.linalg.inv(prec)
    mean = cov @ (X.T @ y)
    resid = y - X @ mean
    # The sigma^2 prior must scale with the response's variance: an absolute
    # prior (b0=1) dominates b_post when y is daily-return magnitude (RSS over
    # 10y at h=1 is ~0.25) and inflates the bands ~3x at short horizons.
    # b0 anchors to TOTAL var(y) (not residual variance) — harmless at this
    # a0, but do not raise a0 without switching the anchor to residual scale.
    # Degenerate y (var ~ 0) must be refused by the CALLER: this floor exists
    # only to keep b_post positive, it is not an uncertainty backstop.
    b0 = prior_a0 * max(float(np.var(y)), 1e-12)
    a_post = prior_a0 + n_stat / 2.0
    b_post = b0 + 0.5 * (resid @ resid + mean @ prior_prec @ mean)
    s2 = b_post / a_post  # Student-t scale b/a (NOT the IG mean b/(a-1))
    df = 2 * a_post
    return mean, cov, df, s2


def local_projection(
    panel: pd.DataFrame,
    shock_col: str,
    response_col: str,
    horizons=range(1, 21),
    controls: list[str] | None = None,
    ridge_lambda: float = 1.0,
    n_lags: int = 5,
    prior_a0: float = 1e-3,
    weights: pd.Series | None = None,
) -> ImpactResult:
    """For each horizon h, regress cumulated response(t+1..t+h) on shock(t)
    standardized to unit variance, controlling for n_lags lags of both.

    weights (0..1 per row) runs textbook WLS: rows of the design are scaled
    by sqrt(w) AFTER lag construction, and the sigma^2 update counts the
    effective sample (sum w)^2 / sum(w^2), not raw rows."""
    from scipy import stats

    shock = panel[shock_col]
    shock = (shock - shock.mean()) / shock.std(ddof=0)
    resp = panel[response_col]

    horizons = list(horizons)
    beta_mean, band68, band95 = [], [], []
    prob_pos_20 = np.nan
    n_used = 0

    for h in horizons:
        cum_resp = resp.rolling(h).sum().shift(-h)  # forward h-day cumulation
        cols = {"shock": shock}
        for lag in range(1, n_lags + 1):
            cols[f"shock_l{lag}"] = shock.shift(lag)
            cols[f"resp_l{lag}"] = resp.shift(lag)
        for c in controls or []:
            cols[c] = panel[c]
        df = pd.DataFrame(cols)
        df["_y"] = cum_resp
        if weights is not None:
            df["_w"] = weights.reindex(df.index).fillna(0.0).clip(0, 1)
        df = df.dropna()
        if len(df) < 50:
            beta_mean.append(np.nan)
            band68.append((np.nan, np.nan))
            band95.append((np.nan, np.nan))
            continue
        y = df.pop("_y").to_numpy()
        if weights is not None:
            w = df.pop("_w").to_numpy()
            w_sq = float((w**2).sum())
            n_eff = float(w.sum()) ** 2 / w_sq if w_sq > 0 else 0.0
            sw = np.sqrt(w)
            y = y * sw
            X = np.column_stack([sw, df.to_numpy() * sw[:, None]])
        else:
            n_eff = float(len(df))
            X = np.column_stack([np.ones(len(df)), df.to_numpy()])
        # a constant/near-constant response (stale or forward-filled series)
        # or a near-empty effective sample carries no information — refuse
        # rather than report false certainty (daily-return h-cumulations have
        # var ~ 1e-4*h; 1e-14 is 10 orders below any live series)
        if float(np.var(y)) < 1e-14 or n_eff < 50:
            beta_mean.append(np.nan)
            band68.append((np.nan, np.nan))
            band95.append((np.nan, np.nan))
            continue
        mean, cov, dof, s2 = _nig_posterior(
            X, y, ridge_lambda, prior_a0=prior_a0, n_eff=n_eff
        )
        b = mean[1]  # shock coefficient (intercept is col 0)
        sd = float(np.sqrt(s2 * cov[1, 1]))
        if not np.isfinite(sd) or sd <= 0:
            beta_mean.append(np.nan)
            band68.append((np.nan, np.nan))
            band95.append((np.nan, np.nan))
            continue
        t68 = stats.t.ppf(0.84, dof)
        t95 = stats.t.ppf(0.975, dof)
        beta_mean.append(float(b))
        band68.append((b - t68 * sd, b + t68 * sd))
        band95.append((b - t95 * sd, b + t95 * sd))
        n_used = len(df)
        if h == max(horizons):
            prob_pos_20 = float(1 - stats.t.cdf(0.0, dof, loc=b, scale=sd))

    return ImpactResult(
        shock=shock_col,
        response=response_col,
        horizons=horizons,
        beta_mean=beta_mean,
        band68=band68,
        band95=band95,
        prob_positive_20d=prob_pos_20,
        n_obs=n_used,
    )


def regime_conditional(
    panel: pd.DataFrame,
    shock_col: str,
    response_col: str,
    regime_probs: pd.Series,
    **kwargs,
) -> ImpactResult:
    """Soft regime conditioning: P(state) becomes the WLS row weight inside
    local_projection. Row-level weighting (not series pre-scaling) keeps the
    shock standardization and the lag columns on their raw scales, and the
    sigma^2 update counts the effective sample (sum w)^2 / sum(w^2) — a
    regime active 5% of the time holds ~5% of the information, not 100%."""
    p = regime_probs.reindex(panel.index).fillna(0.0).clip(0, 1)
    return local_projection(panel, shock_col, response_col, weights=p, **kwargs)
