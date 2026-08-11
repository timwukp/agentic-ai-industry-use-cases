"""Change-point instruments for the BOCPD fast-alarm test.

Two detectors, both strictly causal:
- BOCPD (Adams-MacKay 2007) with Student-t emissions via a Normal-Inverse-
  Gamma conjugate model (predictive is Student-t — robust to the fat tails
  that make Gaussian BOCPD fire on every outlier, the literature's >90%
  false-discovery failure mode).
- Two-sided CUSUM (Page 1954) on standardized observations — the classical
  minimal instrument, Moustakides-optimal under Lorden's criterion.

Both consume one observation at a time; nothing at date t sees t+1.
Self-calibration gates live in tests/unit/test_studylib.py.
"""

import numpy as np
from scipy import stats


class StudentTBOCPD:
    """BOCPD with NIG conjugate emissions (Student-t predictive).

    Tracks the run-length posterior; alarm signal is
    P(run length <= k) at each step. Hazard is constant.
    """

    def __init__(
        self,
        hazard: float = 1.0 / 250.0,
        mu0: float = 0.0,
        kappa0: float = 1.0,
        alpha0: float = 1.0,
        beta0: float = 1.0,
        max_run: int = 2000,
    ):
        self.h = hazard
        self.prior = (mu0, kappa0, alpha0, beta0)
        self.max_run = max_run
        self.reset()

    def reset(self) -> None:
        mu0, k0, a0, b0 = self.prior
        self.r_probs = np.array([1.0])  # P(run length) — starts at r=0
        self.mu = np.array([mu0])
        self.kappa = np.array([k0])
        self.alpha = np.array([a0])
        self.beta = np.array([b0])

    # Without a df cap the NIG posterior's alpha grows 0.5/obs, so the
    # Student-t predictive silently converges to Gaussian on long runs and
    # re-inherits the outlier-firing failure mode the robust variant exists
    # to prevent (caught by the Phase-3 t(3) calibration test). df=30 is
    # already near-Gaussian — the calibration test showed it still fires on
    # t(3) samples; df<=8 keeps the predictive tails genuinely heavy while
    # a 1.5-sigma sustained MEAN shift still dominates the likelihood.
    DF_MAX = 8.0

    def _predictive_logpdf(self, x: float) -> np.ndarray:
        """Student-t predictive per run-length hypothesis (df clamped)."""
        df = np.minimum(2.0 * self.alpha, self.DF_MAX)
        scale = np.sqrt(self.beta * (self.kappa + 1.0) / (self.alpha * self.kappa))
        return stats.t.logpdf(x, df=df, loc=self.mu, scale=scale)

    def update(self, x: float) -> float:
        """Consume one observation; return P(run length <= 5) AFTER update."""
        logpred = self._predictive_logpdf(x)
        pred = np.exp(logpred - logpred.max())
        pred *= np.exp(logpred.max())  # unnormalized but stable

        growth = self.r_probs * pred * (1.0 - self.h)
        cp = float(np.sum(self.r_probs * pred * self.h))
        new_probs = np.concatenate([[cp], growth])
        s = new_probs.sum()
        if s <= 0 or not np.isfinite(s):
            self.reset()
            return 0.0
        new_probs /= s

        # conjugate NIG updates per run-length hypothesis
        mu0, k0, a0, b0 = self.prior
        kappa_new = self.kappa + 1.0
        mu_new = (self.kappa * self.mu + x) / kappa_new
        alpha_new = self.alpha + 0.5
        beta_new = self.beta + 0.5 * self.kappa * (x - self.mu) ** 2 / kappa_new

        self.mu = np.concatenate([[mu0], mu_new])
        self.kappa = np.concatenate([[k0], kappa_new])
        self.alpha = np.concatenate([[a0], alpha_new])
        self.beta = np.concatenate([[b0], beta_new])
        self.r_probs = new_probs

        if len(self.r_probs) > self.max_run:  # truncate ancient hypotheses
            self.r_probs = self.r_probs[: self.max_run]
            self.mu = self.mu[: self.max_run]
            self.kappa = self.kappa[: self.max_run]
            self.alpha = self.alpha[: self.max_run]
            self.beta = self.beta[: self.max_run]
            self.r_probs /= self.r_probs.sum()

        k = min(6, len(self.r_probs))
        return float(self.r_probs[:k].sum())  # P(run <= 5)


def bocpd_alarm_series(x: np.ndarray, hazard: float = 1.0 / 250.0) -> np.ndarray:
    """P(run length <= 5) after each observation (strictly causal)."""
    det = StudentTBOCPD(hazard=hazard)
    out = np.empty(len(x))
    for i, xi in enumerate(x):
        out[i] = det.update(float(xi))
    return out


class GaussianBOCPD(StudentTBOCPD):
    """Falsification control: effectively-Gaussian emissions — the
    literature's failure mode (fires on fat-tail outliers). The df clamp is
    lifted and alpha0 is large, so the predictive is numerically normal."""

    DF_MAX = 1e9

    def __init__(self, hazard: float = 1.0 / 250.0):
        super().__init__(hazard=hazard, alpha0=1e3, beta0=1e3)


def cusum_alarm_series(x: np.ndarray, k: float = 0.5, h: float = 8.0) -> np.ndarray:
    """Two-sided CUSUM statistic max(S+, S-) per step, reset on alarm.

    k = reference value (drift allowance, in sigma units of the
    standardized input); h = decision threshold. Returns the running
    statistic; an alarm is statistic > h (caller thresholds).
    """
    sp = sm = 0.0
    out = np.empty(len(x))
    for i, xi in enumerate(x):
        sp = max(0.0, sp + xi - k)
        sm = max(0.0, sm - xi - k)
        stat = max(sp, sm)
        out[i] = stat
        if stat > h:  # restart after alarm — sequential-detection convention
            sp = sm = 0.0
    return out
