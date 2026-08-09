"""PRISM — Probabilistic Regime & Impact Shock Model.

An original composition of established methods — Gaussian-HMM regimes,
transfer-entropy/Granger causality under BH FDR control, Bayesian local
projections, EVT peaks-over-threshold — with a validation protocol that
decides CONFIRMED vs HYPOTHESIS. Pure functions over pandas inputs; all
AWS I/O lives in runner.py.
"""

PRISM_VERSION = "2026-08-09.1"

from .data import build_panel, factor_series, to_returns  # noqa: E402,F401
from .regime import RegimeResult, fit_regimes  # noqa: E402,F401
from .causality import (  # noqa: E402,F401
    causality_scan,
    granger_pvalue,
    te_pvalue,
    transfer_entropy,
)
from .impact import ImpactResult, local_projection  # noqa: E402,F401
from .tails import TailResult, bipower_jump_stat, fit_gpd_pot  # noqa: E402,F401
from .validate import confirm, walk_forward  # noqa: E402,F401
