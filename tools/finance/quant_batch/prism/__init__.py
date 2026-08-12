"""PRISM — Probabilistic Regime & Impact Shock Model.

An original composition of established methods — Gaussian-HMM regimes,
transfer-entropy/Granger causality under BH FDR control, Bayesian local
projections, EVT peaks-over-threshold — with a validation protocol that
decides CONFIRMED vs HYPOTHESIS. Pure functions over pandas inputs; all
AWS I/O lives in runner.py.
"""

PRISM_VERSION = "2026-08-10.1"  # +vol-filtered EVT (H4 candidate 2, back-tested green)

from .data import build_panel, factor_series, to_returns  # noqa: E402,F401
from .regime import RegimeResult, fit_regimes  # noqa: E402,F401
from .causality import (  # noqa: E402,F401
    causality_scan,
    granger_pvalue,
    te_pvalue,
    transfer_entropy,
)
from .impact import (  # noqa: E402,F401
    ImpactResult,
    local_projection,
    regime_conditional,
)
from .tails import (  # noqa: E402,F401
    TailResult,
    bipower_jump_stat,
    ewma_sigma,
    fit_gpd_by_regime,
    fit_gpd_pot,
    fit_vol_filtered_var,
)
from .validate import confirm, walk_forward  # noqa: E402,F401
