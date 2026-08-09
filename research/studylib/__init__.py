"""Study machinery for the PRISM historical validation study.

Wraps — never patches — the frozen PRISM library. Everything here is
point-in-time-safe or purely evaluative; see research/protocol.md.
"""

from .backtests import (  # noqa: F401
    basel_traffic_light,
    christoffersen_independence,
    conditional_coverage,
    kupiec_pof,
)
from .forecast_tests import diebold_mariano, spa_test  # noqa: F401
from .metrics import (  # noqa: F401
    auroc,
    confusion_at,
    detection_lags,
    event_hit_test,
)
from .breaks import sup_chow  # noqa: F401
from .pit import pit_regime_probs, rolling_var_series  # noqa: F401
