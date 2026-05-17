"""Tools for the Insurance Claims Agent."""

from .claims import (  # noqa: F401
    assess_damage,
    get_claim_status,
    list_claims,
    submit_claim,
)
from .fraud_detection import (  # noqa: F401
    analyze_fraud_risk,
    check_fraud_patterns,
    generate_fraud_report,
    get_fraud_dashboard,
)
from .policy import (  # noqa: F401
    check_coverage,
    get_policy_history,
    search_policies,
    verify_policy,
)
from .settlement import (  # noqa: F401
    approve_settlement,
    calculate_settlement,
    estimate_reserve,
    get_settlement_analytics,
)
from .underwriting import (  # noqa: F401
    assess_risk_factors,
    calculate_premium,
    review_application,
    suggest_policy_terms,
)
from .loss_prevention import (  # noqa: F401
    analyze_loss_patterns,
    generate_prevention_alert,
    predict_loss_probability,
    recommend_risk_mitigation,
)
from .retention import (  # noqa: F401
    analyze_customer_lifecycle,
    compare_competitive_pricing,
    generate_renewal_offer,
    predict_churn_risk,
)
