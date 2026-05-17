"""Tools for the Finance Trading Agent."""

from .market_data import (  # noqa: F401
    get_historical_prices,
    get_market_overview,
    get_sector_performance,
    get_stock_quote,
)
from .risk_analysis import (  # noqa: F401
    analyze_portfolio_risk,
    calculate_var,
    monte_carlo_simulation,
    stress_test_portfolio,
)
from .portfolio import (  # noqa: F401
    calculate_pnl,
    get_portfolio_allocation,
    get_portfolio_positions,
    suggest_rebalancing,
)
from .trade import (  # noqa: F401
    cancel_order,
    get_order_status,
    get_trade_history,
    place_order,
)
from .aml_kyc import (  # noqa: F401
    analyze_customer_behavior,
    check_sanctions_list,
    generate_sar_report,
    screen_transaction,
)
from .regulatory_reporting import (  # noqa: F401
    check_compliance_gaps,
    generate_regulatory_report,
    monitor_rule_changes,
    validate_report_data,
)
from .event_trading import (  # noqa: F401
    analyze_earnings_call,
    assess_macro_event_impact,
    generate_trade_signal,
    scan_alternative_data,
)
