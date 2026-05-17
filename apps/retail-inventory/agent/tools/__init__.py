"""Tools for the Retail Inventory Agent."""

from .inventory import (  # noqa: F401
    check_inventory,
    get_inventory_summary,
    get_stockout_report,
    transfer_stock,
)
from .demand_forecast import (  # noqa: F401
    auto_reorder,
    forecast_demand,
    get_abc_analysis,
    get_demand_trends,
)
from .pricing import (  # noqa: F401
    get_competitive_intelligence,
    get_margin_report,
    get_pricing_analysis,
    optimize_pricing,
)
from .supplier import (  # noqa: F401
    create_purchase_order,
    get_supplier_performance,
    get_supplier_risk_report,
    list_suppliers,
)
from .returns import (  # noqa: F401
    analyze_return_reason,
    detect_return_fraud,
    determine_disposition,
    predict_return_probability,
)
from .omnichannel import (  # noqa: F401
    optimize_order_routing,
    reserve_inventory,
    resolve_inventory_conflict,
    sync_channel_stock,
)
from .dynamic_pricing import (  # noqa: F401
    calculate_optimal_price,
    generate_pricing_strategy,
    scan_competitor_prices,
    simulate_price_impact,
)
