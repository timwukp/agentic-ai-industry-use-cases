"""Tools for the Real Estate Valuation Agent."""

from .valuation import (  # noqa: F401
    calculate_replacement_cost,
    estimate_property_value,
    generate_cma_report,
    get_comparables,
)
from .market import (  # noqa: F401
    get_market_conditions,
    get_market_forecast,
    get_market_trends,
    get_neighborhood_analysis,
)
from .investment import (  # noqa: F401
    analyze_rental_income,
    calculate_cap_rate,
    calculate_roi,
    get_investment_comparison,
)
from .property import (  # noqa: F401
    check_zoning,
    get_property_details,
    get_tax_assessment,
    search_properties,
)
from .due_diligence import (  # noqa: F401
    assess_environmental_risk,
    check_title_status,
    generate_dd_checklist,
    review_legal_documents,
)
from .lease_admin import (  # noqa: F401
    calculate_lease_liability,
    extract_lease_terms,
    predict_tenant_churn,
    track_critical_dates,
)
from .esg_assessment import (  # noqa: F401
    analyze_energy_performance,
    assess_climate_risk,
    calculate_retrofit_roi,
    generate_gresb_report,
)
