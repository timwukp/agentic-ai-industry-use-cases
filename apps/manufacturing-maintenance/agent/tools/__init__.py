"""Tools for the Manufacturing Maintenance Agent."""

from .equipment import (  # noqa: F401
    get_equipment_alerts,
    get_equipment_list,
    get_equipment_status,
    get_sensor_data,
)
from .prediction import (  # noqa: F401
    analyze_vibration,
    detect_anomalies,
    get_reliability_metrics,
    predict_failure,
)
from .maintenance import (  # noqa: F401
    generate_work_order,
    get_maintenance_calendar,
    get_maintenance_history,
    schedule_maintenance,
)
from .parts import (  # noqa: F401
    check_spare_parts,
    get_parts_forecast,
    get_parts_inventory_report,
    order_spare_parts,
)
from .quality_rca import (  # noqa: F401
    analyze_defect_pattern,
    generate_8d_report,
    perform_root_cause_analysis,
    recommend_corrective_action,
)
from .supply_chain import (  # noqa: F401
    assess_disruption_impact,
    find_alternative_suppliers,
    generate_contingency_plan,
    simulate_shortage_scenario,
)
from .carbon_tracking import (  # noqa: F401
    calculate_carbon_footprint,
    generate_esg_report,
    identify_reduction_opportunities,
    track_scope3_emissions,
)
