"""Tools for the Healthcare Medical Agent."""

from .records import (  # noqa: F401
    get_lab_results,
    get_medication_list,
    get_patient_summary,
    search_medical_records,
)
from .clinical import (  # noqa: F401
    assess_symptoms,
    calculate_risk_score,
    check_drug_interactions,
    get_clinical_guidelines,
)
from .scheduling import (  # noqa: F401
    get_provider_availability,
    get_upcoming_appointments,
    schedule_appointment,
    send_appointment_reminder,
)
from .analytics import (  # noqa: F401
    get_care_gap_analysis,
    get_patient_analytics,
    get_population_health_metrics,
    get_readmission_risk,
)
from .clinical_trials import (  # noqa: F401
    check_eligibility_criteria,
    generate_trial_summary,
    match_patient_to_trials,
    search_active_trials,
)
from .prior_authorization import (  # noqa: F401
    check_coverage_policy,
    draft_appeal_letter,
    predict_denial_risk,
    submit_prior_auth,
)
from .chronic_disease import (  # noqa: F401
    assess_adherence,
    generate_care_plan,
    monitor_patient_metrics,
    trigger_escalation_alert,
)
