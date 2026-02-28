"""Healthcare Medical Records - Strands Agent with AgentCore integration.

An intelligent medical records analysis assistant that provides:
- Comprehensive patient record summarization
- Drug interaction checking and medication management
- Clinical decision support with evidence-based guidelines
- Appointment scheduling and provider management
- Lab result analysis with reference range interpretation
- Triage assessment and risk scoring
- Population health analytics and care gap identification

Uses AgentCore Memory for persistent clinical knowledge/preferences,
Code Interpreter for calculations, and Browser for research.

HIPAA COMPLIANCE: All data handling follows HIPAA regulations.
HL7 FHIR standards observed for data interoperability.
"""
import os
import sys
from typing import Optional

# Add project root for shared package imports (packages.shared.*)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
# Add agent directory so local tool modules can be imported as tools.*
sys.path.insert(0, os.path.dirname(__file__))

from bedrock_agentcore.memory.integrations.strands.config import (
    AgentCoreMemoryConfig,
    RetrievalConfig,
)

from packages.shared.base_agent import BaseIndustryAgent
from tools.records import (
    get_patient_summary,
    search_medical_records,
    get_medication_list,
    get_lab_results,
)
from tools.clinical import (
    check_drug_interactions,
    assess_symptoms,
    get_clinical_guidelines,
    calculate_risk_score,
)
from tools.scheduling import (
    schedule_appointment,
    get_provider_availability,
    get_upcoming_appointments,
    send_appointment_reminder,
)
from tools.analytics import (
    get_patient_analytics,
    get_population_health_metrics,
    get_readmission_risk,
    get_care_gap_analysis,
)


class MedicalRecordsAgent(BaseIndustryAgent):
    """AI-powered medical records analysis assistant for healthcare providers."""

    industry = "healthcare"
    name = "MedicalRecordsAnalyzer"

    def get_system_prompt(self) -> str:
        return """You are an expert medical AI assistant designed for healthcare providers including
physicians, nurses, clinical staff, and healthcare administrators. You help with:

1. **Medical Records Analysis**: Comprehensive patient summaries, record search, history review
2. **Patient History Summarization**: Demographics, conditions, medications, allergies, recent visits
3. **Drug Interaction Checking**: Multi-medication interaction analysis with severity levels and recommendations
4. **Appointment Scheduling**: Provider availability, booking, reminders, and calendar management
5. **Triage Assessment**: Symptom-based urgency evaluation with possible conditions and recommended actions
6. **Lab Result Analysis**: Interpretation of lab values with reference ranges, flags, and trend analysis
7. **Clinical Decision Support**: Evidence-based guidelines, risk scoring, and care gap identification
8. **Research**: Latest clinical research and guidelines via web browsing
9. **Calculations**: Clinical risk scores and health metrics via secure code interpreter

CRITICAL COMPLIANCE REQUIREMENTS:
- HIPAA compliance is MANDATORY - never expose Protected Health Information (PHI) in logs or unsecured channels
- All patient data must be treated as encrypted at rest and in transit
- Maintain complete audit logging for all data access and modifications
- Follow HL7 FHIR standards for data interoperability
- Always recommend consulting with a licensed physician for clinical decisions
- This system provides decision SUPPORT only - it does NOT replace clinical judgment
- Document all clinical recommendations with evidence-based citations when possible

IMPORTANT GUIDELINES:
- Always verify patient identity before disclosing medical information
- Flag critical lab values and drug interactions with HIGH severity immediately
- Present medication lists with dosage, frequency, route, and prescriber information
- Include ICD-10 codes when referencing diagnoses
- Use the code interpreter for BMI calculations, GFR estimates, and risk score computations
- Use the browser tool to research latest clinical guidelines and drug information
- Remember provider preferences (preferred labs, referral patterns, documentation style) across sessions
- Present clinical data in structured, scannable formats
- Never make definitive diagnoses - always frame findings as possibilities requiring physician review"""

    def get_tools(self) -> list:
        return [
            # Medical records tools
            get_patient_summary,
            search_medical_records,
            get_medication_list,
            get_lab_results,
            # Clinical decision support tools
            check_drug_interactions,
            assess_symptoms,
            get_clinical_guidelines,
            calculate_risk_score,
            # Scheduling tools
            schedule_appointment,
            get_provider_availability,
            get_upcoming_appointments,
            send_appointment_reminder,
            # Analytics tools
            get_patient_analytics,
            get_population_health_metrics,
            get_readmission_risk,
            get_care_gap_analysis,
        ]

    def get_memory_config(self) -> Optional[AgentCoreMemoryConfig]:
        memory_id = os.getenv("AGENTCORE_MEMORY_ID")
        if not memory_id:
            return None

        return AgentCoreMemoryConfig(
            memory_id=memory_id,
            session_id=self.session_id,
            actor_id=self.actor_id,
            retrieval_config={
                # Remember provider preferences (documentation style, preferred labs, referral patterns)
                "/preferences/{actorId}/": RetrievalConfig(
                    top_k=5,
                    relevance_score=0.5,
                ),
                # Remember clinical knowledge (guidelines, drug info, protocol updates)
                "/facts/{actorId}/": RetrievalConfig(
                    top_k=10,
                    relevance_score=0.3,
                ),
                # Remember patient encounter summaries
                "/summaries/{actorId}/{sessionId}/": RetrievalConfig(
                    top_k=3,
                    relevance_score=0.4,
                ),
            },
            batch_size=5,
            context_tag="medical_memory",
        )
