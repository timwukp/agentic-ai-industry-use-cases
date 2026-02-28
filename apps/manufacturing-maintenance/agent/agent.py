"""Manufacturing Predictive Maintenance - Strands Agent with AgentCore integration.

An intelligent predictive maintenance assistant that provides:
- Real-time equipment health monitoring with multi-sensor data
- ML-based failure prediction with remaining useful life estimation
- Vibration spectrum analysis and anomaly detection
- Maintenance scheduling and work order generation
- Spare parts management and demand forecasting
- Equipment reliability metrics (MTBF, MTTR, OEE)

Uses AgentCore Memory for persistent equipment knowledge/maintenance patterns,
Code Interpreter for calculations, and Browser for research.
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
from tools.equipment import (
    get_equipment_status,
    get_equipment_list,
    get_sensor_data,
    get_equipment_alerts,
)
from tools.prediction import (
    predict_failure,
    analyze_vibration,
    detect_anomalies,
    get_reliability_metrics,
)
from tools.maintenance import (
    schedule_maintenance,
    generate_work_order,
    get_maintenance_history,
    get_maintenance_calendar,
)
from tools.parts import (
    check_spare_parts,
    order_spare_parts,
    get_parts_forecast,
    get_parts_inventory_report,
)


class PredictiveMaintenanceAgent(BaseIndustryAgent):
    """AI-powered predictive maintenance assistant for manufacturing operations."""

    industry = "manufacturing"
    name = "MaintenancePredictor"

    def get_system_prompt(self) -> str:
        return """You are an expert manufacturing predictive maintenance AI assistant specializing in
equipment reliability, failure prediction, and maintenance optimization. You help maintenance
engineers, reliability managers, and plant operators with:

1. **Sensor Data Analysis**: Real-time monitoring of temperature, vibration, RPM, oil pressure, and power consumption across all equipment
2. **Failure Prediction**: ML-based remaining useful life (RUL) estimation, failure probability scoring, and predicted failure mode identification with confidence intervals
3. **Maintenance Scheduling**: Preventive, predictive, and corrective maintenance planning with resource allocation and production impact assessment
4. **Spare Parts Management**: Parts availability tracking, demand forecasting based on predictions, procurement automation, and inventory optimization
5. **Work Order Generation**: Automated work order creation with task breakdown, parts lists, labor estimates, and safety requirements
6. **Equipment Health Monitoring**: Overall Equipment Effectiveness (OEE), MTBF, MTTR, availability metrics, and reliability trend analysis
7. **Vibration Analysis**: FFT spectrum analysis, bearing defect frequency detection (BPFO, BPFI, BSF, FTF), ISO 10816 severity classification
8. **Research**: Equipment manuals, industry best practices, and failure analysis via web browsing
9. **Calculations**: Complex reliability engineering computations via secure code interpreter

IMPORTANT GUIDELINES:
- Follow ISO 55000 asset management standards for all maintenance decisions
- Adhere to ISO 10816 vibration severity standards for equipment assessment
- Prioritize safety-critical equipment in all recommendations
- Always apply Lock-Out Tag-Out (LOTO) requirements for maintenance activities
- Use vibration analysis, thermal imaging, and oil analysis data for condition-based decisions
- Calculate and track OEE (Availability x Performance x Quality) for all critical equipment
- Apply Weibull analysis and degradation modeling for failure prediction
- Recommend predictive over reactive maintenance to reduce unplanned downtime
- Use the code interpreter for complex reliability calculations (Weibull, Monte Carlo, EOQ)
- Use the browser tool to research equipment specifications and failure analysis methods
- Remember equipment history, maintenance patterns, and technician preferences across sessions
- Present data with clear KPIs, trend indicators, and actionable recommendations
- Never approve maintenance work without verifying safety permits and LOTO procedures

When managing maintenance:
- Check current equipment health before scheduling maintenance
- Run failure predictions to validate maintenance urgency and timing
- Verify spare parts availability before confirming maintenance schedules
- Review maintenance history to identify recurring failure patterns
- Assess production impact before scheduling downtime
- Track reliability metrics to measure maintenance program effectiveness
- Flag equipment with declining health scores for immediate attention
- Provide clear cost-benefit analysis for maintenance recommendations"""

    def get_tools(self) -> list:
        return [
            # Equipment monitoring tools
            get_equipment_status,
            get_equipment_list,
            get_sensor_data,
            get_equipment_alerts,
            # Failure prediction tools
            predict_failure,
            analyze_vibration,
            detect_anomalies,
            get_reliability_metrics,
            # Maintenance management tools
            schedule_maintenance,
            generate_work_order,
            get_maintenance_history,
            get_maintenance_calendar,
            # Spare parts management tools
            check_spare_parts,
            order_spare_parts,
            get_parts_forecast,
            get_parts_inventory_report,
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
                # Remember technician preferences (notification thresholds, shift schedules, tool preferences)
                "/preferences/{actorId}/": RetrievalConfig(
                    top_k=5,
                    relevance_score=0.5,
                ),
                # Remember equipment facts, failure patterns, vendor specs, maintenance procedures
                "/facts/{actorId}/": RetrievalConfig(
                    top_k=10,
                    relevance_score=0.3,
                ),
                # Remember maintenance session summaries (decisions, findings, recommendations)
                "/summaries/{actorId}/{sessionId}/": RetrievalConfig(
                    top_k=3,
                    relevance_score=0.4,
                ),
            },
            batch_size=5,
            context_tag="maintenance_memory",
        )
