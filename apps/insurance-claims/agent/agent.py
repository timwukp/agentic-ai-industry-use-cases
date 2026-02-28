"""Insurance Claims Processing - Strands Agent with AgentCore integration.

An intelligent claims processing assistant that provides:
- Claim intake and lifecycle management
- AI-assisted damage assessment
- Fraud detection and investigation
- Settlement calculation and approval
- Policy verification and coverage checking

Uses AgentCore Memory for persistent claims/preference knowledge,
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
from tools.claims import (
    submit_claim,
    get_claim_status,
    assess_damage,
    list_claims,
)
from tools.fraud_detection import (
    analyze_fraud_risk,
    check_fraud_patterns,
    generate_fraud_report,
    get_fraud_dashboard,
)
from tools.policy import (
    verify_policy,
    check_coverage,
    get_policy_history,
    search_policies,
)
from tools.settlement import (
    calculate_settlement,
    approve_settlement,
    get_settlement_analytics,
    estimate_reserve,
)


class ClaimsProcessingAgent(BaseIndustryAgent):
    """AI-powered claims processing assistant for insurance operations."""

    industry = "insurance"
    name = "ClaimsProcessor"

    def get_system_prompt(self) -> str:
        return """You are an expert AI claims processing assistant with deep knowledge of insurance
operations, claims management, and regulatory compliance. You help claims adjusters and
insurance professionals with:

1. **Claim Intake & Management**: Submit new claims, track status, manage claim lifecycle
2. **Damage Assessment**: AI-assisted damage evaluation, cost estimation, severity rating
3. **Fraud Detection**: Multi-factor fraud analysis, pattern recognition, SIU referrals
4. **Settlement Processing**: Settlement calculation, approval workflows, reserve estimation
5. **Policy Verification**: Coverage checks, policy lookups, claims history review
6. **Research**: Regulatory updates, case precedents via web browsing
7. **Calculations**: Complex actuarial computations via secure code interpreter

IMPORTANT GUIDELINES:
- Ensure HIPAA compliance when handling medical claims data
- Follow state insurance regulation requirements for all claim decisions
- Adhere to fair claims practices act standards in all recommendations
- Always document the rationale behind claim decisions
- Flag potential fraud indicators early in the claims process
- Use the code interpreter for complex actuarial and statistical calculations
- Use the browser tool to research regulatory requirements and case law
- Remember adjuster preferences (handling patterns, escalation thresholds) across sessions
- Present data in clear, structured formats with relevant metrics
- Never approve settlements without proper documentation and compliance checks

When processing claims:
- Verify policy coverage before proceeding with assessment
- Run fraud screening on all new claims
- Calculate reserves using actuarial best practices (Chain-Ladder, Bornhuetter-Ferguson)
- Ensure all settlements comply with state-specific regulations
- Provide clear explanations of coverage determinations"""

    def get_tools(self) -> list:
        return [
            # Claims management tools
            submit_claim,
            get_claim_status,
            assess_damage,
            list_claims,
            # Fraud detection tools
            analyze_fraud_risk,
            check_fraud_patterns,
            generate_fraud_report,
            get_fraud_dashboard,
            # Policy verification tools
            verify_policy,
            check_coverage,
            get_policy_history,
            search_policies,
            # Settlement tools
            calculate_settlement,
            approve_settlement,
            get_settlement_analytics,
            estimate_reserve,
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
                # Remember adjuster preferences (handling patterns, escalation thresholds)
                "/preferences/{actorId}/": RetrievalConfig(
                    top_k=5,
                    relevance_score=0.5,
                ),
                # Remember policy details, fraud patterns, claim outcomes
                "/facts/{actorId}/": RetrievalConfig(
                    top_k=10,
                    relevance_score=0.3,
                ),
                # Remember claim session summaries
                "/summaries/{actorId}/{sessionId}/": RetrievalConfig(
                    top_k=3,
                    relevance_score=0.4,
                ),
            },
            batch_size=5,
            context_tag="claims_memory",
        )
