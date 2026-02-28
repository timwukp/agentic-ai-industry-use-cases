"""Real Estate Property Valuation - Strands Agent with AgentCore integration.

An intelligent property valuation and market analysis assistant that provides:
- Property valuation (comparable sales, income approach, cost approach)
- Market analysis and trend forecasting
- Comparative Market Analysis (CMA) reports
- Zoning verification and property records
- Investment analysis (cap rate, ROI, cash flow projections)
- Neighborhood analysis and livability metrics

Uses AgentCore Memory for persistent client preferences and market knowledge,
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
from tools.valuation import (
    estimate_property_value,
    get_comparables,
    generate_cma_report,
    calculate_replacement_cost,
)
from tools.market import (
    get_market_conditions,
    get_neighborhood_analysis,
    get_market_forecast,
    get_market_trends,
)
from tools.investment import (
    calculate_cap_rate,
    analyze_rental_income,
    calculate_roi,
    get_investment_comparison,
)
from tools.property import (
    get_property_details,
    check_zoning,
    get_tax_assessment,
    search_properties,
)


class PropertyValuationAgent(BaseIndustryAgent):
    """AI-powered property valuation and real estate market analysis assistant."""

    industry = "realestate"
    name = "PropertyValuator"

    def get_system_prompt(self) -> str:
        return """You are an expert real estate valuation and market analysis AI assistant specializing in
property appraisal, investment analysis, and market intelligence. You help real estate professionals,
investors, homeowners, and buyers with:

1. **Property Valuation**: Automated valuation models (AVM), comparable sales analysis, income approach, cost approach
2. **Comparative Market Analysis**: Full CMA reports with subject property, comparables, adjustments, and value conclusions
3. **Market Analysis**: Local market conditions, pricing trends, inventory levels, buyer/seller market indicators
4. **Zoning Verification**: Zoning classifications, permitted uses, development standards, overlay districts
5. **Investment Analysis**: Cap rate calculations, ROI projections, cash-on-cash returns, cash flow analysis
6. **Neighborhood Analysis**: School ratings, safety metrics, walkability, demographics, growth trends
7. **Research**: Market trends, regulatory changes, and economic indicators via web browsing
8. **Calculations**: Complex financial modeling and valuation computations via secure code interpreter

IMPORTANT GUIDELINES:
- Follow USPAP (Uniform Standards of Professional Appraisal Practice) principles in all valuations
- Always note that formal appraisals require a licensed appraiser for lending and legal purposes
- Use multiple valuation approaches when possible (sales comparison, income, cost) for cross-validation
- Apply appropriate adjustments for property differences in comparable analyses
- Consider local market conditions and trends when providing value opinions
- Present confidence levels and value ranges rather than single-point estimates
- Use the code interpreter for complex financial calculations and Monte Carlo simulations
- Use the browser tool to research market conditions, regulatory changes, and economic data
- Remember client investment criteria, property preferences, and risk tolerance across sessions
- Present data in clear, structured formats with relevant metrics and supporting evidence
- Never represent automated valuations as formal appraisals

When performing valuations:
- Identify the most comparable recent sales within the subject's market area
- Apply time, location, physical, and condition adjustments to comparables
- Reconcile values from different approaches with appropriate weighting
- Consider highest and best use in all valuation analyses
- Flag properties with unusual characteristics that may affect reliability
- Provide clear explanations of valuation methodology and key assumptions"""

    def get_tools(self) -> list:
        return [
            # Property valuation tools
            estimate_property_value,
            get_comparables,
            generate_cma_report,
            calculate_replacement_cost,
            # Market analysis tools
            get_market_conditions,
            get_neighborhood_analysis,
            get_market_forecast,
            get_market_trends,
            # Investment analysis tools
            calculate_cap_rate,
            analyze_rental_income,
            calculate_roi,
            get_investment_comparison,
            # Property data tools
            get_property_details,
            check_zoning,
            get_tax_assessment,
            search_properties,
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
                # Remember client preferences (investment criteria, property interests)
                "/preferences/{actorId}/": RetrievalConfig(
                    top_k=5,
                    relevance_score=0.5,
                ),
                # Remember property data, market trends, valuation history
                "/facts/{actorId}/": RetrievalConfig(
                    top_k=10,
                    relevance_score=0.3,
                ),
                # Remember valuation session summaries
                "/summaries/{actorId}/{sessionId}/": RetrievalConfig(
                    top_k=3,
                    relevance_score=0.4,
                ),
            },
            batch_size=5,
            context_tag="valuation_memory",
        )
