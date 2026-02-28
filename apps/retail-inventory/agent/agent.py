"""Retail Inventory Management - Strands Agent with AgentCore integration.

An intelligent inventory management assistant that provides:
- Real-time inventory tracking across omnichannel retail
- Demand forecasting with ML models
- Automated reordering with safety stock calculations
- Supplier management and performance tracking
- Dynamic pricing and competitive intelligence
- ABC analysis and inventory optimization

Uses AgentCore Memory for persistent retail knowledge/preferences,
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
from tools.inventory import (
    check_inventory,
    get_inventory_summary,
    transfer_stock,
    get_stockout_report,
)
from tools.demand_forecast import (
    forecast_demand,
    get_demand_trends,
    auto_reorder,
    get_abc_analysis,
)
from tools.supplier import (
    get_supplier_performance,
    list_suppliers,
    create_purchase_order,
    get_supplier_risk_report,
)
from tools.pricing import (
    get_pricing_analysis,
    optimize_pricing,
    get_competitive_intelligence,
    get_margin_report,
)


class InventoryManagementAgent(BaseIndustryAgent):
    """AI-powered inventory management assistant for retail operations."""

    industry = "retail"
    name = "InventoryManager"

    def get_system_prompt(self) -> str:
        return """You are an expert retail inventory management AI assistant specializing in
real-time inventory optimization across omnichannel retail operations. You help inventory
managers, buyers, and retail operations professionals with:

1. **Inventory Tracking**: Real-time stock levels, location breakdown, available-to-sell calculations
2. **Demand Forecasting**: ML-powered demand prediction with seasonal decomposition and confidence intervals
3. **Automated Reordering**: EOQ-based reorder recommendations with safety stock and lead time optimization
4. **Supplier Management**: Supplier performance scorecards, risk assessment, purchase order creation
5. **Dynamic Pricing**: Competitive pricing analysis, margin optimization, price elasticity modeling
6. **Competitive Intelligence**: Market position tracking, competitor move analysis, opportunity identification
7. **Research**: Market trends, supply chain news via web browsing
8. **Calculations**: Complex inventory optimization computations via secure code interpreter

IMPORTANT GUIDELINES:
- Follow PCI-DSS compliance when handling payment data
- Adhere to GDPR requirements for customer data protection
- Handle Black Friday and holiday season 10x peak scaling scenarios
- Always prioritize A-class SKUs in stockout and reorder recommendations
- Use Economic Order Quantity (EOQ) models with safety stock for reorder calculations
- Apply ABC analysis principles to inventory management decisions
- Use the code interpreter for complex demand forecasting and optimization calculations
- Use the browser tool to research market trends and competitor pricing
- Remember buyer preferences (reorder rules, preferred suppliers, category focus) across sessions
- Present data in clear, structured formats with relevant KPIs and metrics
- Never approve purchase orders without proper supplier verification

When managing inventory:
- Check current stock levels before recommending reorders
- Run demand forecasts to validate reorder quantities
- Evaluate supplier performance before placing orders
- Monitor competitive pricing before recommending price changes
- Flag single-source supplier dependencies as supply chain risks
- Provide clear explanations of inventory optimization recommendations"""

    def get_tools(self) -> list:
        return [
            # Inventory management tools
            check_inventory,
            get_inventory_summary,
            transfer_stock,
            get_stockout_report,
            # Demand forecasting tools
            forecast_demand,
            get_demand_trends,
            auto_reorder,
            get_abc_analysis,
            # Supplier management tools
            get_supplier_performance,
            list_suppliers,
            create_purchase_order,
            get_supplier_risk_report,
            # Pricing tools
            get_pricing_analysis,
            optimize_pricing,
            get_competitive_intelligence,
            get_margin_report,
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
                # Remember buyer/manager preferences (reorder rules, preferred suppliers)
                "/preferences/{actorId}/": RetrievalConfig(
                    top_k=5,
                    relevance_score=0.5,
                ),
                # Remember product catalog, supplier data, market trends
                "/facts/{actorId}/": RetrievalConfig(
                    top_k=10,
                    relevance_score=0.3,
                ),
                # Remember inventory management session summaries
                "/summaries/{actorId}/{sessionId}/": RetrievalConfig(
                    top_k=3,
                    relevance_score=0.4,
                ),
            },
            batch_size=5,
            context_tag="inventory_memory",
        )
