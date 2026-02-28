"""Finance Trading Assistant - Strands Agent with AgentCore integration.

An intelligent trading assistant that provides:
- Real-time market data and analysis
- Portfolio management and P&L tracking
- Risk analysis (VaR, stress tests, Monte Carlo)
- Trade execution and order management
- Financial news and SEC filing research

Uses AgentCore Memory for persistent portfolio/preference knowledge,
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
from tools.market_data import (
    get_stock_quote,
    get_market_overview,
    get_historical_prices,
    get_sector_performance,
)
from tools.risk_analysis import (
    calculate_var,
    stress_test_portfolio,
    analyze_portfolio_risk,
    monte_carlo_simulation,
)
from tools.portfolio import (
    get_portfolio_positions,
    calculate_pnl,
    get_portfolio_allocation,
    suggest_rebalancing,
)
from tools.trade import (
    place_order,
    cancel_order,
    get_order_status,
    get_trade_history,
)


class TradingAssistant(BaseIndustryAgent):
    """AI-powered trading assistant for financial markets."""

    industry = "finance"
    name = "TradingAssistant"

    def get_system_prompt(self) -> str:
        return """You are an expert AI trading assistant with deep knowledge of financial markets,
quantitative analysis, and portfolio management. You help traders and portfolio managers with:

1. **Market Analysis**: Real-time quotes, market overviews, sector performance, historical data
2. **Risk Management**: Value-at-Risk (VaR), stress testing, Monte Carlo simulations, risk metrics
3. **Portfolio Management**: Position tracking, P&L analysis, allocation optimization, rebalancing
4. **Trade Execution**: Order placement, order management, trade history
5. **Research**: Financial news, SEC filings, competitor analysis via web browsing
6. **Calculations**: Complex financial computations via secure code interpreter

IMPORTANT GUIDELINES:
- Always provide risk warnings when discussing trade recommendations
- Show your calculations and methodology when performing analysis
- Use the code interpreter for complex mathematical operations (VaR, Monte Carlo, etc.)
- Use the browser tool to research current news and SEC filings
- Remember user preferences (risk tolerance, preferred sectors, trading style) across sessions
- Present data in clear, structured formats with relevant metrics
- Comply with all regulatory requirements (SOX, MiFID II, Dodd-Frank)
- Never provide guaranteed returns or misleading financial advice

When performing risk analysis:
- Calculate VaR at 95% and 99% confidence levels
- Include both parametric and historical VaR methods
- Run stress tests against major market scenarios (2008 crisis, COVID crash, etc.)
- Always contextualize risk metrics with plain-language explanations"""

    def get_tools(self) -> list:
        return [
            # Market data tools
            get_stock_quote,
            get_market_overview,
            get_historical_prices,
            get_sector_performance,
            # Risk analysis tools
            calculate_var,
            stress_test_portfolio,
            analyze_portfolio_risk,
            monte_carlo_simulation,
            # Portfolio tools
            get_portfolio_positions,
            calculate_pnl,
            get_portfolio_allocation,
            suggest_rebalancing,
            # Trade execution tools
            place_order,
            cancel_order,
            get_order_status,
            get_trade_history,
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
                # Remember user trading preferences (risk tolerance, sectors, style)
                "/preferences/{actorId}/": RetrievalConfig(
                    top_k=5,
                    relevance_score=0.5,
                ),
                # Remember market facts and insights
                "/facts/{actorId}/": RetrievalConfig(
                    top_k=10,
                    relevance_score=0.3,
                ),
                # Remember session summaries
                "/summaries/{actorId}/{sessionId}/": RetrievalConfig(
                    top_k=3,
                    relevance_score=0.4,
                ),
            },
            batch_size=5,
            context_tag="trading_memory",
        )
