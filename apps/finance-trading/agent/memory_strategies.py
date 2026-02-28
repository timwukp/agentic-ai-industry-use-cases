"""Memory strategy configuration for the Trading Assistant.

Defines the memory strategies to be created in AgentCore Memory
for persistent trading knowledge.
"""


def get_trading_memory_strategies() -> list[dict]:
    """Return memory strategy configurations for the trading assistant.

    These strategies are created via the AgentCore control plane when
    setting up the Memory resource.
    """
    return [
        {
            "strategyName": "trading_summary",
            "strategyType": "summaryMemoryStrategy",
            "description": "Summarizes trading sessions including key decisions, market conditions, and outcomes.",
            "namespace": "/summaries/{actorId}/{sessionId}/",
        },
        {
            "strategyName": "trading_preferences",
            "strategyType": "userPreferenceMemoryStrategy",
            "description": "Learns and remembers trader preferences: risk tolerance, preferred sectors, "
                          "trading style (day trading vs swing vs long-term), position sizing rules, "
                          "and favored analysis methods.",
            "namespace": "/preferences/{actorId}/",
        },
        {
            "strategyName": "market_knowledge",
            "strategyType": "semanticMemoryStrategy",
            "description": "Extracts and stores market facts, stock fundamentals, sector insights, "
                          "and investment theses shared during conversations.",
            "namespace": "/facts/{actorId}/",
        },
    ]
