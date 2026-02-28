"""Memory strategy configuration for the Property Valuation Agent."""


def get_valuation_memory_strategies() -> list[dict]:
    """Return memory strategy configurations for the property valuation agent.

    These strategies are created via the AgentCore control plane when
    setting up the Memory resource.
    """
    return [
        {
            "strategyName": "valuation_summary",
            "strategyType": "summaryMemoryStrategy",
            "description": "Summarizes property valuation sessions including appraisal results, CMA reports, investment analyses, and market research conducted.",
            "namespace": "/summaries/{actorId}/{sessionId}/",
        },
        {
            "strategyName": "client_preferences",
            "strategyType": "userPreferenceMemoryStrategy",
            "description": "Learns client preferences: property type interests, investment criteria (cap rate thresholds, ROI targets), preferred neighborhoods, budget ranges, risk tolerance, and reporting format preferences.",
            "namespace": "/preferences/{actorId}/",
        },
        {
            "strategyName": "market_knowledge",
            "strategyType": "semanticMemoryStrategy",
            "description": "Stores real estate knowledge: property valuations performed, comparable sales data, market trend analyses, neighborhood profiles, zoning details, and investment performance benchmarks.",
            "namespace": "/facts/{actorId}/",
        },
    ]
