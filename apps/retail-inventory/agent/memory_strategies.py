"""Memory strategy configuration for the Inventory Management Agent."""


def get_inventory_memory_strategies() -> list[dict]:
    """Return memory strategy configurations for the inventory management agent.

    These strategies are created via the AgentCore control plane when
    setting up the Memory resource.
    """
    return [
        {
            "strategyName": "inventory_summary",
            "strategyType": "summaryMemoryStrategy",
            "description": "Summarizes inventory management sessions including reorder decisions, pricing changes, and supplier interactions.",
            "namespace": "/summaries/{actorId}/{sessionId}/",
        },
        {
            "strategyName": "buyer_preferences",
            "strategyType": "userPreferenceMemoryStrategy",
            "description": "Learns buyer/manager preferences: reorder thresholds, preferred suppliers, pricing strategies, category focus areas, reporting preferences.",
            "namespace": "/preferences/{actorId}/",
        },
        {
            "strategyName": "retail_knowledge",
            "strategyType": "semanticMemoryStrategy",
            "description": "Stores retail facts: product catalog details, supplier capabilities, market trends, seasonal patterns, competitor intelligence.",
            "namespace": "/facts/{actorId}/",
        },
    ]
