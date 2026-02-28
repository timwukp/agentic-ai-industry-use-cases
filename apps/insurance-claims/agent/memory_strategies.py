"""Memory strategy configuration for the Claims Processing Agent."""


def get_claims_memory_strategies() -> list[dict]:
    """Return memory strategy configurations for the claims processing agent.

    These strategies are created via the AgentCore control plane when
    setting up the Memory resource.
    """
    return [
        {
            "strategyName": "claims_summary",
            "strategyType": "summaryMemoryStrategy",
            "description": "Summarizes claims processing sessions including decisions made, claim outcomes, and processing notes.",
            "namespace": "/summaries/{actorId}/{sessionId}/",
        },
        {
            "strategyName": "adjuster_preferences",
            "strategyType": "userPreferenceMemoryStrategy",
            "description": "Learns adjuster preferences: claim handling patterns, documentation requirements, escalation thresholds, communication style.",
            "namespace": "/preferences/{actorId}/",
        },
        {
            "strategyName": "claims_knowledge",
            "strategyType": "semanticMemoryStrategy",
            "description": "Stores claim-related facts: policy details, fraud patterns, settlement precedents, regulatory requirements.",
            "namespace": "/facts/{actorId}/",
        },
    ]
