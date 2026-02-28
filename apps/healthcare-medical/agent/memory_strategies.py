"""Memory strategy configuration for the Medical Records Analysis Agent."""


def get_medical_memory_strategies() -> list[dict]:
    """Return memory strategy configurations for the medical records analysis agent.

    These strategies are created via the AgentCore control plane when
    setting up the Memory resource.
    """
    return [
        {
            "strategyName": "clinical_summary",
            "strategyType": "summaryMemoryStrategy",
            "description": "Summarizes clinical encounter sessions including patient assessments, diagnostic decisions, treatment plan changes, lab result reviews, and referral actions taken.",
            "namespace": "/summaries/{actorId}/{sessionId}/",
        },
        {
            "strategyName": "provider_preferences",
            "strategyType": "userPreferenceMemoryStrategy",
            "description": "Learns provider preferences: preferred lab panels, referral patterns, documentation style, formulary preferences, clinical workflow shortcuts, and communication channel choices.",
            "namespace": "/preferences/{actorId}/",
        },
        {
            "strategyName": "medical_knowledge",
            "strategyType": "semanticMemoryStrategy",
            "description": "Stores clinical knowledge: drug interaction data, clinical guideline updates, protocol changes, formulary information, disease management pathways, and evidence-based treatment references.",
            "namespace": "/facts/{actorId}/",
        },
    ]
