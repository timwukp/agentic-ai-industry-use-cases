"""Memory strategy configuration for the Predictive Maintenance Agent."""


def get_maintenance_memory_strategies() -> list[dict]:
    """Return memory strategy configurations for the predictive maintenance agent.

    These strategies are created via the AgentCore control plane when
    setting up the Memory resource.
    """
    return [
        {
            "strategyName": "maintenance_summary",
            "strategyType": "summaryMemoryStrategy",
            "description": "Summarizes maintenance sessions including equipment inspections, failure diagnoses, work orders created, maintenance scheduled, and parts ordered.",
            "namespace": "/summaries/{actorId}/{sessionId}/",
        },
        {
            "strategyName": "technician_preferences",
            "strategyType": "userPreferenceMemoryStrategy",
            "description": "Learns technician/engineer preferences: alert thresholds, preferred maintenance windows, notification settings, reporting formats, equipment focus areas, shift schedules.",
            "namespace": "/preferences/{actorId}/",
        },
        {
            "strategyName": "equipment_knowledge",
            "strategyType": "semanticMemoryStrategy",
            "description": "Stores equipment facts: failure histories, vibration baselines, bearing specifications, lubrication schedules, vendor documentation, reliability benchmarks, root cause analyses.",
            "namespace": "/facts/{actorId}/",
        },
    ]
