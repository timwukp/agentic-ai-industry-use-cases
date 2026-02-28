"""Memory configuration helpers for AgentCore Memory integration."""
from typing import Optional

from bedrock_agentcore.memory.integrations.strands.config import (
    AgentCoreMemoryConfig,
    RetrievalConfig,
)


def create_memory_config(
    memory_id: str,
    session_id: str = "default",
    actor_id: str = "default-user",
    enable_preferences: bool = True,
    enable_facts: bool = True,
    enable_summaries: bool = True,
    preferences_top_k: int = 5,
    facts_top_k: int = 10,
    summaries_top_k: int = 3,
    batch_size: int = 5,
) -> AgentCoreMemoryConfig:
    """Create a standard AgentCore memory configuration.

    Args:
        memory_id: The AgentCore Memory resource ID.
        session_id: Session identifier.
        actor_id: User/actor identifier.
        enable_preferences: Enable user preference memory strategy.
        enable_facts: Enable semantic fact memory strategy.
        enable_summaries: Enable session summary memory strategy.
        preferences_top_k: Number of preference memories to retrieve.
        facts_top_k: Number of fact memories to retrieve.
        summaries_top_k: Number of summary memories to retrieve.
        batch_size: Number of messages to buffer before sending to Memory.
    """
    retrieval_config = {}

    if enable_preferences:
        retrieval_config["/preferences/{actorId}/"] = RetrievalConfig(
            top_k=preferences_top_k,
            relevance_score=0.5,
        )

    if enable_facts:
        retrieval_config["/facts/{actorId}/"] = RetrievalConfig(
            top_k=facts_top_k,
            relevance_score=0.3,
        )

    if enable_summaries:
        retrieval_config["/summaries/{actorId}/{sessionId}/"] = RetrievalConfig(
            top_k=summaries_top_k,
            relevance_score=0.4,
        )

    return AgentCoreMemoryConfig(
        memory_id=memory_id,
        session_id=session_id,
        actor_id=actor_id,
        retrieval_config=retrieval_config,
        batch_size=batch_size,
        context_tag="agent_memory",
    )
