"""Tests for packages/shared/memory_config.py - AgentCore memory configuration."""
from packages.shared.memory_config import create_memory_config


class TestCreateMemoryConfig:
    """Tests for create_memory_config function."""

    def test_default_config_creation(self, sample_memory_id):
        config = create_memory_config(memory_id=sample_memory_id)
        assert config.memory_id == sample_memory_id
        assert config.session_id == "default"
        assert config.actor_id == "default-user"
        assert config.batch_size == 5

    def test_custom_session_and_actor(self, sample_memory_id):
        config = create_memory_config(
            memory_id=sample_memory_id,
            session_id="session-abc",
            actor_id="user-xyz",
        )
        assert config.session_id == "session-abc"
        assert config.actor_id == "user-xyz"

    def test_default_retrieval_config_has_all_strategies(self, sample_memory_id):
        config = create_memory_config(memory_id=sample_memory_id)
        retrieval = config.retrieval_config
        assert "/preferences/{actorId}/" in retrieval
        assert "/facts/{actorId}/" in retrieval
        assert "/summaries/{actorId}/{sessionId}/" in retrieval

    def test_preferences_disabled(self, sample_memory_id):
        config = create_memory_config(
            memory_id=sample_memory_id,
            enable_preferences=False,
        )
        retrieval = config.retrieval_config
        assert "/preferences/{actorId}/" not in retrieval
        assert "/facts/{actorId}/" in retrieval
        assert "/summaries/{actorId}/{sessionId}/" in retrieval

    def test_facts_disabled(self, sample_memory_id):
        config = create_memory_config(
            memory_id=sample_memory_id,
            enable_facts=False,
        )
        retrieval = config.retrieval_config
        assert "/preferences/{actorId}/" in retrieval
        assert "/facts/{actorId}/" not in retrieval
        assert "/summaries/{actorId}/{sessionId}/" in retrieval

    def test_summaries_disabled(self, sample_memory_id):
        config = create_memory_config(
            memory_id=sample_memory_id,
            enable_summaries=False,
        )
        retrieval = config.retrieval_config
        assert "/preferences/{actorId}/" in retrieval
        assert "/facts/{actorId}/" in retrieval
        assert "/summaries/{actorId}/{sessionId}/" not in retrieval

    def test_all_strategies_disabled(self, sample_memory_id):
        config = create_memory_config(
            memory_id=sample_memory_id,
            enable_preferences=False,
            enable_facts=False,
            enable_summaries=False,
        )
        retrieval = config.retrieval_config
        assert len(retrieval) == 0

    def test_custom_top_k_preferences(self, sample_memory_id):
        config = create_memory_config(
            memory_id=sample_memory_id,
            preferences_top_k=10,
        )
        retrieval = config.retrieval_config
        assert retrieval["/preferences/{actorId}/"].top_k == 10

    def test_custom_top_k_facts(self, sample_memory_id):
        config = create_memory_config(
            memory_id=sample_memory_id,
            facts_top_k=20,
        )
        retrieval = config.retrieval_config
        assert retrieval["/facts/{actorId}/"].top_k == 20

    def test_custom_top_k_summaries(self, sample_memory_id):
        config = create_memory_config(
            memory_id=sample_memory_id,
            summaries_top_k=7,
        )
        retrieval = config.retrieval_config
        assert retrieval["/summaries/{actorId}/{sessionId}/"].top_k == 7

    def test_custom_batch_size(self, sample_memory_id):
        config = create_memory_config(
            memory_id=sample_memory_id,
            batch_size=10,
        )
        assert config.batch_size == 10
