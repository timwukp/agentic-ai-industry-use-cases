"""Common test fixtures for the agentic-ai-industry-use-cases project."""
import pytest


@pytest.fixture
def sample_valid_input():
    """Return a simple valid input string for testing."""
    return "What is the current price of AAPL?"


@pytest.fixture
def sample_memory_id():
    """Return a sample memory resource ID."""
    return "mem-test-12345"
