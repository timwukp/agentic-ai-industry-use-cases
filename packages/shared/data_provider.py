"""Data provider abstraction for switching between mock and real data sources.

The DATA_PROVIDER_MODE environment variable controls which provider is used:
- "mock" (default): Uses in-memory simulated data via MockDataProvider
- Future modes can be added for real data integrations
"""

import os
from abc import ABC, abstractmethod
from typing import Any


class DataProvider(ABC):
    """Abstract base class for data providers.

    Subclasses implement get, put, and list operations against a data store.
    """

    @abstractmethod
    def get(self, key: str) -> Any:
        """Retrieve a value by key.

        Args:
            key: The lookup key.

        Returns:
            The stored value, or None if not found.
        """

    @abstractmethod
    def put(self, key: str, value: Any) -> None:
        """Store a value by key.

        Args:
            key: The storage key.
            value: The value to store.
        """

    @abstractmethod
    def list(self, prefix: str) -> list[str]:
        """List keys matching a given prefix.

        Args:
            prefix: The prefix to filter keys by.

        Returns:
            A list of matching keys.
        """


class MockDataProvider(DataProvider):
    """In-memory data provider for development and testing."""

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}

    def get(self, key: str) -> Any:
        """Retrieve a value from the in-memory store."""
        return self._store.get(key)

    def put(self, key: str, value: Any) -> None:
        """Store a value in the in-memory store."""
        self._store[key] = value

    def list(self, prefix: str) -> list[str]:
        """List keys matching the given prefix from the in-memory store."""
        return [k for k in self._store if k.startswith(prefix)]


def get_data_provider(mode: str = None) -> DataProvider:
    """Factory function to create a data provider based on mode.

    Args:
        mode: Provider mode string. If None, reads from DATA_PROVIDER_MODE
              environment variable (defaults to "mock").

    Returns:
        A DataProvider instance for the requested mode.

    Raises:
        ValueError: If the requested mode is not supported.
    """
    if mode is None:
        mode = os.environ.get("DATA_PROVIDER_MODE", "mock")

    if mode == "mock":
        return MockDataProvider()

    raise ValueError(f"Unsupported data provider mode: {mode!r}. Supported modes: 'mock'")
