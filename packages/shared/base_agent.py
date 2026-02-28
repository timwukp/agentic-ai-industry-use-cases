"""Base class for all industry agentic AI agents.

Uses Strands Agents SDK for agent logic and Bedrock AgentCore SDK for deployment.
Subclasses implement get_tools(), get_system_prompt(), and get_memory_config().
"""
import os
import logging
from abc import ABC, abstractmethod
from typing import Optional

from strands import Agent
from strands.models import BedrockModel
from bedrock_agentcore.memory.integrations.strands.config import (
    AgentCoreMemoryConfig,
    RetrievalConfig,
)
from bedrock_agentcore.memory.integrations.strands.session_manager import (
    AgentCoreMemorySessionManager,
)

from packages.shared.observability import setup_observability
from packages.shared.code_interpreter import execute_python_code
from packages.shared.browser_tool import browse_url

logger = logging.getLogger(__name__)


class BaseIndustryAgent(ABC):
    """Abstract base class for industry-specific agentic AI agents.

    Integrates Strands Agent with all AgentCore services:
    - Memory (persistent knowledge via AgentCoreMemorySessionManager)
    - Code Interpreter (sandboxed execution via @tool)
    - Browser (web automation via @tool)
    - Observability (OTEL tracing)
    - Identity (credential management)
    """

    industry: str = ""
    name: str = ""

    def __init__(
        self,
        session_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        model_id: str = "us.anthropic.claude-sonnet-4-20250514-v1:0",
        region: str = "us-west-2",
        temperature: float = 0.3,
    ):
        self.session_id = session_id or "default"
        self.actor_id = actor_id or "default-user"
        self.region = region
        self.model_id = model_id
        self.temperature = temperature

        # Setup observability
        setup_observability(
            service_name=f"{self.industry}-{self.name}",
            environment=os.getenv("ENVIRONMENT", "development"),
        )

        # Build the Strands agent
        self._agent = self._build_agent()

    def _build_agent(self) -> Agent:
        """Build the Strands Agent with all tools and AgentCore integrations."""
        model = BedrockModel(
            model_id=self.model_id,
            region_name=self.region,
            temperature=self.temperature,
            streaming=True,
        )

        # Collect domain tools + shared tools
        tools = self.get_tools()
        tools.extend([execute_python_code, browse_url])

        # Setup memory session manager
        memory_config = self.get_memory_config()
        session_manager = None
        if memory_config:
            memory_config.session_id = self.session_id
            memory_config.actor_id = self.actor_id
            session_manager = AgentCoreMemorySessionManager(
                memory_config, region_name=self.region
            )

        agent = Agent(
            model=model,
            tools=tools,
            system_prompt=self.get_system_prompt(),
            name=self.name,
            session_manager=session_manager,
            trace_attributes={
                "industry": self.industry,
                "agent_name": self.name,
            },
        )

        return agent

    def __call__(self, prompt: str) -> str:
        """Invoke the agent with a user prompt."""
        result = self._agent(prompt)
        return str(result)

    @abstractmethod
    def get_tools(self) -> list:
        """Return domain-specific tools for this industry agent."""
        ...

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the system prompt for this industry agent."""
        ...

    @abstractmethod
    def get_memory_config(self) -> Optional[AgentCoreMemoryConfig]:
        """Return memory configuration for this agent, or None to disable memory."""
        ...

    @classmethod
    def create(
        cls,
        session_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        **kwargs,
    ) -> "BaseIndustryAgent":
        """Factory method to create an instance."""
        return cls(session_id=session_id, actor_id=actor_id, **kwargs)
