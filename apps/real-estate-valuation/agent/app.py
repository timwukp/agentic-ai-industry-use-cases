"""Real Estate Property Valuation - AgentCore Runtime Entry Point.

This is the main entry point for deploying the Property Valuation Agent
to AWS Bedrock AgentCore Runtime.
"""
import os
import sys
import logging

# Add project root to path for shared package imports (packages.shared.*)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
# Add agent directory so local modules (agent, tools.*) can be imported directly
sys.path.insert(0, os.path.dirname(__file__))

from packages.shared.agentcore_app import create_agentcore_app
from agent import PropertyValuationAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def create_valuation_agent(session_id: str = "default", actor_id: str = "default-user"):
    """Factory function for creating PropertyValuationAgent instances."""
    return PropertyValuationAgent.create(
        session_id=session_id,
        actor_id=actor_id,
        model_id=os.getenv("MODEL_ID", "us.anthropic.claude-sonnet-4-20250514-v1:0"),
        region=os.getenv("AWS_REGION", "us-west-2"),
    )


# Create the AgentCore application
app = create_agentcore_app(
    agent_factory=create_valuation_agent,
    allowed_origins=os.getenv("CORS_ORIGINS", "*").split(","),
)

if __name__ == "__main__":
    logger.info("Starting Real Estate Property Valuation Agent on AgentCore Runtime...")
    app.run()
