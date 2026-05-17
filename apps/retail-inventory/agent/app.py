"""Retail Inventory Management - AgentCore Runtime Entry Point.

This is the main entry point for deploying the Inventory Management Agent
to AWS Bedrock AgentCore Runtime.
"""
import os
import logging

from packages.shared.agentcore_app import create_agentcore_app
from .agent import InventoryManagementAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def create_inventory_agent(session_id: str = "default", actor_id: str = "default-user"):
    """Factory function for creating InventoryManagementAgent instances."""
    return InventoryManagementAgent.create(
        session_id=session_id,
        actor_id=actor_id,
        model_id=os.getenv("MODEL_ID", "us.anthropic.claude-sonnet-4-20250514-v1:0"),
        region=os.getenv("AWS_REGION", "us-west-2"),
    )


# Create the AgentCore application
app = create_agentcore_app(
    agent_factory=create_inventory_agent,
    allowed_origins=os.getenv("CORS_ORIGINS", "*").split(","),
)

if __name__ == "__main__":
    logger.info("Starting Retail Inventory Management Agent on AgentCore Runtime...")
    app.run()
