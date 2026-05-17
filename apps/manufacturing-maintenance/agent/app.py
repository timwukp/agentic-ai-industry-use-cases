"""Manufacturing Predictive Maintenance - AgentCore Runtime Entry Point.

This is the main entry point for deploying the Predictive Maintenance Agent
to AWS Bedrock AgentCore Runtime.
"""
import os
import logging

from packages.shared.agentcore_app import create_agentcore_app
from .agent import PredictiveMaintenanceAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def create_maintenance_agent(session_id: str = "default", actor_id: str = "default-user"):
    """Factory function for creating PredictiveMaintenanceAgent instances."""
    return PredictiveMaintenanceAgent.create(
        session_id=session_id,
        actor_id=actor_id,
        model_id=os.getenv("MODEL_ID", "us.anthropic.claude-sonnet-4-20250514-v1:0"),
        region=os.getenv("AWS_REGION", "us-west-2"),
    )


# Create the AgentCore application
app = create_agentcore_app(
    agent_factory=create_maintenance_agent,
    allowed_origins=os.getenv("CORS_ORIGINS", "*").split(","),
)

if __name__ == "__main__":
    logger.info("Starting Manufacturing Predictive Maintenance Agent on AgentCore Runtime...")
    app.run()
