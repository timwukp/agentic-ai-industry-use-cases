"""Factory for creating BedrockAgentCoreApp with standard configuration."""
import json
import logging
from typing import Callable, Optional

from bedrock_agentcore import BedrockAgentCoreApp, RequestContext
from bedrock_agentcore.runtime.models import PingStatus
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)


def create_agentcore_app(
    agent_factory: Callable,
    allowed_origins: Optional[list[str]] = None,
) -> BedrockAgentCoreApp:
    """Create a BedrockAgentCoreApp with standard middleware and handlers.

    Args:
        agent_factory: Callable that accepts (session_id, actor_id) and returns a BaseIndustryAgent
        allowed_origins: CORS allowed origins. Defaults to ["*"] for development.
    """
    origins = allowed_origins or ["*"]

    app = BedrockAgentCoreApp(
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=origins,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        ]
    )

    @app.entrypoint
    def handle_invocation(request: dict, context: RequestContext) -> dict:
        """Handle synchronous agent invocations."""
        prompt = request.get("prompt", "")
        session_id = context.session_id or request.get("session_id", "default")
        actor_id = request.get("actor_id", "default-user")

        agent = agent_factory(session_id=session_id, actor_id=actor_id)
        response = agent(prompt)

        return {
            "response": response,
            "session_id": session_id,
            "actor_id": actor_id,
        }

    @app.websocket
    async def handle_websocket(websocket, context: RequestContext):
        """Handle WebSocket connections for streaming responses."""
        await websocket.accept()
        session_id = context.session_id or "ws-default"

        try:
            while True:
                data = await websocket.receive_text()
                message = json.loads(data)
                prompt = message.get("prompt", "")
                actor_id = message.get("actor_id", "default-user")

                agent = agent_factory(session_id=session_id, actor_id=actor_id)
                response = agent(prompt)

                await websocket.send_text(json.dumps({
                    "type": "response",
                    "content": response,
                    "session_id": session_id,
                }))
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            try:
                await websocket.close()
            except Exception:
                pass

    @app.ping
    def health_check() -> PingStatus:
        """Health check endpoint."""
        return PingStatus.HEALTHY

    return app
