"""Gateway → Lambda dispatch.

AgentCore Gateway invokes the target Lambda with the tool arguments as the
event and the fully-qualified tool name ("<target>___<tool>") in
context.client_context.custom["bedrockAgentCoreToolName"].
"""

from typing import Callable

TOOL_NAME_KEY = "bedrockAgentCoreToolName"
DELIMITER = "___"


def resolve_tool_name(context) -> str | None:
    try:
        name = context.client_context.custom[TOOL_NAME_KEY]
    except (AttributeError, KeyError, TypeError):
        return None
    return name.split(DELIMITER)[-1] if name else None


def dispatch(tool_map: dict[str, Callable], event: dict, context) -> dict:
    tool = resolve_tool_name(context)
    if tool is None:
        return {"error": "Missing bedrockAgentCoreToolName in client context"}
    handler = tool_map.get(tool)
    if handler is None:
        return {"error": f"Unknown tool: {tool}", "available": sorted(tool_map)}
    try:
        return handler(**(event or {}))
    except TypeError as exc:
        return {"error": f"Bad arguments for {tool}: {exc}"}
