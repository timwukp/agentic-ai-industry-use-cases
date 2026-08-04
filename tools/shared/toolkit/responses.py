"""Uniform response envelopes for gateway tools.

Gateway Lambda targets must return JSON-serializable values. Every simulated
payload carries a "source" marker so the agent can disclose data provenance.
"""

import json
from typing import Any


def tool_ok(payload: dict, simulated: bool = False) -> dict:
    if simulated:
        payload = {**payload, "source": "simulated"}
    return payload


def tool_error(message: str, **details: Any) -> dict:
    return {"error": message, **details}


def parse_json_arg(value: Any, arg_name: str):
    """Accept either a JSON string or an already-parsed structure."""
    if isinstance(value, (list, dict)):
        return value, None
    try:
        return json.loads(value), None
    except (TypeError, json.JSONDecodeError):
        return None, f"Invalid JSON for {arg_name}"
