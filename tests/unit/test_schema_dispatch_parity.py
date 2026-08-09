"""Every gateway schema tool must have a handler, and vice versa.

Catches schema/handler drift before it becomes a deployed 'Unknown tool' error.
Covers all industries: finance plus the five templates ported from the old apps.
"""

import importlib
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO / "tools"

# industry -> {schema file stem -> handler module dir}
INDUSTRY_TARGETS = {
    "finance": {
        "market_data": "market_data",
        "market_live": "market_live",
        "macro_signals": "macro_signals",
        "quant_insights": "quant_insights",
        "portfolio": "portfolio",
        "risk": "risk",
        "trading": "trading",
        "kb": "kb_search",
    },
    "healthcare": {
        "records": "records",
        "clinical": "clinical",
        "scheduling": "scheduling",
        "analytics": "analytics",
        "kb": "kb_search",
    },
    "insurance": {
        "claims": "claims",
        "fraud_detection": "fraud_detection",
        "policy": "policy",
        "settlement": "settlement",
        "kb": "kb_search",
    },
    "retail": {
        "inventory": "inventory",
        "demand_forecast": "demand_forecast",
        "supplier": "supplier",
        "pricing": "pricing",
        "kb": "kb_search",
    },
    "manufacturing": {
        "equipment": "equipment",
        "prediction": "prediction",
        "maintenance": "maintenance",
        "parts": "parts",
        "kb": "kb_search",
    },
    "realestate": {
        "valuation": "valuation",
        "market": "market",
        "investment": "investment",
        "property": "property",
        "kb": "kb_search",
    },
}

# Each industry ships 4 domain targets x 4 tools + 1 KB search tool.
# Finance additionally has market-live (6 real-data tools), macro-signals
# (4 factor/macro tools), and quant-insights (4 PRISM model tools).
EXPECTED_TOOL_COUNTS = {
    "finance": 31,  # 16 domain + 6 live + 4 signals + 4 prism + 1 KB
    "healthcare": 17,
    "insurance": 17,
    "retail": 17,
    "manufacturing": 17,
    "realestate": 17,
}

PARITY_CASES = [
    (industry, schema_stem, module_dir)
    for industry, targets in sorted(INDUSTRY_TARGETS.items())
    for schema_stem, module_dir in sorted(targets.items())
]

ALLOWED_INPUT_SCHEMA_KEYS = {"type", "properties", "required", "items", "description"}


def _load_handler(industry: str, module_dir: str):
    """Import tools/<industry>/<module_dir>/handler.py in isolation."""
    import sys

    sys.path.insert(0, str(TOOLS_DIR / industry / module_dir))
    try:
        handler = importlib.import_module("handler")
        return importlib.reload(handler)
    finally:
        sys.path.pop(0)
        sys.modules.pop("handler", None)


@pytest.mark.parametrize("industry,schema_stem,module_dir", PARITY_CASES)
def test_schema_matches_dispatch_table(industry, schema_stem, module_dir):
    schema_path = TOOLS_DIR / industry / "schemas" / f"{schema_stem}.json"
    schema = json.loads(schema_path.read_text())
    schema_names = {t["name"] for t in schema}

    handler = _load_handler(industry, module_dir)
    assert schema_names == set(handler.TOOLS), (
        f"{industry}/{schema_stem}: schema tools {schema_names} "
        f"!= dispatch table {set(handler.TOOLS)}"
    )


@pytest.mark.parametrize("industry", sorted(INDUSTRY_TARGETS))
def test_all_schemas_have_required_fields(industry):
    schema_dir = TOOLS_DIR / industry / "schemas"
    schema_files = list(schema_dir.glob("*.json"))
    assert schema_files, f"No schema files found in {schema_dir}"
    for f in schema_files:
        for tool in json.loads(f.read_text()):
            assert tool.get("name"), f"{industry}/{f.name}: tool missing name"
            assert tool.get(
                "description"
            ), f"{industry}/{f.name}:{tool['name']} missing description"
            input_schema = tool.get("inputSchema", {})
            assert (
                input_schema.get("type") == "object"
            ), f"{industry}/{f.name}:{tool['name']} inputSchema must be type object"


def _assert_allowed_keys(node: dict, location: str):
    extra = set(node) - ALLOWED_INPUT_SCHEMA_KEYS
    assert not extra, f"{location}: disallowed inputSchema keys {sorted(extra)}"
    for prop_name, prop in (node.get("properties") or {}).items():
        _assert_allowed_keys(prop, f"{location}.{prop_name}")
    if isinstance(node.get("items"), dict):
        _assert_allowed_keys(node["items"], f"{location}.items")


@pytest.mark.parametrize("industry", sorted(INDUSTRY_TARGETS))
def test_input_schemas_use_only_gateway_supported_keys(industry):
    """Gateway inlinePayload rejects enum/default/etc; those live in descriptions."""
    for f in (TOOLS_DIR / industry / "schemas").glob("*.json"):
        for tool in json.loads(f.read_text()):
            _assert_allowed_keys(
                tool["inputSchema"], f"{industry}/{f.name}:{tool['name']}"
            )


@pytest.mark.parametrize("industry,expected", sorted(EXPECTED_TOOL_COUNTS.items()))
def test_total_tool_count(industry, expected):
    total = sum(
        len(json.loads(f.read_text()))
        for f in (TOOLS_DIR / industry / "schemas").glob("*.json")
    )
    assert total == expected, f"{industry}: expected {expected} tools, found {total}"
