"""Anti-drift tests for docs/business-flows: the Python specs in
generate_business_flows.py are the single source of truth; the committed SVGs,
the mermaid blocks pasted into both docs, and the bilingual pair must all stay
in lockstep with them (pattern: tests/unit/test_starter_prompts.py)."""

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BF_DIR = ROOT / "docs" / "business-flows"
DOC_EN = ROOT / "docs" / "business-flows.md"
DOC_ZH = ROOT / "docs" / "business-flows.zh-TW.md"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_business_flows", BF_DIR / "generate_business_flows.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GEN = _load_generator()
SLUGS = [f["slug"] for f in GEN.FLOWS]


def _mermaid_blocks(text):
    return re.findall(r"```mermaid\n(.*?)```", text, re.DOTALL)


@pytest.mark.parametrize("flow", GEN.FLOWS, ids=SLUGS)
def test_geometry_and_freshness(flow):
    """render_flow raises on any edge crossing / box hit; the committed SVG
    must be byte-identical to a fresh render (edited spec => regenerate)."""
    svg = GEN.render_flow(flow)
    committed = (BF_DIR / f"{flow['slug']}.svg").read_text()
    assert svg == committed, f"{flow['slug']}.svg is stale — rerun the generator"


def test_mermaid_parity_with_english_doc():
    """The mermaid blocks in business-flows.md are the generator's --mermaid
    output, in FLOWS order — edit the spec, not the doc."""
    blocks = _mermaid_blocks(DOC_EN.read_text())
    assert len(blocks) == len(GEN.FLOWS)
    for flow, block in zip(GEN.FLOWS, blocks):
        assert (
            block.strip() == GEN.mermaid(flow).strip()
        ), f"mermaid drift for {flow['slug']}"


def test_bilingual_docs_in_sync():
    en, zh = DOC_EN.read_text(), DOC_ZH.read_text()
    embeds_en = re.findall(r"!\[[^]]*]\(business-flows/([a-z-]+)\.svg\)", en)
    embeds_zh = re.findall(r"!\[[^]]*]\(business-flows/([a-z-]+)\.svg\)", zh)
    assert embeds_en == SLUGS, "EN doc must embed all six SVGs in FLOWS order"
    assert embeds_zh == SLUGS, "ZH doc must embed all six SVGs in FLOWS order"
    assert _mermaid_blocks(en) == _mermaid_blocks(
        zh
    ), "mermaid blocks must be byte-identical across the bilingual pair"
    # same number of gate-table rows per section (tables start with '| Gate' / '| 關卡')
    rows_en = len(re.findall(r"^\|(?!\s*Gate|[-\s|]+$)", en, re.MULTILINE))
    rows_zh = len(re.findall(r"^\|(?!\s*關卡|[-\s|]+$)", zh, re.MULTILINE))
    assert rows_en == rows_zh, "gate/guardrail table row counts differ EN vs ZH"


def test_readmes_link_the_docs():
    en = (ROOT / "README.md").read_text()
    zh = (ROOT / "README.zh-TW.md").read_text()
    assert "docs/business-flows.md" in en
    assert "docs/business-flows.zh-TW.md" in zh
