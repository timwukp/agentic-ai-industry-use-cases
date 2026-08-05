"""Harness templates must not starve the agent of its own tools.

This exists because of a real, silent, total failure. Every industry's live
harness had drifted to an explicit ``allowedTools`` list:

    ["market-data___*", "portfolio___*", ..., "browser", "code_interpreter"]

which matched **nothing**. The agent could see only the ``skills`` tool. It then
did the worst possible thing with that: rather than refusing, it answered from
memory and invented market data. A user reported "the reply is in Chinese and
the table is ugly" — the real defect underneath was that the S&P 500 level in
that reply (5,248) did not exist anywhere in the system. The tool returns
6,120.35.

Nothing caught it. The gateway was READY, all five targets were READY, all 17
tools worked when called directly over MCP, the harness IAM role was `allowed`
for InvokeGateway, and every deploy step exited 0. The only observable symptom
was `"Unknown tool: ..."` inside a tool-result event that both the smoke script
and the web client discard.

So the assertions here are about the *filter*, which is the part with no other
signal:

1. ``allowedTools`` must be non-empty — empty means the agent sees nothing.
2. Plain built-in names (``browser``, ``code_interpreter``) must not appear.
   They never match; a glob or ``*`` is required. This is the exact drift.
3. Every declared gateway/built-in tool must be matched by some pattern, checked
   by actually running the glob rather than eyeballing it.
4. Tools must carry ``config`` — a tool without it is stored but not wired.

What this canNOT check: whether the *live* harness matches the template. That
is a deploy-time property, and drift is precisely what happened. `make test`
runs offline, so the live check belongs with deploy verification — see
``deploy/verify_harness.py``, which is why that script exists.
"""

import fnmatch
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "deploy"))
from industries import INDUSTRIES  # noqa: E402

# Built-in tool primitives are exposed under names the plain tool name does not
# equal, so they need a glob. Keeping the list here rather than importing it
# makes the test independent of the builder script's own opinions.
BUILTIN_TYPES = {"agentcore_browser", "agentcore_code_interpreter"}

INDUSTRY_IDS = sorted(INDUSTRIES)


def _template(industry: str) -> dict:
    path = (
        REPO
        / "harnesses"
        / INDUSTRIES[industry]["harness_dir"]
        / "harness.template.json"
    )
    return json.loads(path.read_text())


@pytest.mark.parametrize("industry", INDUSTRY_IDS)
def test_allowed_tools_is_non_empty(industry: str) -> None:
    cfg = _template(industry)
    allowed = cfg.get("allowedTools")
    assert isinstance(allowed, list), f"{industry}: allowedTools must be a list"
    assert allowed, (
        f"{industry}: allowedTools is empty — the agent would see no tools at all "
        f"and (observed behaviour) answer from memory with invented numbers."
    )


@pytest.mark.parametrize("industry", INDUSTRY_IDS)
def test_allowed_tools_has_no_plain_builtin_names(industry: str) -> None:
    """The drift that actually shipped: a plain name that matches nothing."""
    allowed = _template(industry)["allowedTools"]
    bad = [a for a in allowed if a in {"browser", "code_interpreter"}]
    assert not bad, (
        f"{industry}: allowedTools contains plain built-in name(s) {bad}. A plain "
        f"name never matches the underlying primitives — use '*' or a glob like "
        f"'{bad[0]}_*'. This exact entry silently disabled every tool in all six "
        f"industries."
    )


@pytest.mark.parametrize("industry", INDUSTRY_IDS)
def test_every_declared_tool_is_reachable_through_allowed_tools(industry: str) -> None:
    """Run the globs, don't eyeball them.

    A gateway tool's real name is ``<target>___<tool>``, so a pattern for it must
    match at least one such name. The target names come from the gateway, not the
    template, so the check here is the weaker but still decisive one: some
    pattern must be capable of matching a prefixed name.
    """
    cfg = _template(industry)
    allowed = cfg["allowedTools"]

    for tool in cfg.get("tools", []):
        name, ttype = tool["name"], tool["type"]

        if ttype == "agentcore_gateway":
            # Gateway tools arrive as "<target>___<tool_name>" — never the bare
            # tool block name. A pattern must be able to match that shape.
            probe = f"{name}___probe_tool"
            wildcard_probe = "any-target___any_tool"
            matched = any(
                fnmatch.fnmatch(probe, pat) or fnmatch.fnmatch(wildcard_probe, pat)
                for pat in allowed
            )
            assert matched, (
                f"{industry}: no allowedTools pattern in {allowed} can match a "
                f"gateway tool name of the form '<target>___<tool>'. Gateway tools "
                f"are exposed with the target prefix, not as '{name}'."
            )
        elif ttype in BUILTIN_TYPES:
            matched = any(
                fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(f"{name}_x", pat)
                for pat in allowed
            )
            assert matched, (
                f"{industry}: built-in tool '{name}' ({ttype}) is not matched by "
                f"any pattern in {allowed}, so it is filtered out."
            )


@pytest.mark.parametrize("industry", INDUSTRY_IDS)
def test_every_tool_is_wired(industry: str) -> None:
    """A tool without `config` is stored but not wired — the agent cannot call it."""
    for tool in _template(industry).get("tools", []):
        assert tool.get("config"), (
            f"{industry}: tool '{tool.get('name')}' has no 'config'; it would be "
            f"stored on the harness but not wired to anything."
        )


@pytest.mark.parametrize("industry", INDUSTRY_IDS)
def test_system_prompt_placeholder_is_present(industry: str) -> None:
    """render_harness.py substitutes this; a renamed key would ship an empty prompt."""
    cfg = _template(industry)
    text = "".join(block.get("text", "") for block in cfg["systemPrompt"])
    assert text == "{{SYSTEM_PROMPT}}", (
        f"{industry}: systemPrompt is {text[:60]!r}, not the placeholder that "
        f"render_harness.py replaces."
    )


@pytest.mark.parametrize("industry", INDUSTRY_IDS)
def test_system_prompt_states_language_and_formatting_rules(industry: str) -> None:
    """Both were added to fix reported defects; neither is self-evident from code.

    Language: a stored memory record written in Chinese was being read as a
    language instruction, so English questions got Chinese answers.
    Formatting: the agent hand-drew tables with box characters inside code
    fences, which renders as unaligned raw text in the chat panel.
    """
    prompt = (
        REPO
        / "harnesses"
        / INDUSTRIES[industry]["harness_dir"]
        / "prompts"
        / "system.md"
    ).read_text()

    for heading in ("RESPONSE LANGUAGE:", "RESPONSE FORMATTING:"):
        assert prompt.count(heading) == 1, (
            f"{industry}: expected exactly one '{heading}' section, found "
            f"{prompt.count(heading)}."
        )

    # The specific instructions, not just the headings — a heading with the body
    # deleted would pass the count check above.
    assert "CURRENT message" in prompt, (
        f"{industry}: the language rule must tell the model to judge from the "
        f"current message, not from retrieved memory (the actual failure mode)."
    )
    assert "box characters" in prompt, (
        f"{industry}: the formatting rule must forbid hand-drawn tables; that is "
        f"what made answers unreadable."
    )
