"""`verify_harness.py`'s detector must fail on the stream that actually failed.

`deploy/verify_harness.py` is the only check that can see live `allowedTools`
drift, so its detection logic needs a test of its own — a verifier that reports
PASS on a broken deployment is worse than no verifier, because it converts an
outage into a signed-off deployment.

The fixture is not synthetic. `tests/fixtures/harness_stream_unknown_tool.json`
is the real 166-event stream captured from the live finance harness while every
tool was unreachable. In it the agent tries three name spellings
(`market___`, `market__`, bare) and gets `Unknown tool` six times, then writes a
confident market summary with invented index levels. That last part is why the
detector reads tool-result events and never the prose: the prose looked fine.

Loaded by path because `deploy/` is a scripts directory, not a package.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "harness_stream_unknown_tool.json"


def _load_verifier():
    # verify_harness imports `industries` as a top-level module, the same way the
    # deploy scripts do when run from that directory.
    sys.path.insert(0, str(REPO / "deploy"))
    spec = importlib.util.spec_from_file_location(
        "verify_harness", REPO / "deploy" / "verify_harness.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def verifier():
    return _load_verifier()


@pytest.fixture(scope="module")
def broken_stream() -> list[dict]:
    events = json.loads(FIXTURE.read_text())
    # Guard against a vacuous test: if the fixture were empty or truncated, every
    # assertion below would still "pass" for the wrong reason.
    assert (
        len(events) > 100
    ), f"fixture has only {len(events)} events; expected the full capture"
    return events


def test_detector_finds_the_unknown_tool_errors(verifier, broken_stream):
    called, errors = verifier._trace(broken_stream)
    assert (
        len(errors) == 6
    ), f"expected 6 unknown-tool errors, got {len(errors)}: {errors}"
    assert all(e.startswith("Unknown tool") for e in errors)


def test_detector_records_the_wrong_tool_names_that_were_attempted(
    verifier, broken_stream
):
    called, _ = verifier._trace(broken_stream)
    # The agent guessed downward through three spellings. Seeing the guesses is
    # what distinguishes "tools unreachable" from "agent chose not to call one".
    assert "market___get_market_overview" in called
    assert "market__get_market_overview" in called
    assert "get_market_overview" in called
    # And it never reached the real name, which is hyphenated.
    assert not any(n.startswith("market-data___") for n in called)


def test_the_verifier_rejects_this_stream(verifier, broken_stream):
    """The decisive assertion, run through the real decision function.

    `judge_trace` is called rather than re-implemented on purpose: an earlier
    version of this test restated the conditions itself, and weakening the real
    check from "a tool with the gateway prefix" to "any tool at all" then passed
    both the test and the fixture — because `skills` always succeeds.
    """
    called, errors = verifier._trace(broken_stream)
    _, prefix = verifier.PROBES["finance"]
    assert "skills" in called, "fixture should contain the succeeding skills call"

    reasons = verifier.judge_trace(called, errors, prefix)
    assert len(reasons) == 2, f"expected both failure conditions to fire, got {reasons}"
    assert any("unknown-tool" in r for r in reasons)
    assert any(prefix in r for r in reasons)


def test_detector_accepts_a_healthy_trace(verifier):
    """Mutation guard in the other direction: the detector must not always fail.

    Shaped exactly like the events the data plane emits — a `start.toolUse` and a
    successful `delta.toolResult` with no `Unknown tool` text.
    """
    healthy = [
        {
            "contentBlockIndex": 0,
            "start": {"toolUse": {"name": "market-data___get_market_overview"}},
        },
        {
            "contentBlockIndex": 0,
            "delta": {
                "toolResult": [{"text": '{"indices": {"SP500": {"value": 6120.35}}}'}]
            },
        },
        {"contentBlockIndex": 0, "delta": {"text": "The S&P 500 is at 6,120.35."}},
    ]
    called, errors = verifier._trace(healthy)
    assert called == ["market-data___get_market_overview"]
    assert errors == []
    _, prefix = verifier.PROBES["finance"]
    assert verifier.judge_trace(called, errors, prefix) == []


def test_every_industry_has_a_probe(verifier):
    """A missing probe would silently skip an industry's live check."""
    sys.path.insert(0, str(REPO / "deploy"))
    from industries import INDUSTRIES

    assert set(verifier.PROBES) == set(INDUSTRIES), (
        f"PROBES covers {sorted(verifier.PROBES)} but industries are "
        f"{sorted(INDUSTRIES)}; an uncovered industry is never verified."
    )
    for industry, (prompt, prefix) in verifier.PROBES.items():
        assert prompt.strip(), f"{industry}: empty probe prompt"
        assert prefix.endswith("___"), (
            f"{industry}: prefix {prefix!r} should end with the gateway target "
            f"separator '___', otherwise it cannot distinguish a real call."
        )
