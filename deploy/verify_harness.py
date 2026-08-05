#!/usr/bin/env python3
"""Verify a DEPLOYED harness can actually reach its tools.

Why this is separate from `make test`: the unit tests read
`harnesses/*/harness.template.json`, and the failure this script exists to catch
was **live drift** — the template said `allowedTools: ["*"]` while every live
harness had an explicit list of patterns that matched nothing. The agent could
see only the `skills` tool, and instead of refusing it answered from memory and
invented market data (it reported the S&P 500 at 5,248 when the tool returns
6,120.35). No offline test can see that.

Nothing else caught it either. The gateway was READY, all targets were READY, all
17 tools worked when called directly over MCP, IAM simulated as `allowed`, and
every deploy step exited 0. The only trace was `"Unknown tool: ..."` inside a
tool-result event that both the smoke script and the web client discard.

So the check is: ask the live harness to *use* a tool, then read the tool-result
events — not the prose. An agent that cannot reach its tools produces
confident-looking prose, which is why asserting on text would be worse than no
check at all.

Usage:
    python deploy/verify_harness.py                    # all industries
    python deploy/verify_harness.py --industry finance
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import boto3
from botocore.eventstream import EventStreamBuffer

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from industries import INDUSTRIES  # noqa: E402

# A prompt per industry that cannot be answered without a gateway tool, plus the
# target prefix whose tools must appear in the trace. The prefix matters: the
# agent guessed "market___" (wrong) before "market-data___" (right), and only
# the real prefix proves the call landed.
PROBES: dict[str, tuple[str, str]] = {
    "finance": (
        "Call the market overview tool and report the S&P 500 level. Numbers only.",
        "market-data___",
    ),
    "healthcare": (
        "Call the population health metrics tool and report the active patient count.",
        "analytics___",
    ),
    "insurance": (
        "Call the claims listing tool and report how many claims came back.",
        "claims___",
    ),
    "retail": (
        "Call the inventory summary tool and report the total SKU count.",
        "inventory___",
    ),
    "manufacturing": (
        "Call the equipment list tool and report how many machines came back.",
        "equipment___",
    ),
    "realestate": (
        "Call the market conditions tool and report the median list price.",
        "market___",
    ),
}


def _auth(region: str) -> tuple[str, str]:
    cdk = json.loads((OUTPUTS / "cdk-outputs.json").read_text())["AgenticAuth"]
    password = (OUTPUTS / "demo-user-password.txt").read_text().strip()
    idp = boto3.client("cognito-idp", region_name=region)
    resp = idp.initiate_auth(
        ClientId=cdk["UserPoolClientId"],
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": "demo@example.com", "PASSWORD": password},
    )
    token = resp["AuthenticationResult"]["AccessToken"]
    user = idp.get_user(AccessToken=token)
    sub = next(a["Value"] for a in user["UserAttributes"] if a["Name"] == "sub")
    return token, sub


def _invoke(
    industry: str, prompt: str, token: str, sub: str, region: str
) -> list[dict]:
    """Return every stream event, including the ones the smoke script drops."""
    harness = json.loads((OUTPUTS / f"harness-id-{industry}.json").read_text())
    url = (
        f"https://bedrock-agentcore.{region}.amazonaws.com/harnesses/invoke"
        f"?harnessArn={urllib.parse.quote(harness['harnessArn'], safe='')}"
        f"&qualifier=DEFAULT"
    )
    body = json.dumps(
        {
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "actorId": sub,
        }
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            # A fresh session every run: a reused session could answer from
            # conversation history and never touch a tool, which would make this
            # check pass while proving nothing.
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": uuid.uuid4().hex
            + uuid.uuid4().hex[:8],
        },
    )
    buf = EventStreamBuffer()
    events: list[dict] = []
    with urllib.request.urlopen(req, timeout=310) as resp:  # nosec B310
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            buf.add_data(chunk)
            for event in buf:
                if not event.payload:
                    continue
                try:
                    events.append(json.loads(event.payload.decode("utf-8", "replace")))
                except json.JSONDecodeError:
                    continue
    return events


def _trace(events: list[dict]) -> tuple[list[str], list[str]]:
    """(tool names called, tool errors) — the two facts worth asserting on."""
    called: list[str] = []
    errors: list[str] = []
    for event in events:
        start = event.get("start", {})
        if "toolUse" in start:
            called.append(start["toolUse"]["name"])
        delta = event.get("delta", {})
        result = delta.get("toolResult")
        # toolResult deltas arrive as a list of content blocks.
        if isinstance(result, list):
            for block in result:
                text = block.get("text", "") if isinstance(block, dict) else ""
                if text.startswith("Unknown tool"):
                    errors.append(text[:160])
    return called, errors


def judge_trace(called: list[str], errors: list[str], prefix: str) -> list[str]:
    """Reasons the trace proves the harness could NOT reach its tools ([] = healthy).

    Split out from `verify` so the decision itself is testable against a real
    captured stream. When the test re-implemented these conditions instead of
    calling them, weakening the prefix check to a bare `if not called` went
    undetected — `skills` always succeeds, so "called something" is not evidence.
    """
    reasons: list[str] = []
    if errors:
        reasons.append(f"{len(errors)} unknown-tool error(s): {errors[:3]}")
    if not any(name.startswith(prefix) for name in called):
        reasons.append(
            f"no tool call with prefix '{prefix}'. The agent answered without its "
            f"tools — expect fabricated numbers in the reply."
        )
    return reasons


def verify(industry: str, region: str) -> bool:
    prompt, prefix = PROBES[industry]
    print(f"\n=== {industry} ===")

    control = boto3.client("bedrock-agentcore-control", region_name=region)
    harness_id = json.loads((OUTPUTS / f"harness-id-{industry}.json").read_text())[
        "harnessId"
    ]
    harness = control.get_harness(harnessId=harness_id)["harness"]
    allowed = harness.get("allowedTools")
    print(
        f"  live v{harness['harnessVersion']} {harness['status']} allowedTools={allowed}"
    )

    ok = True
    if harness["status"] != "READY":
        print(f"  FAIL status is {harness['status']}, not READY")
        ok = False
    # The drift itself, checked against the live resource rather than the file.
    plain = [a for a in (allowed or []) if a in {"browser", "code_interpreter"}]
    if plain:
        print(
            f"  FAIL allowedTools has plain built-in name(s) {plain} — matches nothing"
        )
        ok = False
    if not allowed:
        print("  FAIL allowedTools is empty — the agent sees no tools")
        ok = False

    token, sub = _auth(region)
    called, errors = _trace(_invoke(industry, prompt, token, sub, region))
    print(f"  tools called: {called or '(none)'}")

    # `skills` is always available and is not evidence of anything, so the trace
    # judgement requires a call carrying the gateway target prefix.
    for reason in judge_trace(called, errors, prefix):
        print(f"  FAIL {reason}")
        ok = False

    print(f"  {'PASS' if ok else 'FAIL'}")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--industry", choices=sorted(INDUSTRIES), default=None)
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    industries = [args.industry] if args.industry else sorted(INDUSTRIES)
    results = {ind: verify(ind, args.region) for ind in industries}

    failed = [ind for ind, ok in results.items() if not ok]
    print(
        f"\n{len(results) - len(failed)}/{len(results)} harnesses can reach their tools"
    )
    if failed:
        raise SystemExit(f"FAILED: {', '.join(failed)}")


if __name__ == "__main__":
    main()
