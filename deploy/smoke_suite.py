#!/usr/bin/env python3
"""Full smoke suite against the deployed harness (JWT end-user path).

Verifies: gateway tools (market data + portfolio via DynamoDB), KB retrieval,
and cross-session memory. Exits non-zero on any failure.
"""
import json
import sys
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from smoke_invoke import get_token, OUTPUTS  # noqa: E402

from botocore.eventstream import EventStreamBuffer  # noqa: E402

REGION = "us-east-1"


def invoke(url: str, token: str, sub: str, prompt: str, session: str) -> str:
    body = json.dumps({"messages": [{"role": "user", "content": [{"text": prompt}]}],
                       "actorId": sub}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session})
    buf, text = EventStreamBuffer(), []
    with urllib.request.urlopen(req, timeout=310) as resp:
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            buf.add_data(chunk)
            for event in buf:
                if not event.payload:
                    continue
                try:
                    e = json.loads(event.payload.decode("utf-8", "replace"))
                except json.JSONDecodeError:
                    continue
                d = (e.get("contentBlockDelta", {}).get("delta", {}).get("text")
                     or e.get("delta", {}).get("text") or e.get("text")
                     or (e.get("message") and f"[ERROR] {e['message']}"))
                if d:
                    text.append(d)
    return "".join(text)


def main() -> None:
    harness = json.loads((OUTPUTS / "harness-id-finance.json").read_text())
    token, sub = get_token(REGION)
    url = (f"https://bedrock-agentcore.{REGION}.amazonaws.com/harnesses/invoke"
           f"?harnessArn={urllib.parse.quote(harness['harnessArn'], safe='')}"
           f"&qualifier=DEFAULT")

    checks = []

    def run(name, prompt, expect_any, session=None):
        session = session or (uuid.uuid4().hex + "ffffffff")
        t0 = time.time()
        out = invoke(url, token, sub, prompt, session)
        ok = any(marker.lower() in out.lower() for marker in expect_any)
        checks.append((name, ok, time.time() - t0))
        print(f"\n{'PASS' if ok else 'FAIL'} [{time.time()-t0:.0f}s] {name}")
        print(out[:600].strip())
        return session, out

    run("gateway market data tool",
        "Use your market data tool to get a quote for AAPL. Report the price.",
        ["AAPL"])

    run("gateway portfolio tool (DynamoDB)",
        "Show my default portfolio positions. How many positions and what total market value?",
        ["NVDA", "position"])

    run("knowledge base retrieval",
        "Search the knowledge base: what is the maintenance margin for leveraged ETFs?",
        ["50", "leveraged"])

    mem_session, _ = run("memory write",
        "Remember this preference: my risk tolerance is conservative and I prefer dividend stocks.",
        ["conservative", "preference", "remember", "noted", "got it"])

    print("\nWaiting 90s for memory extraction...")
    time.sleep(90)
    run("memory recall (new session)",
        "What is my risk tolerance?",
        ["conservative"])

    print("\n===== SUMMARY =====")
    failed = 0
    for name, ok, dt in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name} ({dt:.0f}s)")
        failed += 0 if ok else 1
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
