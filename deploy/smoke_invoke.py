#!/usr/bin/env python3
"""Smoke-test the harness data plane with a real Cognito JWT (end-user path).

Authenticates the demo user (USER_PASSWORD_AUTH), then POSTs to
/harnesses/invoke with Bearer auth — exactly what the browser does.

Usage: python deploy/smoke_invoke.py --prompt "..." [--session-id X] [--region R]
"""
import argparse
import json
import sys
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"


def get_token(region: str) -> tuple[str, str]:
    cdk = json.loads((OUTPUTS / "cdk-outputs.json").read_text())["AgenticAuth"]
    password = (OUTPUTS / "demo-user-password.txt").read_text().strip()
    idp = boto3.client("cognito-idp", region_name=region)
    resp = idp.initiate_auth(
        ClientId=cdk["UserPoolClientId"],
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": "demo@example.com", "PASSWORD": password},
    )
    access_token = resp["AuthenticationResult"]["AccessToken"]
    user = idp.get_user(AccessToken=access_token)
    sub = next(a["Value"] for a in user["UserAttributes"] if a["Name"] == "sub")
    return access_token, sub


def invoke(
    prompt: str, session_id: str, region: str, industry: str = "finance"
) -> None:
    harness = json.loads((OUTPUTS / f"harness-id-{industry}.json").read_text())
    token, sub = get_token(region)

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
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
        },
    )
    print(f"POST {url[:100]}...")
    from botocore.eventstream import EventStreamBuffer

    buf = EventStreamBuffer()
    text_parts: list[str] = []
    errors: list[str] = []
    with urllib.request.urlopen(req, timeout=310) as resp:  # nosec B310
        print("HTTP", resp.status, resp.headers.get("content-type"))
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
                delta = (
                    e.get("contentBlockDelta", {}).get("delta", {}).get("text")
                    or e.get("delta", {}).get("text")
                    or e.get("text")
                )
                if delta:
                    text_parts.append(delta)
                    sys.stdout.write(delta)
                    sys.stdout.flush()
                elif e.get("message"):
                    errors.append(e["message"])
    print("\n---")
    print(f"[{len(text_parts)} chunks streamed]")
    if errors:
        raise SystemExit(f"harness error: {errors[0][:300]}")
    if not text_parts:
        raise SystemExit("FAIL: no text streamed")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--industry", default="finance")
    ap.add_argument("--session-id", default=None)
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()
    session_id = args.session_id or (uuid.uuid4().hex + uuid.uuid4().hex[:8])
    print(f"session: {session_id}")
    invoke(args.prompt, session_id, args.region, args.industry)


if __name__ == "__main__":
    main()
