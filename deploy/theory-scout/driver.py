#!/usr/bin/env python3
"""PrismTheoryScout driver — invoked by CodeBuild on the monthly schedule.

Invokes the harness data-plane, streams the run to stdout (lands in
CloudWatch via CodeBuild logs), and exits non-zero if the stream errors or
produces no text — a failed run must look failed.
"""
import os
import secrets
import sys
import time

import boto3

HARNESS_ARN = os.environ["HARNESS_ARN"]
REGION = os.environ.get("AWS_REGION", "us-east-1")

PROMPT = (
    "Run one full scout cycle now, following your system prompt exactly: "
    "load the theory-to-production skill, read the scoreboard and "
    "conditional-candidates list from the repo main branch, then run "
    "Phases 0-2 to a DRAFT deliverable (or an honest no-candidate summary). "
    "Narrate each phase transition on a line starting with 'PHASE:'."
)


def main() -> int:
    client = boto3.client("bedrock-agentcore", region_name=REGION)  # DATA plane
    # runtimeSessionId must be >= 33 chars (API constraint)
    session_id = f"scout-{time.strftime('%Y%m%d')}-{secrets.token_hex(16)}"
    print(f"MARKER run-start session={session_id}")

    try:
        resp = client.invoke_harness(
            harnessArn=HARNESS_ARN,
            runtimeSessionId=session_id,
            messages=[{"role": "user", "content": [{"text": PROMPT}]}],
        )
    except Exception as e:  # noqa: BLE001
        print(f"FAIL invoke_harness rejected: {e}")
        return 1

    got_text = False
    try:
        for event in resp["stream"]:
            if "contentBlockDelta" in event:
                delta = event["contentBlockDelta"].get("delta", {})
                if "text" in delta:
                    sys.stdout.write(delta["text"])
                    sys.stdout.flush()
                    got_text = True
    except Exception as e:  # noqa: BLE001
        print(f"\nFAIL error while streaming: {e}")
        return 1

    print(f"\nMARKER run-end session={session_id} got_text={got_text}")
    if not got_text:
        print("FAIL stream produced no text — treat as failed run")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
