#!/usr/bin/env python3
"""Wire BYO AgentCore Memory to the harness (3 steps, idempotent).

Replaces the skill's wire_memory.py because our strategy set (from
harnesses/<industry>/memory.json — no episodic) differs from its hardcoded
4-strategy set, whose episodic shape the live API currently rejects.

Steps: 1. CreateMemory with strategies  2. UpdateHarness(memory=...)
       3. Inline IAM policy on the execution role scoped to the Memory ARN.
"""
import argparse
import json
import time
import uuid
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"
INDUSTRY_DIRS = {"finance": "finance-trading"}

EVENT_ACTIONS = ["bedrock-agentcore:CreateEvent", "bedrock-agentcore:GetEvent",
                 "bedrock-agentcore:ListEvents", "bedrock-agentcore:ListSessions",
                 "bedrock-agentcore:ListActors"]
RETRIEVAL_ACTIONS = ["bedrock-agentcore:ListMemoryRecords",
                     "bedrock-agentcore:RetrieveMemoryRecords"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--industry", default="finance")
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    cfg = json.loads((REPO / "harnesses" / INDUSTRY_DIRS[args.industry] /
                      "memory.json").read_text())
    harness = json.loads((OUTPUTS / f"harness-id-{args.industry}.json").read_text())
    role_arn = json.loads((OUTPUTS / "cdk-outputs.json").read_text())[
        "AgenticFinanceTools"]["HarnessRoleArn"]
    role_name = role_arn.split("/")[-1]

    control = boto3.client("bedrock-agentcore-control", region_name=args.region)

    # 1. CreateMemory (reuse if a memory with this name already exists)
    memory = None
    for m in control.list_memories().get("memories", []):
        if m.get("id", "").startswith(cfg["memoryName"]):
            memory = m
            print(f"Memory exists: {m['id']}")
            break
    if memory is None:
        resp = control.create_memory(
            name=cfg["memoryName"],
            eventExpiryDuration=cfg["eventExpiryDuration"],
            memoryStrategies=cfg["strategies"],
            clientToken=uuid.uuid4().hex + uuid.uuid4().hex[:8],
        )
        memory = resp["memory"]
        print(f"Created memory: {memory['id']}")

    memory_id = memory.get("id") or memory.get("memoryId")
    for _ in range(30):
        m = control.get_memory(memoryId=memory_id)["memory"]
        if m["status"] == "ACTIVE":
            break
        if m["status"] == "FAILED":
            raise SystemExit(f"Memory FAILED: {m.get('failureReason')}")
        print("memory status:", m["status"])
        time.sleep(10)
    memory_arn = m["arn"]
    strategies = {s["type"]: s["strategyId"] for s in m.get("strategies", [])}
    print("Memory ACTIVE:", memory_arn)
    print("Strategies:", strategies)

    # 2. UpdateHarness with retrievalConfig per strategy namespace
    ns_by_type = {
        "USER_PREFERENCE": "/users/{actorId}/preferences",
        "SEMANTIC": "/users/{actorId}/facts",
        "SUMMARIZATION": "/summaries/{actorId}/{sessionId}",
    }
    retrieval = {
        ns: {"strategyId": sid, "topK": 10, "relevanceScore": 0.2}
        for stype, sid in strategies.items()
        if (ns := ns_by_type.get(stype))
    }
    control.update_harness(
        harnessId=harness["harnessId"],
        clientToken=uuid.uuid4().hex + uuid.uuid4().hex[:8],
        memory={"optionalValue": {"agentCoreMemoryConfiguration": {
            "arn": memory_arn,
            "actorId": "web-user",
            "messagesCount": 20,
            "retrievalConfig": retrieval,
        }}},
    )
    print("Harness updated with memory config")

    # 3. IAM grant on the execution role (namespace placeholders -> globs)
    globs = [ns.replace("{actorId}", "*").replace("{sessionId}", "*") for ns in retrieval]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "MemoryEvents", "Effect": "Allow",
             "Action": EVENT_ACTIONS, "Resource": memory_arn},
            {"Sid": "MemoryRetrieval", "Effect": "Allow",
             "Action": RETRIEVAL_ACTIONS, "Resource": memory_arn,
             "Condition": {"StringLike": {"bedrock-agentcore:namespace": globs}}},
        ],
    }
    boto3.client("iam").put_role_policy(
        RoleName=role_name, PolicyName=f"memory-{cfg['memoryName']}",
        PolicyDocument=json.dumps(policy),
    )
    print(f"IAM policy attached to {role_name}")

    (OUTPUTS / f"memory-{args.industry}.json").write_text(json.dumps(
        {"memoryId": memory_id, "memoryArn": memory_arn, "strategies": strategies},
        indent=2))
    print("Done.")


if __name__ == "__main__":
    main()
