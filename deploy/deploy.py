#!/usr/bin/env python3
"""End-to-end deploy orchestrator for one industry (default: finance).

Sequences:
  1. cdk deploy (core stacks)          5. create harness (skill script)
  2. seed data + KB ingestion          6. wire memory (skill script)
  3. create gateway + targets          7. observability (skill script)
  4. render + validate harness.json    8. smoke invoke

Skill scripts live in SKILL_DIR (agentcore-harness-builder). Each step is
idempotent; rerun the whole script safely. Use --from-step N to resume.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"
SKILL_DIR = Path(os.environ.get(
    "HARNESS_SKILL_DIR", str(Path.home() / "Downloads" / "agentcore-harness-builder")))
PY = sys.executable
REGION = os.environ.get("AWS_REGION", "us-east-1")

CORE_STACKS = ["AgenticSharedSecurity", "AgenticAuth", "AgenticFinanceData",
               "AgenticFinanceTools", "AgenticApi"]


def run(cmd: list[str], cwd: Path = REPO) -> None:
    print(f"\n>>> {' '.join(str(c) for c in cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)


def step_cdk(_args) -> None:
    cdk_bin = REPO / "node_modules" / ".bin" / "cdk"
    run([str(cdk_bin), "deploy", *CORE_STACKS, "--require-approval", "never",
         "--outputs-file", str(OUTPUTS / "cdk-outputs.json")],
        cwd=REPO / "infra" / "cdk")


def step_seed(args) -> None:
    run([PY, str(REPO / "deploy" / "seed_data.py"), "--region", args.region])


def step_gateway(args) -> None:
    run([PY, str(REPO / "deploy" / "create_gateway.py"),
         "--industry", args.industry, "--region", args.region])


def step_render(args) -> None:
    run([PY, str(REPO / "deploy" / "render_harness.py"),
         "--industry", args.industry, "--region", args.region])
    run([PY, str(SKILL_DIR / "scripts" / "validate_config.py"),
         "--config", str(OUTPUTS / f"harness-{args.industry}.json")])


def _harness_config(args) -> dict:
    return json.loads((OUTPUTS / f"harness-{args.industry}.json").read_text())


def _tools_outputs() -> dict:
    return json.loads((OUTPUTS / "cdk-outputs.json").read_text())["AgenticFinanceTools"]


def step_harness(args) -> None:
    run([PY, str(SKILL_DIR / "scripts" / "create_harness.py"),
         "--config", str(OUTPUTS / f"harness-{args.industry}.json"),
         "--role-arn", _tools_outputs()["HarnessRoleArn"],
         "--region", args.region])


def step_memory(args) -> None:
    harness_id = _find_harness_id(args)
    memory_cfg = json.loads(
        (REPO / "harnesses" / "finance-trading" / "memory.json").read_text())
    run([PY, str(SKILL_DIR / "scripts" / "wire_memory.py"),
         "--harness-id", harness_id,
         "--role-arn", _tools_outputs()["HarnessRoleArn"],
         "--memory-name", memory_cfg["memoryName"],
         "--region", args.region])


def step_observability(args) -> None:
    harness_id = _find_harness_id(args)
    run([PY, str(SKILL_DIR / "scripts" / "setup_observability.py"),
         "--harness-id", harness_id, "--region", args.region])


def step_smoke(args) -> None:
    harness_arn = _find_harness_arn(args)
    for prompt in [
        "List the names of every tool you have access to, grouped by category.",
        "Get a quote for AAPL, then show my default portfolio positions and total value.",
        "What does our margin policy say about leveraged ETFs?",
    ]:
        run([PY, str(SKILL_DIR / "scripts" / "invoke_harness.py"),
             "--harness-arn", harness_arn, "--prompt", prompt, "--region", args.region])


def _client(args):
    import boto3
    return boto3.client("bedrock-agentcore-control", region_name=args.region)


def _find_harness(args) -> dict:
    name = _harness_config(args)["harnessName"]
    client = _client(args)
    paginator = client.get_paginator("list_harnesses")
    for page in paginator.paginate():
        for h in page.get("items", []):
            if h["harnessName"] == name:
                return h
    raise SystemExit(f"Harness not found: {name}")


def _find_harness_id(args) -> str:
    return _find_harness(args)["harnessId"]


def _find_harness_arn(args) -> str:
    return _find_harness(args)["harnessArn"]


STEPS = [
    ("cdk", step_cdk), ("seed", step_seed), ("gateway", step_gateway),
    ("render", step_render), ("harness", step_harness), ("memory", step_memory),
    ("observability", step_observability), ("smoke", step_smoke),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--industry", default="finance")
    ap.add_argument("--region", default=REGION)
    ap.add_argument("--from-step", default=None, choices=[s for s, _ in STEPS])
    ap.add_argument("--only", default=None, choices=[s for s, _ in STEPS])
    args = ap.parse_args()

    steps = STEPS
    if args.only:
        steps = [(n, f) for n, f in STEPS if n == args.only]
    elif args.from_step:
        idx = [n for n, _ in STEPS].index(args.from_step)
        steps = STEPS[idx:]

    for name, fn in steps:
        print(f"\n========== step: {name} ==========")
        fn(args)
    print("\nAll steps complete.")


if __name__ == "__main__":
    main()
