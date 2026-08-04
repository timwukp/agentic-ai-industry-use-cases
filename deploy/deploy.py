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
SKILL_DIR = Path(
    os.environ.get(
        "HARNESS_SKILL_DIR",
        str(Path.home() / "Downloads" / "agentcore-harness-builder"),
    )
)
PY = sys.executable
REGION = os.environ.get("AWS_REGION", "us-east-1")

CORE_STACKS = [
    "AgenticSharedSecurity",
    "AgenticAuth",
    "AgenticFinanceData",
    "AgenticFinanceTools",
    "AgenticApi",
]


def run(cmd: list[str], cwd: Path = REPO) -> None:
    print(f"\n>>> {' '.join(str(c) for c in cmd)}")
    env = os.environ.copy()
    # cdk.json runs `python3 app.py`; make sure the repo venv wins on PATH
    env["PATH"] = f"{Path(PY).parent}:{env['PATH']}"
    subprocess.run(cmd, cwd=cwd, check=True, env=env)


def step_cdk(args) -> None:
    sys.path.insert(0, str(REPO / "deploy"))
    from industries import INDUSTRIES

    stacks = list(CORE_STACKS)
    industry_stack = INDUSTRIES[args.industry]["stack"]
    if industry_stack not in stacks:
        stacks.append(industry_stack)
    cdk_bin = REPO / "node_modules" / ".bin" / "cdk"
    # cdk --outputs-file truncates the file to just this run's stacks, so write
    # to a scratch file and merge — otherwise deploying industry N erases the
    # outputs (gateway role, KB id, tool ARNs) that industries 1..N-1 need.
    scratch = OUTPUTS / f"cdk-outputs-{args.industry}.json"
    run(
        [
            str(cdk_bin),
            "deploy",
            *stacks,
            "--require-approval",
            "never",
            "--outputs-file",
            str(scratch),
        ],
        cwd=REPO / "infra" / "cdk",
    )
    merged = OUTPUTS / "cdk-outputs.json"
    combined = json.loads(merged.read_text()) if merged.exists() else {}
    combined.update(json.loads(scratch.read_text()))
    merged.write_text(json.dumps(combined, indent=2, sort_keys=True))
    scratch.unlink()


def step_seed(args) -> None:
    run(
        [
            PY,
            str(REPO / "deploy" / "seed_data.py"),
            "--industry",
            args.industry,
            "--region",
            args.region,
        ]
    )


def step_gateway(args) -> None:
    run(
        [
            PY,
            str(REPO / "deploy" / "create_gateway.py"),
            "--industry",
            args.industry,
            "--region",
            args.region,
        ]
    )


def step_render(args) -> None:
    run(
        [
            PY,
            str(REPO / "deploy" / "render_harness.py"),
            "--industry",
            args.industry,
            "--region",
            args.region,
        ]
    )
    run(
        [
            PY,
            str(SKILL_DIR / "scripts" / "validate_config.py"),
            "--config",
            str(OUTPUTS / f"harness-{args.industry}.json"),
        ]
    )


def _harness_config(args) -> dict:
    return json.loads((OUTPUTS / f"harness-{args.industry}.json").read_text())


def _tools_outputs(args) -> dict:
    sys.path.insert(0, str(REPO / "deploy"))
    from industries import INDUSTRIES

    stack = INDUSTRIES[args.industry]["stack"]
    return json.loads((OUTPUTS / "cdk-outputs.json").read_text())[stack]


def step_harness(args) -> None:
    run(
        [
            PY,
            str(SKILL_DIR / "scripts" / "create_harness.py"),
            "--config",
            str(OUTPUTS / f"harness-{args.industry}.json"),
            "--role-arn",
            _tools_outputs(args)["HarnessRoleArn"],
            "--region",
            args.region,
        ]
    )


def step_memory(args) -> None:
    _save_harness_id(args)  # our wire_memory reads harness-id-<industry>.json
    run(
        [
            PY,
            str(REPO / "deploy" / "wire_memory.py"),
            "--industry",
            args.industry,
            "--region",
            args.region,
        ]
    )


def step_observability(args) -> None:
    _save_harness_id(args)
    run(
        [
            PY,
            str(REPO / "deploy" / "setup_log_delivery.py"),
            "--industry",
            args.industry,
            "--region",
            args.region,
        ]
    )
    run(
        [
            PY,
            str(REPO / "deploy" / "setup_evaluations.py"),
            "--industry",
            args.industry,
            "--region",
            args.region,
        ]
    )


SMOKE_PROMPTS = {
    "finance": [
        "Get a quote for AAPL, then show my default portfolio positions and total value.",
        "What does our margin policy say about leveraged ETFs?",
    ],
    "healthcare": [
        "Check drug interactions between warfarin and aspirin.",
        "What does our medication safety policy require before dispensing high-alert drugs?",
    ],
    "insurance": [
        "Submit a demo auto claim for policy POL-2001, then check its fraud risk.",
        "What does our claims handling manual say about total-loss vehicles?",
    ],
    "retail": [
        "Check inventory for SKU-1001 and forecast its demand for the next 30 days.",
        "What does our supplier SLA standard require for on-time delivery?",
    ],
    "manufacturing": [
        "Get the status of equipment EQ-100 and predict its failure risk.",
        "What does our maintenance standard say about ISO 10816 vibration zones?",
    ],
    "realestate": [
        "Estimate the value of a 3-bed 2-bath 1800 sqft property in Austin.",
        "What does our appraisal methodology guide say about comparable selection?",
    ],
}


def step_smoke(args) -> None:
    # JWT end-user path (harness inbound auth is customJWTAuthorizer, so the
    # skill's IAM-signed invoke_harness.py would be rejected)
    _save_harness_id(args)
    prompts = [
        "List the names of every tool you have access to, grouped by category.",
        *SMOKE_PROMPTS.get(args.industry, []),
    ]
    for prompt in prompts:
        run(
            [
                PY,
                str(REPO / "deploy" / "smoke_invoke.py"),
                "--industry",
                args.industry,
                "--prompt",
                prompt,
                "--region",
                args.region,
            ]
        )


def _client(args):
    import boto3

    return boto3.client("bedrock-agentcore-control", region_name=args.region)


def _find_harness(args) -> dict:
    import time

    name = _harness_config(args)["harnessName"]
    client = _client(args)
    resp = client.list_harnesses()
    key = next(k for k in resp if k not in ("ResponseMetadata", "nextToken"))
    for h in resp[key]:
        if h["harnessName"] == name:
            # wait until it leaves CREATING/UPDATING — downstream steps need READY
            for _ in range(30):
                detail = client.get_harness(harnessId=h["harnessId"])["harness"]
                if detail["status"] == "READY":
                    return detail
                if detail["status"] in ("FAILED", "DELETING"):
                    raise SystemExit(f"Harness {name} entered {detail['status']}")
                print(f"harness status: {detail['status']}")
                time.sleep(10)
            raise SystemExit(f"Harness {name} never reached READY")
    raise SystemExit(f"Harness not found: {name}")


def _save_harness_id(args) -> dict:
    """Persist harness-id-<industry>.json (wire_memory/log_delivery read it)."""
    h = _find_harness(args)
    account = _tools_outputs(args)["HarnessRoleArn"].split(":")[4]
    arn = h.get("arn") or (
        f"arn:aws:bedrock-agentcore:{args.region}:{account}:harness/{h['harnessId']}"
    )
    info = {"harnessId": h["harnessId"], "harnessArn": arn}
    (OUTPUTS / f"harness-id-{args.industry}.json").write_text(
        json.dumps(info, indent=2)
    )
    return info


def _find_harness_id(args) -> str:
    return _find_harness(args)["harnessId"]


def _find_harness_arn(args) -> str:
    return _save_harness_id(args)["harnessArn"]


STEPS = [
    ("cdk", step_cdk),
    ("seed", step_seed),
    ("gateway", step_gateway),
    ("render", step_render),
    ("harness", step_harness),
    ("memory", step_memory),
    ("observability", step_observability),
    ("smoke", step_smoke),
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
