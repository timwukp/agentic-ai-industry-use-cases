#!/usr/bin/env python3
"""Create an online evaluation config for a harness (idempotent).

Samples 100% of live traffic from the runtime's OTel log group and scores it
with built-in evaluators. Results land in AgentCore Observability
(CloudWatch → /aws/bedrock-agentcore/evaluations/results/<config-id>).

PREREQUISITE: the harness role must be able to write traces (the
ObservabilityTraces statement in IndustryStack: xray:PutTraceSegments,
xray:PutTelemetryRecords, cloudwatch:PutMetricData). Without it the OTel
exporter gets 403, no span ever reaches aws/spans, and this evaluator sits
ACTIVE forever with an empty results log group — there is no error surfaced
anywhere. Verify spans arrive before trusting the evaluator:
  aws logs filter-log-events --log-group-name aws/spans \
    --filter-pattern '"harness_<name>"' --max-items 1

Usage: python deploy/setup_evaluations.py --industry finance [--region us-east-1]
"""

import argparse
import json
import sys
import uuid
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from industries import INDUSTRIES  # noqa: E402, F401

EVALUATORS = [
    "Builtin.Helpfulness",
    "Builtin.GoalSuccessRate",
    "Builtin.ToolSelectionAccuracy",
    "Builtin.ToolParameterAccuracy",
    "Builtin.Faithfulness",
]

EVAL_ROLE = "AgentCoreEvalExecutionRole"  # shared, created by prior projects


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--industry", default="finance")
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    control = boto3.client("bedrock-agentcore-control", region_name=args.region)
    account = boto3.client("sts").get_caller_identity()["Account"]
    obs = json.loads((OUTPUTS / f"observability-{args.industry}.json").read_text())

    name = f"{args.industry}_harness_quality"
    existing = control.list_online_evaluation_configs().get(
        "onlineEvaluationConfigs", []
    )
    if any(c["onlineEvaluationConfigName"] == name for c in existing):
        print(f"Evaluation config exists: {name}")
        return

    resp = control.create_online_evaluation_config(
        onlineEvaluationConfigName=name,
        description=f"Live-traffic quality scores for the {args.industry} harness",
        rule={"samplingConfig": {"samplingPercentage": 100.0}},
        dataSourceConfig={
            "cloudWatchLogs": {
                "logGroupNames": [obs["logGroup"]],
                "serviceNames": [f"{obs['runtimeName']}.DEFAULT"],
            }
        },
        evaluators=[{"evaluatorId": e} for e in EVALUATORS],
        evaluationExecutionRoleArn=f"arn:aws:iam::{account}:role/{EVAL_ROLE}",
        enableOnCreate=True,
        clientToken=uuid.uuid4().hex + uuid.uuid4().hex[:8],
        tags={"project": "agentic-ai-industry-use-cases", "industry": args.industry},
    )
    cfg_id = resp.get("onlineEvaluationConfigId")
    print(f"Created evaluation config: {name} ({cfg_id})")
    print(f"Evaluators: {', '.join(EVALUATORS)}")
    print(f"Results: /aws/bedrock-agentcore/evaluations/results/{cfg_id}")


if __name__ == "__main__":
    main()
