#!/usr/bin/env python3
"""Wire OTel log/trace delivery for a harness runtime (idempotent).

Creates the delivery-source → delivery-destination → delivery triples the
skill's setup_observability.py leaves out:
  APPLICATION_LOGS → CloudWatch log group   (evaluations read from here)
  TRACES           → X-Ray

Usage: python deploy/setup_log_delivery.py --industry finance [--region us-east-1]
"""

import argparse
import json
import sys
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"
sys.path.insert(0, str(Path(__file__).resolve().parent))


def ensure(fn, exists_check, **kwargs):
    try:
        return fn(**kwargs)
    except Exception as exc:  # noqa: BLE001
        if "ConflictException" in type(exc).__name__ or "already exists" in str(exc):
            return exists_check()
        raise


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--industry", default="finance")
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    control = boto3.client("bedrock-agentcore-control", region_name=args.region)
    logs = boto3.client("logs", region_name=args.region)
    account = boto3.client("sts").get_caller_identity()["Account"]

    harness = json.loads((OUTPUTS / f"harness-id-{args.industry}.json").read_text())
    h = control.get_harness(harnessId=harness["harnessId"])["harness"]
    rt = h["environment"]["agentCoreRuntimeEnvironment"]
    runtime_arn = rt["agentRuntimeArn"]
    runtime_name = rt["agentRuntimeName"]
    runtime_id = rt["agentRuntimeId"]
    print(f"runtime: {runtime_id}")

    # the conventional default group evaluations read from
    log_group = f"/aws/bedrock-agentcore/runtimes/{runtime_id}-DEFAULT"
    try:
        logs.create_log_group(logGroupName=log_group)
        print(f"created log group {log_group}")
    except logs.exceptions.ResourceAlreadyExistsException:
        print(f"log group exists: {log_group}")
    logs.put_retention_policy(logGroupName=log_group, retentionInDays=30)

    prefix = f"harness-{args.industry}"
    # sources
    for suffix, log_type in (("app-logs", "APPLICATION_LOGS"), ("traces", "TRACES")):
        ensure(
            logs.put_delivery_source,
            lambda: None,
            name=f"{prefix}-{suffix}",
            resourceArn=runtime_arn,
            logType=log_type,
        )
        print(f"delivery source ready: {prefix}-{suffix}")

    # destinations
    ensure(
        logs.put_delivery_destination,
        lambda: None,
        name=f"{prefix}-cwl",
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={
            "destinationResourceArn": (
                f"arn:aws:logs:{args.region}:{account}:log-group:{log_group}:*"
            )
        },
    )
    # XRAY destination takes no destinationResourceArn (existing ones show
    # empty string on describe, but Put rejects short strings — omit the config)
    ensure(
        logs.put_delivery_destination,
        lambda: None,
        name=f"{prefix}-xray",
        deliveryDestinationType="XRAY",
    )
    print("delivery destinations ready")

    # deliveries (source -> destination). Must page: an account with many
    # harnesses has more destinations than one describe call returns, and the
    # one we just created is not guaranteed to be on the first page.
    dests: dict[str, str] = {}
    token = None
    while True:
        kwargs = {"limit": 50}
        if token:
            kwargs["nextToken"] = token
        page = logs.describe_delivery_destinations(**kwargs)
        dests.update({d["name"]: d["arn"] for d in page["deliveryDestinations"]})
        token = page.get("nextToken")
        if not token:
            break
    for suffix, dest_name in (
        ("app-logs", f"{prefix}-cwl"),
        ("traces", f"{prefix}-xray"),
    ):
        try:
            logs.create_delivery(
                deliverySourceName=f"{prefix}-{suffix}",
                deliveryDestinationArn=dests[dest_name],
            )
            print(f"delivery created: {prefix}-{suffix} -> {dest_name}")
        except logs.exceptions.ConflictException:
            print(f"delivery exists: {prefix}-{suffix} -> {dest_name}")

    (OUTPUTS / f"observability-{args.industry}.json").write_text(
        json.dumps(
            {
                "runtimeId": runtime_id,
                "runtimeName": runtime_name,
                "logGroup": log_group,
            },
            indent=2,
        )
    )
    print("Done.")


if __name__ == "__main__":
    main()
