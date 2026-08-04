#!/usr/bin/env python3
"""Create the AgentCore Gateway + Lambda targets for an industry (idempotent).

Usage:
    python deploy/create_gateway.py --industry finance [--region us-east-1] [--dry-run]

Reads CDK outputs from deploy/outputs/cdk-outputs.json, creates:
  1. Gateway  (MCP protocol, AWS_IAM inbound auth)
  2. One Lambda target per schema file in tools/<industry>/schemas/
  3. SynchronizeGatewayTargets, then waits for READY

Writes the gateway ARN to deploy/outputs/gateway-<industry>.json.
"""
import argparse
import json
import time
import uuid
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"

# schema file stem -> {lambda output key} per industry
INDUSTRY_CONFIG = {
    "finance": {
        "gateway_name": "finance-trading-gw",
        "stack": "AgenticFinanceTools",
        "role_output": "GatewayRoleArn",
        # target name must match ([0-9a-zA-Z][-]?){1,100} — no underscores;
        # keys are (targetName, schemaFileStem)
        "targets": {
            ("market-data", "market_data"): "ToolLambdaMarketDataArn",
            ("portfolio", "portfolio"): "ToolLambdaPortfolioArn",
            ("risk", "risk"): "ToolLambdaRiskArn",
            ("trading", "trading"): "ToolLambdaTradingArn",
            ("kb", "kb"): "ToolLambdaKbSearchArn",
        },
    },
}


def load_outputs(stack: str) -> dict:
    data = json.loads((OUTPUTS / "cdk-outputs.json").read_text())
    return data[stack]


def find_gateway(client, name: str):
    paginator = client.get_paginator("list_gateways")
    for page in paginator.paginate():
        for gw in page.get("items", []):
            if gw["name"] == name:
                return gw
    return None


def existing_targets(client, gateway_id: str) -> dict:
    out = {}
    paginator = client.get_paginator("list_gateway_targets")
    for page in paginator.paginate(gatewayIdentifier=gateway_id):
        for t in page.get("items", []):
            out[t["name"]] = t
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--industry", default="finance")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cfg = INDUSTRY_CONFIG[args.industry]
    outputs = load_outputs(cfg["stack"])
    role_arn = outputs[cfg["role_output"]]
    client = boto3.client("bedrock-agentcore-control", region_name=args.region)

    gw = find_gateway(client, cfg["gateway_name"])
    if gw:
        print(f"Gateway exists: {gw['gatewayId']}")
    else:
        params = dict(
            name=cfg["gateway_name"],
            roleArn=role_arn,
            protocolType="MCP",
            authorizerType="AWS_IAM",
            clientToken=uuid.uuid4().hex + uuid.uuid4().hex[:8],
        )
        if args.dry_run:
            print("DRY RUN create_gateway:", json.dumps(params, indent=2))
            return
        gw = client.create_gateway(**params)
        print(f"Created gateway: {gw['gatewayId']}")

    gateway_id = gw["gatewayId"]
    have = existing_targets(client, gateway_id)

    for (target_name, schema_stem), lambda_key in cfg["targets"].items():
        if target_name in have:
            print(f"Target exists: {target_name}")
            continue
        schema = json.loads(
            (
                REPO / "tools" / args.industry / "schemas" / f"{schema_stem}.json"
            ).read_text()
        )
        params = dict(
            gatewayIdentifier=gateway_id,
            name=target_name,
            targetConfiguration={
                "mcp": {
                    "lambda": {
                        "lambdaArn": outputs[lambda_key],
                        "toolSchema": {"inlinePayload": schema},
                    }
                }
            },
            credentialProviderConfigurations=[
                {"credentialProviderType": "GATEWAY_IAM_ROLE"}
            ],
            clientToken=uuid.uuid4().hex + uuid.uuid4().hex[:8],
        )
        if args.dry_run:
            print(f"DRY RUN create_gateway_target {target_name}")
            continue
        client.create_gateway_target(**params)
        print(f"Created target: {target_name} ({len(schema)} tools)")

    if args.dry_run:
        return

    # targetIdList accepts exactly one id per call
    for tname, tinfo in existing_targets(client, gateway_id).items():
        if tinfo.get("status") == "READY":
            print(f"Target READY: {tname}")
            continue
        try:
            client.synchronize_gateway_targets(
                gatewayIdentifier=gateway_id, targetIdList=[tinfo["targetId"]]
            )
            print(f"Synchronize requested: {tname}")
        except Exception as exc:  # noqa: BLE001 — status poll below is the gate
            print(f"Synchronize skipped for {tname}: {exc}")

    for _ in range(30):
        gw_state = client.get_gateway(gatewayIdentifier=gateway_id)
        status = gw_state.get("status")
        print(f"Gateway status: {status}")
        if status == "READY":
            break
        if status in ("FAILED", "DELETING"):
            raise SystemExit(
                f"Gateway entered {status}: {gw_state.get('statusReasons')}"
            )
        time.sleep(10)

    result = {
        "gatewayId": gateway_id,
        "gatewayArn": gw_state["gatewayArn"],
        "gatewayUrl": gw_state.get("gatewayUrl"),
        "targets": sorted(t for t, _ in cfg["targets"]),
    }
    out_file = OUTPUTS / f"gateway-{args.industry}.json"
    out_file.write_text(json.dumps(result, indent=2))
    print(f"Wrote {out_file}")


if __name__ == "__main__":
    main()
