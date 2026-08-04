#!/usr/bin/env python3
"""Render harness.template.json → deploy/outputs/harness-<industry>.json.

Fills placeholders from CDK outputs + gateway outputs + the system prompt file.
Usage: python deploy/render_harness.py --industry finance [--region us-east-1]
"""
import argparse
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"

import sys  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from industries import INDUSTRIES  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--industry", default="finance")
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    harness_dir = REPO / "harnesses" / INDUSTRIES[args.industry]["harness_dir"]
    template = (harness_dir / "harness.template.json").read_text()

    cdk = json.loads((OUTPUTS / "cdk-outputs.json").read_text())
    gateway = json.loads((OUTPUTS / f"gateway-{args.industry}.json").read_text())
    prompt = (harness_dir / "prompts" / "system.md").read_text().strip()

    replacements = {
        "{{SYSTEM_PROMPT}}": json.dumps(prompt)[1:-1],  # JSON-escape, strip quotes
        "{{GATEWAY_ARN}}": gateway["gatewayArn"],
        "{{REGION}}": args.region,
        "{{COGNITO_DISCOVERY_URL}}": cdk["AgenticAuth"]["DiscoveryUrl"],
        "{{COGNITO_CLIENT_ID}}": cdk["AgenticAuth"]["UserPoolClientId"],
    }
    for key, value in replacements.items():
        template = template.replace(key, value)

    rendered = json.loads(template)  # validate it's still valid JSON
    out_file = OUTPUTS / f"harness-{args.industry}.json"
    out_file.write_text(json.dumps(rendered, indent=2))
    print(f"Wrote {out_file}")
    print(f"  harnessName: {rendered['harnessName']}")
    print(f"  gateway:     {gateway['gatewayArn']}")
    print(
        f"  jwt clients: {rendered['authorizerConfiguration']['customJWTAuthorizer']['allowedClients']}"
    )


if __name__ == "__main__":
    main()
