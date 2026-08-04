#!/usr/bin/env python3
"""Seed DynamoDB demo data and run KB ingestion (idempotent).

Usage: python deploy/seed_data.py [--region us-east-1] [--skip-kb]
"""
import argparse
import json
import time
from decimal import Decimal
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"

DEMO_POSITIONS = [
    ("AAPL", 100, "185.50"),
    ("MSFT", 50, "380.20"),
    ("GOOGL", 75, "145.00"),
    ("AMZN", 40, "178.50"),
    ("NVDA", 30, "490.00"),
    ("JPM", 80, "195.00"),
]


def seed_portfolio(region: str, table_name: str) -> None:
    tbl = boto3.resource("dynamodb", region_name=region).Table(table_name)
    for sym, qty, cost in DEMO_POSITIONS:
        tbl.put_item(
            Item={
                "portfolioId": "default",
                "sk": f"POSITION#{sym}",
                "symbol": sym,
                "quantity": qty,
                "avgCost": Decimal(cost),
            }
        )
    print(f"Seeded {len(DEMO_POSITIONS)} positions into {table_name}")


def ingest_kb(region: str, kb_id: str, ds_id: str) -> None:
    client = boto3.client("bedrock-agent", region_name=region)
    job = client.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id)
    job_id = job["ingestionJob"]["ingestionJobId"]
    print(f"Ingestion job {job_id} started")
    for _ in range(60):
        state = client.get_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )["ingestionJob"]
        status = state["status"]
        if status == "COMPLETE":
            print(
                "Ingestion complete:",
                json.dumps(state.get("statistics", {}), default=str),
            )
            return
        if status == "FAILED":
            raise SystemExit(f"Ingestion failed: {state.get('failureReasons')}")
        time.sleep(10)
    raise SystemExit("Ingestion timed out after 10 minutes")


def main() -> None:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from industries import INDUSTRIES

    ap = argparse.ArgumentParser()
    ap.add_argument("--industry", default="finance")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--skip-kb", action="store_true")
    args = ap.parse_args()

    outputs = json.loads((OUTPUTS / "cdk-outputs.json").read_text())
    if args.industry == "finance":  # only finance has demo tables to seed
        seed_portfolio(args.region, outputs["AgenticFinanceData"]["PortfolioTableName"])
    if not args.skip_kb:
        tools_out = outputs[INDUSTRIES[args.industry]["stack"]]
        ingest_kb(
            args.region, tools_out["KnowledgeBaseId"], tools_out["KbDataSourceId"]
        )


if __name__ == "__main__":
    main()
