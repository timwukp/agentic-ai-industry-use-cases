#!/usr/bin/env python3
"""Sync web/dist to the site bucket and invalidate CloudFront.

Also prints the .env.production values the build should have used, so a
mismatch is visible. Usage: python deploy/publish_web.py [--region us-east-1]
"""
import argparse
import json
import mimetypes
import subprocess
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = REPO / "deploy" / "outputs"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    web_out = json.loads((OUTPUTS / "web-outputs.json").read_text())["AgenticWeb"]
    bucket = web_out["SiteBucketName"]
    dist_id = web_out["DistributionId"]

    dist_dir = REPO / "web" / "dist"
    if not dist_dir.exists():
        raise SystemExit("web/dist not found — run `npm run build` in web/ first")

    subprocess.run(["aws", "s3", "sync", str(dist_dir), f"s3://{bucket}/",
                    "--delete", "--region", args.region], check=True)

    cf = boto3.client("cloudfront")
    cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/*"]},
            "CallerReference": f"publish-{dist_dir.stat().st_mtime_ns}",
        },
    )
    print(f"Published to s3://{bucket}, invalidated {dist_id}")
    print(f"URL: {web_out['CloudFrontUrl']}")


if __name__ == "__main__":
    main()
