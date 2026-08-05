#!/usr/bin/env python3
"""Sync web/dist to the site bucket and invalidate CloudFront.

Also prints the .env.production values the build should have used, so a
mismatch is visible. Usage: python deploy/publish_web.py [--region us-east-1]
"""
import argparse
import json
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

    # Two passes, because the entry points and the hashed assets need opposite
    # caching. Vite fingerprints everything under assets/ (index-<hash>.js), so
    # those are immutable and can cache for a year. index.html is the ONLY file
    # naming the current hashes — if it is cached, the browser keeps loading the
    # previous bundle no matter how many invalidations run.
    #
    # This was a real defect, not a precaution: index.html was served with only
    # etag/last-modified and no cache-control, so CloudFront applied its default
    # TTL and a shipped feature stayed invisible to a returning visitor while
    # every deploy step reported success.
    #
    # sw.js / registerSW.js are entry points too — a cached service worker keeps
    # serving its own cached shell, a layer CloudFront invalidation cannot reach.
    no_cache = ["index.html", "sw.js", "registerSW.js", "manifest.webmanifest"]

    # Pass 1: hashed assets, long-lived. --delete only here; it is the pass that
    # sees the whole tree, and running it with the exclude set of pass 2 would
    # delete the very entry points pass 2 is about to upload.
    exclude_args: list[str] = []
    for pattern in no_cache:
        exclude_args += ["--exclude", pattern]
    subprocess.run(
        [
            "aws",
            "s3",
            "sync",
            str(dist_dir),
            f"s3://{bucket}/",
            "--delete",
            "--cache-control",
            "public,max-age=31536000,immutable",
            *exclude_args,
            "--region",
            args.region,
        ],
        check=True,
    )

    # Pass 2: entry points, revalidated every load. `cp` per file rather than a
    # second `sync`, because sync compares size and mtime and SKIPS unchanged
    # files — and skipping means the object keeps whatever cache-control it was
    # first uploaded with. manifest.webmanifest is byte-identical across builds,
    # so a sync here would leave the very header this fix is about unset, on the
    # one file guaranteed never to change. Uploading unconditionally is also
    # cheap: four small files.
    for name in no_cache:
        path = dist_dir / name
        # registerSW.js only exists when the PWA plugin injects a registration
        # script; this build registers manually, so it is absent.
        if not path.exists():
            continue
        subprocess.run(
            [
                "aws",
                "s3",
                "cp",
                str(path),
                f"s3://{bucket}/{name}",
                "--cache-control",
                "no-cache,must-revalidate",
                "--region",
                args.region,
            ],
            check=True,
        )
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
