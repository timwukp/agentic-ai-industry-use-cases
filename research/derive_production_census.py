"""Snapshot the production CONFIRMED census — the paper's 'does the dual
gate ever issue a pass in production?' number, anchored as data.

Reads the nightly batch's latest PRISM#SUMMARY and PRISM#CAUSALITY items
(read-only) and writes research/results/production_census.json with the
edge-level grades, plus the campaign timeline derived from the local git
tags (freeze) and result-file commit dates (verdict).

Requires read access to the snapshots table; the committed artifact is the
reproducible record for readers without it.
"""

import json
import subprocess
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "research" / "results" / "production_census.json"
REGION = "us-east-1"
TABLE = "finance-market-snapshots"

TESTS = [  # (tag, verdict artifact path)
    ("qis-test-preregistered", "research/results/qis_test.json"),
    ("rfsv-test-preregistered", "research/results/rfsv_test.json"),
    ("signature-test-preregistered", "research/results/signature_test.json"),
    ("bocpd-test-preregistered", "research/results/bocpd_test.json"),
    ("bcfreq-test-preregistered", "research/results/bcfreq_test.json"),
    ("enso-farmppi-test-preregistered", "research/results/enso_test.json"),
]


def _git(*args):
    return subprocess.run(
        ["git", "-C", str(REPO), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def census():
    ddb = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    summary = ddb.get_item(Key={"pk": "PRISM#SUMMARY", "sk": "latest"})["Item"]
    causality = ddb.get_item(Key={"pk": "PRISM#CAUSALITY", "sk": "latest"})["Item"]
    edges = [
        {
            "source": e["source"],
            "target": e["target"],
            "horizon": int(e.get("horizon", 0)),
            "q_value": float(e["q_value"]) if e.get("q_value") is not None else None,
            "grade": e["grade"],
        }
        for e in causality["payload"]["edges"]
    ]
    s = summary["payload"]
    return {
        "snapshot_at": summary["fetched_at"],
        "prism_version": str(s["prism_version"]),
        "n_tested": int(s["causality"]["n_tested"]),
        "n_significant": int(s["causality"]["n_significant"]),
        "n_confirmed": int(s["confirmed"]),
        "edges": edges,
    }


def timeline():
    rows = []
    for tag, artifact in TESTS:
        frozen = _git("log", "-1", "--format=%cI", tag)
        verdict = _git("log", "-1", "--format=%cI", "origin/main", "--", artifact)
        rows.append({"tag": tag, "frozen": frozen, "verdict_committed": verdict})
    return rows


def main():
    OUT.write_text(
        json.dumps({"census": census(), "campaign_timeline": timeline()}, indent=1)
    )
    print(f"wrote {OUT.relative_to(REPO)}")
    print(json.dumps(json.loads(OUT.read_text())["census"], indent=1)[:400])


if __name__ == "__main__":
    main()
