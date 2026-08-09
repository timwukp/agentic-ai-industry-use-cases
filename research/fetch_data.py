"""Fetch the study's full data universe into research/data/.

- FRED: full history per series (from inception; the study cohorts trim).
- Stooq: gold (XAUUSD) daily back to 1968 — non-official mirror, research
  use only, disclosed in protocol §5.

GDELT is NOT fetched here (BigQuery route; see fetch_gdelt.sql). All output
is plain CSV in research/data/ — small, versioned by the study PR.
"""

import csv
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
DATA.mkdir(exist_ok=True)

DAILY_SERIES = [
    "NASDAQCOM",
    "DGS10",
    "DGS2",
    "DGS30",
    "DFF",
    "DCOILWTICO",
    "DCOILBRENTEU",
    "BAA10Y",
    "VIXCLS",
    "DTWEXBGS",
    "T10YIE",
]
MONTHLY_SERIES = ["CPIAUCSL", "UNRATE", "INDPRO", "TB3MS", "M2SL", "AAA", "BAA"]


def _fred_key() -> str:
    out = subprocess.run(
        [
            "aws",
            "ssm",
            "get-parameter",
            "--name",
            "/agentic/finance/fred-api-key",
            "--with-decryption",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def _http(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("https only")
    req = urllib.request.Request(url, headers={"User-Agent": "prism-study/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # nosec B310
        return resp.read()


def fetch_fred(series: list[str], key: str) -> None:
    for sid in series:
        url = (
            "https://api.stlouisfed.org/fred/series/observations?"
            + urllib.parse.urlencode(
                {
                    "series_id": sid,
                    "api_key": key,
                    "file_type": "json",
                    "observation_start": "1950-01-01",
                }
            )
        )
        obs = json.loads(_http(url))["observations"]
        rows = [(o["date"], o["value"]) for o in obs if o["value"] not in (".", "")]
        with open(DATA / f"{sid}.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["date", "value"])
            w.writerows(rows)
        print(f"{sid}: {len(rows)} obs ({rows[0][0]} → {rows[-1][0]})")
        time.sleep(0.6)  # stay far under FRED's 120/min


def fetch_gold() -> None:
    """PROTOCOL DEVIATION (logged in report §Deviations): Stooq CSV export
    is behind a JavaScript challenge (verified 2026-08-09) — infeasible
    without a headless browser, which would violate the plain-HTTP,
    reproducible-fetch requirement. Fallback: Twelve Data time_series,
    which reaches 2007-12 (verified live) — covers C20 from 2007-12 and
    C10 fully. Gold analyses before 2007-12 are out of scope."""
    out = subprocess.run(
        [
            "aws",
            "ssm",
            "get-parameter",
            "--name",
            "/agentic/finance/twelvedata-api-key",
            "--with-decryption",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    td_key = out.stdout.strip()
    url = "https://api.twelvedata.com/time_series?" + urllib.parse.urlencode(
        {
            "symbol": "XAU/USD",
            "interval": "1day",
            "outputsize": "5000",
            "apikey": td_key,
        }
    )
    d = json.loads(_http(url))
    vals = d.get("values", [])
    if len(vals) < 3000:
        raise SystemExit(f"gold history too short: {len(vals)}")
    rows = sorted((v["datetime"], v["close"]) for v in vals)
    with open(DATA / "XAUUSD.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["date", "value"])
        w.writerows(rows)
    print(f"XAUUSD (twelvedata): {len(rows)} obs ({rows[0][0]} → {rows[-1][0]})")


if __name__ == "__main__":
    key = _fred_key()
    fetch_fred(DAILY_SERIES + MONTHLY_SERIES, key)
    try:
        fetch_gold()
    except Exception as exc:  # noqa: BLE001
        print(f"WARN gold fetch failed: {exc} — gold excluded per protocol §5")
    sys.exit(0)
