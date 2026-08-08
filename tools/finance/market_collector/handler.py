"""Scheduled market-data collector — the ONLY component that calls providers.

Invoked by EventBridge Scheduler with {"job": "quotes"|"index"|"daily"|"fundamentals"}.
Each job fetches from its provider (Finnhub / Twelve Data / FRED), writes the
latest snapshot + a dated item to DynamoDB, and appends the raw rows to the
S3 lake (market/<dataset>/dt=YYYY-MM-DD/part-<ts>.jsonl.gz).

Tool Lambdas read the DynamoDB snapshot only — they never call providers, so
provider quota use is fixed by the schedules regardless of dashboard/agent
load, and a tile number and an agent-quoted number come from the same row.

Provider failures are isolated per symbol/series: one bad fetch is recorded
and skipped, the run continues, and the last good snapshot keeps serving with
its honest fetched_at.
"""

import gzip
import io
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import boto3

from toolkit.dynamo import table, to_decimal

USER_AGENT = "agentic-ai-industry-use-cases/1.0 (market-collector)"
HTTP_TIMEOUT = 10

# Default value-investing watchlist; the live list is stored at META#TRACKED
# and editable via the market-live tools without a redeploy.
DEFAULT_TRACKED = [
    "AAPL",
    "MSFT",
    "GOOGL",
    "AMZN",
    "NVDA",
    "META",
    "BRK.B",
    "JPM",
    "V",
    "JNJ",
    "PG",
    "XOM",
    "UNH",
    "HD",
    "KO",
    "PEP",
    "COST",
    "WMT",
    "TSM",
    "ASML",
]

# Twelve Data's free tier rejects true index symbols (IXIC/SPX need a paid
# plan — verified live 2026-08-08), so intraday index levels come from ETF
# proxies on Finnhub, honestly labeled as proxies. The official Nasdaq
# Composite daily close still arrives via FRED's NASDAQCOM in job_daily.
INDEX_PROXIES = {
    "QQQ": ("Nasdaq-100 (QQQ ETF proxy)", "Nasdaq-100"),
    "SPY": ("S&P 500 (SPY ETF proxy)", "S&P 500"),
}

# FRED series collected by the daily job. delay contract: T+1 end-of-day.
FRED_SERIES = {
    "NASDAQCOM": ("index_history", "Nasdaq Composite (daily close)"),
    "DGS1MO": ("treasury", "1-Month Treasury"),
    "DGS3MO": ("treasury", "3-Month Treasury"),
    "DGS6MO": ("treasury", "6-Month Treasury"),
    "DGS1": ("treasury", "1-Year Treasury"),
    "DGS2": ("treasury", "2-Year Treasury"),
    "DGS5": ("treasury", "5-Year Treasury"),
    "DGS10": ("treasury", "10-Year Treasury"),
    "DGS30": ("treasury", "30-Year Treasury"),
    "DFF": ("rates", "Effective Federal Funds Rate"),
    "DFEDTARU": ("rates", "Fed Funds Target Upper"),
    "DFEDTARL": ("rates", "Fed Funds Target Lower"),
    "SOFR": ("rates", "SOFR"),
}

DATED_TTL_DAYS = 30

_ssm_cache: dict[str, str] = {}


def _api_key(name: str) -> str:
    if name not in _ssm_cache:
        ssm = boto3.client("ssm")
        prefix = os.environ.get("SSM_KEY_PREFIX", "/agentic/finance")
        resp = ssm.get_parameter(Name=f"{prefix}/{name}", WithDecryption=True)
        _ssm_cache[name] = resp["Parameter"]["Value"]
    return _ssm_cache[name]


def _http_json(url: str) -> dict:
    # B310 guard: every URL here is built from a hardcoded https:// provider
    # base + urlencoded params; refuse anything else (file://, custom schemes).
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url.split(':', 1)[0]}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # nosec B310
        return json.loads(resp.read().decode("utf-8"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _snapshot(pk: str, payload: dict, provider: str, delay: str) -> None:
    """Write latest + dated item for one entity."""
    tbl = table("MARKET_SNAPSHOTS_TABLE")
    base = {
        "payload": to_decimal(payload),
        "provider": provider,
        "fetched_at": _now_iso(),
        "delay": delay,
    }
    tbl.put_item(Item={"pk": pk, "sk": "latest", **base})
    expires = int(time.time()) + DATED_TTL_DAYS * 86400
    tbl.put_item(Item={"pk": pk, "sk": f"d#{_today()}", "expiresAt": expires, **base})


def _lake_append(dataset: str, rows: list[dict]) -> None:
    if not rows:
        return
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        for row in rows:
            gz.write((json.dumps(row, separators=(",", ":")) + "\n").encode())
    key = (
        f"market/{dataset}/dt={_today()}/"
        f"part-{datetime.now(timezone.utc).strftime('%H%M%S')}.jsonl.gz"
    )
    boto3.client("s3").put_object(
        Bucket=os.environ["MARKET_LAKE_BUCKET"], Key=key, Body=buf.getvalue()
    )


def _tracked_symbols() -> list[str]:
    tbl = table("MARKET_SNAPSHOTS_TABLE")
    resp = tbl.get_item(Key={"pk": "META#TRACKED", "sk": "latest"})
    item = resp.get("Item")
    if not item:
        tbl.put_item(
            Item={
                "pk": "META#TRACKED",
                "sk": "latest",
                "payload": {"symbols": DEFAULT_TRACKED},
                "provider": "config",
                "fetched_at": _now_iso(),
                "delay": "static",
            }
        )
        return list(DEFAULT_TRACKED)
    return [str(s) for s in item["payload"]["symbols"]]


# ---------------- jobs ----------------


def job_quotes() -> dict:
    """Finnhub /quote per tracked symbol. ~20 calls/run vs 60/min quota."""
    key = _api_key("finnhub-api-key")
    ok, failed, rows = 0, [], []
    for symbol in _tracked_symbols():
        url = "https://finnhub.io/api/v1/quote?" + urllib.parse.urlencode(
            {"symbol": symbol, "token": key}
        )
        try:
            q = _http_json(url)
            if not q.get("c"):  # Finnhub returns c=0 for unknown symbols
                raise ValueError(f"empty quote for {symbol}")
            payload = {
                "symbol": symbol,
                "price": q["c"],
                "change": q.get("d"),
                "change_pct": q.get("dp"),
                "high": q.get("h"),
                "low": q.get("l"),
                "open": q.get("o"),
                "prev_close": q.get("pc"),
            }
            _snapshot(f"QUOTE#{symbol}", payload, "finnhub", "realtime-us")
            rows.append({**payload, "fetched_at": _now_iso()})
            ok += 1
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            failed.append(f"{symbol}: {exc}")
    _lake_append("quotes", rows)
    return {"ok": ok, "failed": failed}


def job_index() -> dict:
    """Finnhub /quote for the index ETF proxies. 2 calls/run vs 60/min."""
    key = _api_key("finnhub-api-key")
    ok, failed, rows = 0, [], []
    for symbol, (label, tracks) in INDEX_PROXIES.items():
        url = "https://finnhub.io/api/v1/quote?" + urllib.parse.urlencode(
            {"symbol": symbol, "token": key}
        )
        try:
            q = _http_json(url)
            if not q.get("c"):
                raise ValueError(f"empty quote for {symbol}")
            payload = {
                "index": symbol,
                "name": label,
                "tracks": tracks,
                "proxy": True,
                "level": q["c"],
                "change": q.get("d"),
                "change_pct": q.get("dp"),
            }
            _snapshot(f"INDEX#{symbol}", payload, "finnhub", "realtime-us")
            rows.append({**payload, "fetched_at": _now_iso()})
            ok += 1
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            failed.append(f"{symbol}: {exc}")
    _lake_append("indices", rows)
    return {"ok": ok, "failed": failed}


def job_daily() -> dict:
    """FRED daily batch: index history, treasury curve, policy rates."""
    key = _api_key("fred-api-key")
    start = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%d")
    ok, failed, rows = 0, [], []
    treasury: dict[str, dict] = {}
    rates: dict[str, dict] = {}
    for series_id, (group, label) in FRED_SERIES.items():
        url = (
            "https://api.stlouisfed.org/fred/series/observations?"
            + urllib.parse.urlencode(
                {
                    "series_id": series_id,
                    "api_key": key,
                    "file_type": "json",
                    "observation_start": start,
                    "sort_order": "desc",
                }
            )
        )
        try:
            obs = [
                o
                for o in _http_json(url)["observations"]
                if o["value"] not in (".", "")
            ]
            if not obs:
                raise ValueError(f"no observations for {series_id}")
            latest = obs[0]
            entry = {
                "series": series_id,
                "label": label,
                "value": float(latest["value"]),
                "as_of_date": latest["date"],
            }
            if group == "treasury":
                treasury[series_id] = entry
            elif group == "rates":
                rates[series_id] = entry
            else:
                _snapshot(f"INDEX_HISTORY#{series_id}", entry, "fred", "eod-t+1")
            rows.append({**entry, "fetched_at": _now_iso()})
            ok += 1
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            failed.append(f"{series_id}: {exc}")
    if treasury:
        _snapshot("TREASURY#CURVE", {"curve": treasury}, "fred", "eod-t+1")
    if rates:
        _snapshot("RATES#POLICY", {"rates": rates}, "fred", "eod-t+1")
    _lake_append("fred_daily", rows)
    return {"ok": ok, "failed": failed}


def job_fundamentals() -> dict:
    """Finnhub metrics + profile per tracked symbol, throttled under 60/min."""
    key = _api_key("finnhub-api-key")
    ok, failed, rows = 0, [], []
    for symbol in _tracked_symbols():
        base = {"symbol": symbol, "token": key}
        try:
            metric = _http_json(
                "https://finnhub.io/api/v1/stock/metric?"
                + urllib.parse.urlencode({**base, "metric": "all"})
            ).get("metric", {})
            profile = _http_json(
                "https://finnhub.io/api/v1/stock/profile2?"
                + urllib.parse.urlencode(base)
            )
            if not profile.get("name"):
                raise ValueError(f"no profile for {symbol}")
            payload = {
                "symbol": symbol,
                "name": profile.get("name"),
                "industry": profile.get("finnhubIndustry"),
                "market_cap_musd": profile.get("marketCapitalization"),
                "pe_ttm": metric.get("peTTM"),
                "pb": metric.get("pb"),
                "dividend_yield_pct": metric.get("currentDividendYieldTTM"),
                "roe_pct": metric.get("roeTTM"),
                "debt_to_equity": metric.get("totalDebt/totalEquityQuarterly"),
                "eps_growth_5y_pct": metric.get("epsGrowth5Y"),
                "week52_high": metric.get("52WeekHigh"),
                "week52_low": metric.get("52WeekLow"),
            }
            _snapshot(f"FUNDAMENTALS#{symbol}", payload, "finnhub", "eod-t+1")
            rows.append({**payload, "fetched_at": _now_iso()})
            ok += 1
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            failed.append(f"{symbol}: {exc}")
        # 2 calls/symbol; stay well under Finnhub's 60/min free-tier cap
        time.sleep(2.1)
    _lake_append("fundamentals", rows)
    return {"ok": ok, "failed": failed}


JOBS = {
    "quotes": job_quotes,
    "index": job_index,
    "daily": job_daily,
    "fundamentals": job_fundamentals,
}


def lambda_handler(event, context):
    job = (event or {}).get("job")
    if job not in JOBS:
        return {"error": f"unknown job: {job!r}", "known": sorted(JOBS)}
    result = JOBS[job]()
    print(json.dumps({"job": job, **result}))
    return {"job": job, **result}
