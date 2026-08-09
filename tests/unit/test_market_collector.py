"""market_collector: provider fetch → snapshot + lake write, failure isolation.

urllib is monkeypatched with canned provider payloads — no network. Numeric
fixture values deliberately avoid bare 9-digit runs (CI's PII scan would flag
them as SSN candidates).
"""

import gzip
import importlib
import io
import json
import os
import sys
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[2]


def _load(monkeypatch, responses: dict[str, dict]):
    """Import a fresh collector with urllib.urlopen returning canned JSON by URL match."""
    sys.path.insert(0, str(REPO / "tools" / "finance" / "market_collector"))
    try:
        import handler

        handler = importlib.reload(handler)
    finally:
        sys.path.pop(0)

    class FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        for fragment, payload in responses.items():
            if fragment in url:
                if isinstance(payload, Exception):
                    raise payload
                return FakeResp(json.dumps(payload).encode())
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(handler.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(handler, "_api_key", lambda name: "test-key")
    monkeypatch.setattr(handler.time, "sleep", lambda s: None)
    return handler


def _lake_keys():
    s3 = boto3.client("s3", region_name="us-east-1")
    resp = s3.list_objects_v2(Bucket=os.environ["MARKET_LAKE_BUCKET"])
    return [o["Key"] for o in resp.get("Contents", [])]


def test_quotes_job_writes_snapshot_and_lake(market_snapshots, monkeypatch):
    h = _load(
        monkeypatch,
        {
            "finnhub.io/api/v1/quote": {
                "c": 232.5,
                "d": 2.8,
                "dp": 1.22,
                "h": 234.1,
                "l": 229.9,
                "o": 230.2,
                "pc": 229.7,
            }
        },
    )
    monkeypatch.setattr(h, "_tracked_symbols", lambda: ["AAPL", "MSFT"])
    result = h.job_quotes()
    assert result == {"ok": 2, "failed": []}

    item = market_snapshots.get_item(Key={"pk": "QUOTE#AAPL", "sk": "latest"})["Item"]
    assert item["provider"] == "finnhub"
    assert item["delay"] == "realtime-us"
    assert float(item["payload"]["price"]) == 232.5

    dated = market_snapshots.get_item(
        Key={"pk": "QUOTE#AAPL", "sk": f"d#{h._today()}"}
    )["Item"]
    assert "expiresAt" in dated  # rolling window self-prunes

    keys = _lake_keys()
    assert len(keys) == 1 and keys[0].startswith("quotes/") is False
    assert keys[0].startswith("market/quotes/dt=")
    body = (
        boto3.client("s3", region_name="us-east-1")
        .get_object(Bucket=os.environ["MARKET_LAKE_BUCKET"], Key=keys[0])["Body"]
        .read()
    )
    rows = [json.loads(line) for line in gzip.decompress(body).splitlines()]
    assert len(rows) == 2 and rows[0]["symbol"] == "AAPL"


def test_quote_failure_is_isolated_per_symbol(market_snapshots, monkeypatch):
    calls = {"n": 0}

    def flaky(req, timeout=None):
        calls["n"] += 1
        payload = (
            {"c": 0}
            if calls["n"] == 1
            else {
                "c": 111.5,
                "d": 1,
                "dp": 0.5,
                "h": 112,
                "l": 110,
                "o": 111,
                "pc": 110.9,
            }
        )

        class R(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return R(json.dumps(payload).encode())

    h = _load(monkeypatch, {})
    monkeypatch.setattr(h.urllib.request, "urlopen", flaky)
    monkeypatch.setattr(h, "_tracked_symbols", lambda: ["BAD", "GOOD"])
    result = h.job_quotes()
    assert result["ok"] == 1
    assert len(result["failed"]) == 1 and "BAD" in result["failed"][0]
    # the good symbol still landed
    assert "Item" in market_snapshots.get_item(Key={"pk": "QUOTE#GOOD", "sk": "latest"})


def test_daily_job_builds_curve_rates_macro_and_gold(market_snapshots, monkeypatch):
    h = _load(
        monkeypatch,
        {
            "api.stlouisfed.org": {
                "observations": [
                    {"date": "2026-08-07", "value": "4.25"},
                    {"date": "2026-08-06", "value": "."},  # FRED missing marker
                ]
            },
            "api.twelvedata.com": {"close": "4342.35", "percent_change": "0.4"},
        },
    )
    result = h.job_daily()
    assert result["failed"] == []
    curve = market_snapshots.get_item(Key={"pk": "TREASURY#CURVE", "sk": "latest"})[
        "Item"
    ]
    assert curve["provider"] == "fred"
    assert float(curve["payload"]["curve"]["DGS10"]["value"]) == 4.25
    rates = market_snapshots.get_item(Key={"pk": "RATES#POLICY", "sk": "latest"})[
        "Item"
    ]
    assert "DFF" in rates["payload"]["rates"]
    # Phase 2: macro series snapshot + rollup + gold
    oil = market_snapshots.get_item(Key={"pk": "MACRO#DCOILWTICO", "sk": "latest"})[
        "Item"
    ]
    assert float(oil["payload"]["value"]) == 4.25
    rollup = market_snapshots.get_item(Key={"pk": "MACRO#ALL", "sk": "latest"})["Item"]
    assert "VIXCLS" in rollup["payload"]["series"]
    gold = market_snapshots.get_item(Key={"pk": "GOLD#XAUUSD", "sk": "latest"})["Item"]
    assert gold["provider"] == "twelvedata"
    assert float(gold["payload"]["value"]) == 4342.35


def test_daily_job_gold_failure_does_not_sink_fred(market_snapshots, monkeypatch):
    h = _load(
        monkeypatch,
        {
            "api.stlouisfed.org": {
                "observations": [{"date": "2026-08-07", "value": "4.25"}]
            },
            "api.twelvedata.com": {"status": "error", "message": "quota exhausted"},
        },
    )
    result = h.job_daily()
    assert len(result["failed"]) == 1 and "XAU/USD" in result["failed"][0]
    # FRED data still landed
    assert "Item" in market_snapshots.get_item(
        Key={"pk": "TREASURY#CURVE", "sk": "latest"}
    )


def test_tracked_symbols_seeds_default_watchlist(market_snapshots, monkeypatch):
    h = _load(monkeypatch, {})
    symbols = h._tracked_symbols()
    assert symbols == h.DEFAULT_TRACKED
    # seeded row persists so the list is editable without a redeploy
    item = market_snapshots.get_item(Key={"pk": "META#TRACKED", "sk": "latest"})["Item"]
    assert list(item["payload"]["symbols"]) == h.DEFAULT_TRACKED


def test_quota_budget_quotes_within_finnhub_free_tier(market_snapshots, monkeypatch):
    """One quotes run must stay under Finnhub's 60 calls/min free tier."""
    h = _load(
        monkeypatch,
        {"finnhub.io": {"c": 1.0, "d": 0, "dp": 0, "h": 1, "l": 1, "o": 1, "pc": 1}},
    )
    assert len(h.DEFAULT_TRACKED) < 60


def test_unknown_job_is_rejected(market_snapshots, monkeypatch):
    h = _load(monkeypatch, {})
    out = h.lambda_handler({"job": "nope"}, None)
    assert "error" in out and "nope" in out["error"]


def test_http_json_refuses_non_https(market_snapshots, monkeypatch):
    """The B310 scheme guard must actually reject, not just annotate."""
    import pytest

    h = _load(monkeypatch, {})
    for url in ("http://finnhub.io/x", "file:///etc/passwd", "ftp://x"):
        with pytest.raises(ValueError, match="refusing non-https"):
            h._http_json(url)
