"""market_live tools: DynamoDB reads, live envelope, staleness, error paths."""

import importlib
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load():
    sys.path.insert(0, str(REPO / "tools" / "finance" / "market_live"))
    try:
        import handler

        return importlib.reload(handler)
    finally:
        sys.path.pop(0)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _put(tbl, pk, payload, *, provider="finnhub", delay="realtime-us", age_s=0):
    fetched = datetime.now(timezone.utc) - timedelta(seconds=age_s)
    tbl.put_item(
        Item={
            "pk": pk,
            "sk": "latest",
            "payload": payload,
            "provider": provider,
            "fetched_at": _iso(fetched),
            "delay": delay,
        }
    )


def test_live_quote_envelope(market_snapshots):
    _put(
        market_snapshots,
        "QUOTE#AAPL",
        {"symbol": "AAPL", "price": Decimal("232.50"), "change_pct": Decimal("1.2")},
    )
    h = _load()
    out = h.get_live_quote("aapl")  # case-insensitive lookup
    assert out["source"] == "live"
    assert out["provider"] == "finnhub"
    assert out["delay"] == "realtime-us"
    assert out["price"] == 232.5  # Decimals converted for JSON
    assert "fetched_at" in out
    assert "stale" not in out


def test_stale_flag_when_snapshot_old(market_snapshots):
    # quotes cadence is 15 min; 2x = 30 min. 45 min old => stale.
    _put(
        market_snapshots,
        "QUOTE#MSFT",
        {"symbol": "MSFT", "price": Decimal("500")},
        age_s=45 * 60,
    )
    h = _load()
    assert h.get_live_quote("MSFT")["stale"] is True


def test_daily_series_not_stale_within_two_days(market_snapshots):
    # FRED is T+1 daily; 30h old must NOT be stale (weekend tolerance is 2d)
    _put(
        market_snapshots,
        "TREASURY#CURVE",
        {
            "curve": {
                "DGS2": {"series": "DGS2", "value": Decimal("3.9")},
                "DGS10": {"series": "DGS10", "value": Decimal("4.3")},
            }
        },
        provider="fred",
        delay="eod-t+1",
        age_s=30 * 3600,
    )
    h = _load()
    out = h.get_treasury_yields()
    assert "stale" not in out
    assert out["spread_10y_2y"] == 0.4
    assert out["curve_inverted"] is False


def test_inverted_curve_flag(market_snapshots):
    _put(
        market_snapshots,
        "TREASURY#CURVE",
        {
            "curve": {
                "DGS2": {"series": "DGS2", "value": Decimal("4.9")},
                "DGS10": {"series": "DGS10", "value": Decimal("4.3")},
            }
        },
        provider="fred",
        delay="eod-t+1",
    )
    h = _load()
    out = h.get_treasury_yields()
    assert out["spread_10y_2y"] == -0.6
    assert out["curve_inverted"] is True


def test_missing_entity_returns_error_not_fabrication(market_snapshots):
    h = _load()
    out = h.get_live_quote("ZZZZ")
    assert "error" in out
    assert "price" not in out  # never invent a number


def test_missing_quote_lists_tracked_symbols(market_snapshots):
    _put(
        market_snapshots,
        "META#TRACKED",
        {"symbols": ["AAPL", "MSFT"]},
        provider="config",
        delay="static",
    )
    h = _load()
    out = h.get_live_quote("ZZZZ")
    assert out["tracked_symbols"] == ["AAPL", "MSFT"]


def test_dispatch_routes_by_gateway_tool_name(market_snapshots, gateway_context):
    _put(
        market_snapshots,
        "INDEX#IXIC",
        {"index": "IXIC", "level": Decimal("20500.5")},
        provider="twelvedata",
        delay="delayed-15m",
    )
    h = _load()
    out = h.lambda_handler({"index": "IXIC"}, gateway_context("get_index_level"))
    assert out["level"] == 20500.5
    assert out["source"] == "live"
