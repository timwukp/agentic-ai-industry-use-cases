"""Phase 2: news job (dedup, scoring parse, aggregation) + macro_signals tools.

Bedrock and HTTP are stubbed; fixture numbers avoid bare 9-digit runs (PII CI).
"""

import importlib
import sys
from decimal import Decimal
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load_news():
    sys.path.insert(0, str(REPO / "tools" / "finance" / "market_collector"))
    try:
        import news_job

        return importlib.reload(news_job)
    finally:
        sys.path.pop(0)


def _load_signals():
    sys.path.insert(0, str(REPO / "tools" / "finance" / "macro_signals"))
    try:
        import handler

        return importlib.reload(handler)
    finally:
        sys.path.pop(0)


# ---------------- news_job: collection & dedup ----------------


def test_collect_headlines_dedups_by_url_and_title():
    nj = _load_news()

    def fake_http(url):
        if "finnhub.io" in url:
            return [
                {
                    "headline": "OPEC announces surprise production cut of two million barrels",
                    "source": "reuters",
                    "url": "https://x.com/1",
                    "datetime": 1754700000,
                },
                {
                    "headline": "OPEC announces surprise production cut of two million barrels",
                    "source": "ap",
                    "url": "https://x.com/2",
                    "datetime": 1754700000,
                },  # dup title
                {
                    "headline": "Fed holds rates steady, signals patience on cuts",
                    "source": "wsj",
                    "url": "https://x.com/1",
                    "datetime": 1754700000,
                },  # dup url
                {
                    "headline": "short",
                    "source": "x",
                    "url": "https://x.com/4",
                    "datetime": 1754700000,
                },  # too short
            ]
        return {"articles": []}  # GDELT empty

    out = nj.collect_headlines(fake_http, lambda name: "k")
    assert len(out) == 1
    assert out[0]["title"].startswith("OPEC announces")


def test_collect_headlines_survives_source_failure():
    nj = _load_news()

    def fake_http(url):
        if "finnhub.io" in url:
            raise ValueError("finnhub down")
        return {
            "articles": [
                {
                    "title": "Red Sea shipping attacks force carriers to reroute around Africa",
                    "domain": "bbc.com",
                    "url": "https://b.com/1",
                    "seendate": "20260809T000000Z",
                }
            ]
        }

    out = nj.collect_headlines(fake_http, lambda name: "k")
    # GDELT queries still ran (one per factor); dedup collapses same URL
    assert len(out) == 1
    assert out[0]["origin"].startswith("gdelt:")


# ---------------- news_job: aggregation math ----------------


def test_aggregate_confidence_weighted_mean():
    nj = _load_news()
    headlines = [
        {"title": "War escalates near major oil terminal"},
        {"title": "Ceasefire talks make progress"},
    ]
    scored = [
        {"idx": 0, "factors": {"war-conflict": {"loading": 0.8, "confidence": 1.0}}},
        {"idx": 1, "factors": {"war-conflict": {"loading": -0.4, "confidence": 0.5}}},
    ]
    out = nj.aggregate(scored, headlines)
    wc = out["war-conflict"]
    # (0.8*1.0 + -0.4*0.5) / (1.0+0.5) = 0.6/1.5 = 0.4
    assert wc["loading"] == pytest.approx(0.4)
    assert wc["event_count"] == 2
    # factors with no events report loading 0, count 0 — not missing keys
    assert out["rare-earths"]["event_count"] == 0
    assert out["rare-earths"]["loading"] == 0.0


def test_aggregate_clamps_out_of_range_and_ignores_garbage():
    nj = _load_news()
    headlines = [{"title": "Chip export controls tightened again this quarter"}]
    scored = [
        {"idx": 0, "factors": {"semiconductors": {"loading": 5.0, "confidence": 2.0}}},
        {
            "idx": 99,
            "factors": {"semiconductors": {"loading": 1, "confidence": 1}},
        },  # bad idx
        {"idx": 0, "factors": {"not-a-factor": {"loading": 1, "confidence": 1}}},
        {"idx": 0, "factors": {"us-china": "garbage"}},
    ]
    out = nj.aggregate(scored, headlines)
    assert out["semiconductors"]["loading"] == 1.0  # clamped
    assert out["us-china"]["event_count"] == 0


def test_score_batch_parses_fenced_json(monkeypatch):
    nj = _load_news()

    class FakeBedrock:
        def converse(self, **kw):
            body = '```json\n[{"idx": 0, "factors": {}}]\n```'
            return {"output": {"message": {"content": [{"text": body}]}}}

    monkeypatch.setattr(nj, "_bedrock_client", lambda: FakeBedrock())
    out = nj.score_batch([{"title": "x", "source": "s"}])
    assert out == [{"idx": 0, "factors": {}}]


def test_run_news_job_isolates_batch_failures(monkeypatch):
    nj = _load_news()
    headlines = [
        {
            "title": f"Distinct headline number {i} about oil supply and shipping",
            "source": "s",
            "url": f"https://u/{i}",
            "published": "",
            "origin": "finnhub-general",
        }
        for i in range(nj.BATCH_SIZE + 1)  # forces 2 batches
    ]
    monkeypatch.setattr(nj, "collect_headlines", lambda h, a: headlines)
    calls = {"n": 0}

    def flaky_score(batch):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("model returned prose")
        return [
            {
                "idx": 0,
                "factors": {"energy-supply": {"loading": 0.5, "confidence": 1.0}},
            }
        ]

    monkeypatch.setattr(nj, "score_batch", flaky_score)
    written = {}
    out = nj.run_news_job(
        http_json=None,
        api_key=None,
        snapshot=lambda pk, payload, prov, delay: written.setdefault(pk, payload),
        lake_append=lambda ds, rows: None,
        today=lambda: "2026-08-09",
        now_iso=lambda: "2026-08-09T00:00:00Z",
    )
    assert len(out["failed"]) == 1  # first batch failed, second survived
    assert "FACTOR#ALL" in written
    assert written["FACTOR#ALL"]["grade"] == "hypothesis"
    # second batch's idx was re-based past the first batch
    assert written["FACTOR#energy-supply"]["event_count"] == 1


# ---------------- macro_signals tools ----------------


def _seed_factor_all(tbl):
    tbl.put_item(
        Item={
            "pk": "FACTOR#ALL",
            "sk": "latest",
            "payload": {
                "factors": {
                    "war-conflict": {
                        "factor": "war-conflict",
                        "label": "War & Conflict",
                        "loading": Decimal("0.7"),
                        "event_count": 12,
                        "top_headlines": ["a"],
                    },
                    "fed-policy": {
                        "factor": "fed-policy",
                        "label": "Fed Policy",
                        "loading": Decimal("-0.2"),
                        "event_count": 3,
                        "top_headlines": [],
                    },
                },
                "taxonomy_version": "test",
                "grade": "hypothesis",
            },
            "provider": "derived",
            "fetched_at": "2026-08-09T00:00:00Z",
            "delay": "daily",
        }
    )


def test_factor_snapshot_carries_derived_grade(market_snapshots):
    _seed_factor_all(market_snapshots)
    h = _load_signals()
    out = h.get_factor_snapshot()
    assert out["source"] == "derived"
    assert out["grade"] == "hypothesis"
    assert out["factors"]["war-conflict"]["loading"] == 0.7


def test_unknown_factor_rejected_with_taxonomy(market_snapshots):
    h = _load_signals()
    out = h.get_factor_snapshot("oil-stuff")
    assert "error" in out and "war-conflict" in out["known_factors"]


def test_hotspots_ranked_by_intensity(market_snapshots):
    _seed_factor_all(market_snapshots)
    h = _load_signals()
    out = h.get_news_hotspots()
    assert out["hotspots"][0]["factor"] == "war-conflict"  # 0.7*log(13) > 0.2*log(4)
    assert out["grade"] == "hypothesis"


def test_macro_series_uses_live_envelope(market_snapshots):
    market_snapshots.put_item(
        Item={
            "pk": "GOLD#XAUUSD",
            "sk": "latest",
            "payload": {"series": "XAUUSD", "value": Decimal("4342.35")},
            "provider": "twelvedata",
            "fetched_at": "2026-08-09T00:00:00Z",
            "delay": "delayed-15m",
        }
    )
    h = _load_signals()
    out = h.get_macro_series("gold")
    assert out["source"] == "live"  # official data, not derived
    assert out["value"] == 4342.35
