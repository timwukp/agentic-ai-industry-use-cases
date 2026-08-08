"""News collection + factor scoring (Phase 2 signal layer).

Pipeline, run daily after US close:
  1. Fetch headlines: Finnhub general+company news (official API) and one
     narrow GDELT 2.0 DOC query per factor (free, keyless, machine-coded —
     capped and deduped because volume/noise is GDELT's known weakness).
  2. Dedup by URL and normalized title.
  3. Score in batches with Bedrock Haiku: per-headline factor loadings in
     [-1, +1] + confidence. Haiku not the harness: schedulable, ~30x cheaper,
     and scoring must not consume the interactive agent's quota.
  4. Aggregate to a daily factor time series (confidence-weighted mean,
     event count) -> DynamoDB FACTOR#<id> snapshots + S3 market/factors lake.

Every derived payload carries grade="hypothesis": a news-derived loading is
an unvalidated signal until Phase 3's out-of-sample protocol confirms it.
"""

import json
import urllib.error
import urllib.parse
from datetime import datetime, timezone

import boto3

from toolkit.factor_taxonomy import FACTORS, TAXONOMY_VERSION

SCORING_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
BATCH_SIZE = 40
MAX_HEADLINES = 400
GDELT_PER_FACTOR = 15
FINNHUB_GENERAL_CAP = 120

_bedrock = None


def _bedrock_client():
    global _bedrock
    if _bedrock is None:
        _bedrock = boto3.client("bedrock-runtime")
    return _bedrock


def _norm_title(title: str) -> str:
    return " ".join(title.lower().split())[:120]


def collect_headlines(http_json, api_key) -> list[dict]:
    """Fetch + dedup headlines from Finnhub and GDELT. Returns
    [{title, source, url, published, origin}]."""
    headlines, seen_urls, seen_titles = [], set(), set()

    def add(title, source, url, published, origin):
        if not title or len(title) < 20:  # GDELT stubs / nav fragments
            return
        key_t = _norm_title(title)
        if url in seen_urls or key_t in seen_titles:
            return
        seen_urls.add(url)
        seen_titles.add(key_t)
        headlines.append(
            {
                "title": title.strip(),
                "source": source,
                "url": url,
                "published": published,
                "origin": origin,
            }
        )

    # Finnhub general market news
    try:
        items = http_json(
            "https://finnhub.io/api/v1/news?"
            + urllib.parse.urlencode(
                {"category": "general", "token": api_key("finnhub-api-key")}
            )
        )
        for it in items[:FINNHUB_GENERAL_CAP]:
            add(
                it.get("headline", ""),
                it.get("source", "finnhub"),
                it.get("url", f"finnhub:{it.get('id')}"),
                datetime.fromtimestamp(it.get("datetime", 0), tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "finnhub-general",
            )
    except (urllib.error.URLError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"news_source_failed": f"finnhub-general: {exc}"}))

    # GDELT: one narrow query per factor, English, last 24h, top by relevance
    for factor_id, (_, _, query) in FACTORS.items():
        try:
            data = http_json(
                "https://api.gdeltproject.org/api/v2/doc/doc?"
                + urllib.parse.urlencode(
                    {
                        "query": f"{query} sourcelang:english",
                        "mode": "artlist",
                        "maxrecords": str(GDELT_PER_FACTOR),
                        "timespan": "24h",
                        "format": "json",
                        "sort": "hybridrel",
                    }
                )
            )
            for art in data.get("articles", []):
                add(
                    art.get("title", ""),
                    art.get("domain", "gdelt"),
                    art.get("url", ""),
                    art.get("seendate", ""),
                    f"gdelt:{factor_id}",
                )
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            print(json.dumps({"news_source_failed": f"gdelt:{factor_id}: {exc}"}))

    return headlines[:MAX_HEADLINES]


def _scoring_prompt(batch: list[dict]) -> str:
    factor_lines = "\n".join(
        f"- {fid}: {desc}" for fid, (_, desc, _) in FACTORS.items()
    )
    headline_lines = "\n".join(
        f'{i}. [{h["source"]}] {h["title"]}' for i, h in enumerate(batch)
    )
    return f"""You are scoring news headlines against a fixed taxonomy of market factors.

FACTORS:
{factor_lines}

For each headline, identify which factors it bears on (usually 0-3; most
headlines are irrelevant to most factors). For each relevant factor give a
loading in [-1, +1]:
  +1 = strongly positive for that factor's intensity/risk (e.g. war escalation
       => war-conflict +0.8; supply disruption => energy-supply +0.7)
  -1 = strongly negative/de-escalating (ceasefire => war-conflict -0.6)
and a confidence in [0, 1]. Omit factors the headline doesn't clearly touch.
Judge only from the headline text; no outside knowledge of outcomes.

HEADLINES:
{headline_lines}

Reply with ONLY a JSON array, one object per headline, same order:
[{{"idx": 0, "factors": {{"factor-id": {{"loading": 0.5, "confidence": 0.8}}}}}}, ...]
Headlines with no relevant factors get "factors": {{}}."""


def score_batch(batch: list[dict]) -> list[dict]:
    """One Haiku call scoring up to BATCH_SIZE headlines. Returns parsed list;
    raises on malformed output (caller isolates per-batch failures)."""
    resp = _bedrock_client().converse(
        modelId=SCORING_MODEL,
        messages=[{"role": "user", "content": [{"text": _scoring_prompt(batch)}]}],
        inferenceConfig={"maxTokens": 4000, "temperature": 0.0},
    )
    text = resp["output"]["message"]["content"][0]["text"].strip()
    if text.startswith("```"):
        text = text.split("```")[1].lstrip("json\n")
    parsed = json.loads(text)
    if not isinstance(parsed, list):
        raise ValueError("scoring output is not a JSON array")
    return parsed


def aggregate(scored: list[dict], headlines: list[dict]) -> dict:
    """Confidence-weighted daily aggregation per factor."""
    acc = {fid: {"wsum": 0.0, "conf": 0.0, "n": 0, "top": []} for fid in FACTORS}
    for row in scored:
        idx = row.get("idx")
        if not isinstance(idx, int) or not 0 <= idx < len(headlines):
            continue
        for fid, sc in (row.get("factors") or {}).items():
            if fid not in acc:
                continue
            try:
                loading = max(-1.0, min(1.0, float(sc["loading"])))
                conf = max(0.0, min(1.0, float(sc["confidence"])))
            except (KeyError, TypeError, ValueError):
                continue
            a = acc[fid]
            a["wsum"] += loading * conf
            a["conf"] += conf
            a["n"] += 1
            if conf >= 0.6 and len(a["top"]) < 3:
                a["top"].append(headlines[idx]["title"][:140])
    out = {}
    for fid, a in acc.items():
        out[fid] = {
            "factor": fid,
            "label": FACTORS[fid][0],
            "loading": round(a["wsum"] / a["conf"], 4) if a["conf"] else 0.0,
            "event_count": a["n"],
            "top_headlines": a["top"],
        }
    return out


def run_news_job(http_json, api_key, snapshot, lake_append, today, now_iso) -> dict:
    """Entry point wired into the collector's JOBS map."""
    headlines = collect_headlines(http_json, api_key)
    if not headlines:
        return {"ok": 0, "failed": ["no headlines collected"]}

    scored, failed = [], []
    for i in range(0, len(headlines), BATCH_SIZE):
        batch = headlines[i : i + BATCH_SIZE]
        try:
            rows = score_batch(batch)
            for r in rows:  # re-base batch-local idx to global
                if isinstance(r.get("idx"), int):
                    r["idx"] += i
            scored.extend(rows)
        except Exception as exc:  # noqa: BLE001 — batch isolation
            failed.append(f"batch@{i}: {type(exc).__name__}: {exc}")

    factors = aggregate(scored, headlines)
    meta = {
        "taxonomy_version": TAXONOMY_VERSION,
        "scoring_model": SCORING_MODEL,
        "headline_count": len(headlines),
        "scored_count": len(scored),
        "grade": "hypothesis",
    }
    for fid, f in factors.items():
        snapshot(f"FACTOR#{fid}", {**f, **meta}, "derived", "daily")
    snapshot("FACTOR#ALL", {"factors": factors, **meta}, "derived", "daily")

    day = today()
    lake_append(
        "factors",
        [{**f, **meta, "date": day, "fetched_at": now_iso()} for f in factors.values()],
    )
    lake_append(
        "headlines",
        [{**h, "date": day} for h in headlines],
    )
    return {"ok": len(factors), "failed": failed, "headlines": len(headlines)}
