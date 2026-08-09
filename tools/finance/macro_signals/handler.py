"""Gateway target: macro_signals — geopolitical factor series + macro data.

Reads the snapshots written by the collector's news/daily jobs. Factor
loadings are news-derived (Haiku-scored headlines): source="derived",
grade="hypothesis" — unvalidated signals until the Phase 3 protocol confirms
a regularity. Macro series (oil, VIX, dollar, breakevens, CPI, gold) are
official provider data and carry the standard live envelope.
"""

from boto3.dynamodb.conditions import Key

from toolkit import tool_error, tool_live
from toolkit.dispatch import dispatch
from toolkit.dynamo import from_decimal, table
from toolkit.factor_taxonomy import FACTORS


def _read(pk: str) -> tuple[dict | None, dict | None]:
    resp = table("MARKET_SNAPSHOTS_TABLE").get_item(Key={"pk": pk, "sk": "latest"})
    item = resp.get("Item")
    if not item:
        return None, tool_error(
            f"No data collected yet for {pk}. "
            "The collector's news/daily job may not have run yet.",
            pk=pk,
        )
    return from_decimal(item), None


def _derived(item: dict) -> dict:
    """Envelope for news-derived factor payloads."""
    return {
        **item["payload"],
        "source": "derived",
        "provider": item["provider"],
        "fetched_at": item["fetched_at"],
    }


def get_factor_snapshot(factor: str = "") -> dict:
    """Latest loading for one factor, or all factors when unspecified."""
    if factor:
        if factor not in FACTORS:
            return tool_error(
                f"Unknown factor: {factor!r}", known_factors=sorted(FACTORS)
            )
        item, err = _read(f"FACTOR#{factor}")
        return err or _derived(item)
    item, err = _read("FACTOR#ALL")
    return err or _derived(item)


def get_factor_history(factor: str, days: int = 30) -> dict:
    """Dated window of a factor's daily loadings (30-day rolling max)."""
    if factor not in FACTORS:
        return tool_error(f"Unknown factor: {factor!r}", known_factors=sorted(FACTORS))
    resp = table("MARKET_SNAPSHOTS_TABLE").query(
        KeyConditionExpression=Key("pk").eq(f"FACTOR#{factor}")
        & Key("sk").begins_with("d#"),
        ScanIndexForward=False,
        Limit=min(int(days), 30),
    )
    items = [from_decimal(i) for i in resp.get("Items", [])]
    if not items:
        return tool_error(f"No history yet for factor {factor}", factor=factor)
    return {
        "factor": factor,
        "label": FACTORS[factor][0],
        "series": [
            {
                "date": i["sk"][2:],
                "loading": i["payload"].get("loading"),
                "event_count": i["payload"].get("event_count"),
            }
            for i in items
        ],
        "source": "derived",
        "grade": "hypothesis",
    }


def get_news_hotspots() -> dict:
    """Factors ranked by |loading|*log(events) with their top headlines."""
    item, err = _read("FACTOR#ALL")
    if err:
        return err
    import math

    factors = item["payload"].get("factors", {})
    ranked = sorted(
        factors.values(),
        key=lambda f: abs(f.get("loading", 0)) * math.log1p(f.get("event_count", 0)),
        reverse=True,
    )
    return {
        "hotspots": ranked[:6],
        "taxonomy_version": item["payload"].get("taxonomy_version"),
        "source": "derived",
        "grade": "hypothesis",
        "provider": item["provider"],
        "fetched_at": item["fetched_at"],
    }


def get_macro_series(series: str = "") -> dict:
    """Official macro data: oil/VIX/dollar/breakevens/CPI (FRED) + gold."""
    if series.upper() in ("XAUUSD", "GOLD", "XAU/USD"):
        item, err = _read("GOLD#XAUUSD")
    elif series:
        item, err = _read(f"MACRO#{series.upper()}")
    else:
        item, err = _read("MACRO#ALL")
    if err:
        return err
    return tool_live(
        item["payload"],
        provider=item["provider"],
        fetched_at=item["fetched_at"],
        delay=item["delay"],
    )


TOOLS = {
    "get_factor_snapshot": get_factor_snapshot,
    "get_factor_history": get_factor_history,
    "get_news_hotspots": get_news_hotspots,
    "get_macro_series": get_macro_series,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
