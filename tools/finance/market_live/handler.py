"""Gateway target: market_live — real US market data (read-side).

Reads the DynamoDB snapshots written by the scheduled market_collector; never
calls the upstream providers itself. Every payload carries the live-provenance
envelope (source/provider/fetched_at/delay) and an honest "stale": true flag
when the snapshot is older than twice its expected refresh cadence.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from toolkit import tool_error, tool_live
from toolkit.dispatch import dispatch
from toolkit.dynamo import from_decimal, table

# pk-class → max acceptable snapshot age (seconds) before we flag stale.
# Intraday classes (QUOTE/INDEX) collect every 15 min but ONLY during market
# hours — so 2× cadence applies only while the market is open. Off-hours the
# Friday close IS the freshest data that can exist; flagging it stale would be
# dishonest the other way. MAX_AGE is the off-hours backstop: longer than the
# longest normal gap (Fri 16:00 → Mon 09:30 ET ≈ 2.7 days), so a collector
# that silently dies still surfaces as stale within a couple of sessions.
STALE_AFTER = {
    "QUOTE": 30 * 60,
    "INDEX": 30 * 60,
    "TREASURY": 2 * 86400,
    "RATES": 2 * 86400,
    "FUNDAMENTALS": 2 * 86400,
}
INTRADAY = ("QUOTE", "INDEX")
MAX_AGE_INTRADAY = int(3.5 * 86400)

NYSE = ZoneInfo("America/New_York")


def _market_open(now_utc: datetime) -> bool:
    """US cash session approximation: Mon–Fri 09:30–16:00 ET (ignores holidays;
    a holiday misclassified as open just makes the stale check stricter)."""
    et = now_utc.astimezone(NYSE)
    if et.weekday() >= 5:
        return False
    minutes = et.hour * 60 + et.minute
    return 9 * 60 + 30 <= minutes < 16 * 60


def _read(pk: str) -> tuple[dict | None, dict | None]:
    """Return (item, error_payload)."""
    resp = table("MARKET_SNAPSHOTS_TABLE").get_item(Key={"pk": pk, "sk": "latest"})
    item = resp.get("Item")
    if not item:
        return None, tool_error(
            f"No data collected yet for {pk}. "
            "The market collector may not have run for this entity.",
            pk=pk,
        )
    return from_decimal(item), None


def _envelope(item: dict) -> dict:
    payload = dict(item["payload"])
    pk_class = item["pk"].split("#")[0]
    age_limit = STALE_AFTER.get(pk_class, 2 * 86400)
    now = datetime.now(timezone.utc)
    if pk_class in INTRADAY and not _market_open(now):
        age_limit = MAX_AGE_INTRADAY
    fetched = datetime.strptime(item["fetched_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    if (now - fetched).total_seconds() > age_limit:
        payload["stale"] = True
    return tool_live(
        payload,
        provider=item["provider"],
        fetched_at=item["fetched_at"],
        delay=item["delay"],
    )


def get_live_quote(symbol: str) -> dict:
    item, err = _read(f"QUOTE#{symbol.upper()}")
    if err:
        tracked, terr = _read("META#TRACKED")
        if not terr:
            err["tracked_symbols"] = tracked["payload"]["symbols"]
        return err
    return _envelope(item)


def get_index_level(index: str = "QQQ") -> dict:
    item, err = _read(f"INDEX#{index.upper()}")
    return err or _envelope(item)


def get_treasury_yields() -> dict:
    item, err = _read("TREASURY#CURVE")
    if err:
        return err
    out = _envelope(item)
    curve = out.get("curve", {})
    y10 = curve.get("DGS10", {}).get("value")
    y2 = curve.get("DGS2", {}).get("value")
    if y10 is not None and y2 is not None:
        spread = round(y10 - y2, 2)
        out["spread_10y_2y"] = spread
        out["curve_inverted"] = spread < 0
    return out


def get_policy_rates() -> dict:
    item, err = _read("RATES#POLICY")
    return err or _envelope(item)


def get_fundamentals(symbol: str) -> dict:
    item, err = _read(f"FUNDAMENTALS#{symbol.upper()}")
    return err or _envelope(item)


def list_tracked_symbols() -> dict:
    item, err = _read("META#TRACKED")
    if err:
        return err
    return tool_live(
        {"symbols": item["payload"]["symbols"]},
        provider="config",
        fetched_at=item["fetched_at"],
        delay="static",
    )


TOOLS = {
    "get_live_quote": get_live_quote,
    "get_index_level": get_index_level,
    "get_treasury_yields": get_treasury_yields,
    "get_policy_rates": get_policy_rates,
    "get_fundamentals": get_fundamentals,
    "list_tracked_symbols": list_tracked_symbols,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
