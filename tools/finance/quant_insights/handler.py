"""Gateway target: quant_insights — PRISM model outputs (read-side).

Reads the precomputed results the nightly finance-quant-batch writes. Every
payload carries the PRISM version and an explicit CONFIRMED/HYPOTHESIS grade:
CONFIRMED means the regularity survived FDR control AND out-of-sample
walk-forward validation; everything else is HYPOTHESIS and must be presented
as such. An empty CONFIRMED list is a valid, honest result — especially early,
before enough factor history exists.
"""

from toolkit import tool_error
from toolkit.dispatch import dispatch
from toolkit.dynamo import from_decimal, table


def _read(pk: str) -> tuple[dict | None, dict | None]:
    resp = table("MARKET_SNAPSHOTS_TABLE").get_item(Key={"pk": pk, "sk": "latest"})
    item = resp.get("Item")
    if not item:
        return None, tool_error(
            f"No PRISM results yet for {pk}. The nightly quant batch may not "
            "have run since deployment.",
            pk=pk,
        )
    return from_decimal(item), None


def _envelope(item: dict) -> dict:
    return {
        **item["payload"],
        "source": "model",
        "provider": "prism",
        "fetched_at": item["fetched_at"],
    }


def get_regime_state() -> dict:
    """Current market regime probabilities (risk-on / neutral / stress)."""
    item, err = _read("PRISM#REGIME")
    return err or _envelope(item)


def get_impact_function(shock: str, response: str) -> dict:
    """Estimated response curve of an asset to a 1-sigma shock, with
    credible bands and its validation grade."""
    item, err = _read(f"PRISM#IMPACT#{shock}__{response}")
    if err:
        summary, serr = _read("PRISM#SUMMARY")
        if not serr:
            err["available_pairs"] = summary["payload"].get(
                "impact_pairs", summary.get("impact_pairs", [])
            )
        return err
    return _envelope(item)


def get_confirmed_regularities() -> dict:
    """Only the causal edges that survived FDR + out-of-sample validation.
    An empty list early on is expected and honest."""
    item, err = _read("PRISM#CAUSALITY")
    if err:
        return err
    out = _envelope(item)
    edges = out.get("edges", [])
    out["confirmed"] = [e for e in edges if e.get("grade") == "CONFIRMED"]
    out["hypothesis_count"] = sum(1 for e in edges if e.get("grade") != "CONFIRMED")
    return out


def get_tail_risk(asset: str = "NASDAQCOM") -> dict:
    """EVT-based tail risk (GPD peaks-over-threshold): tail index, VaR/ES
    at 99/99.9%, jump indicator."""
    item, err = _read("PRISM#TAILS")
    if err:
        return err
    out = _envelope(item)
    assets = out.get("assets", {})
    if asset.upper() not in assets:
        return tool_error(
            f"No tail model for {asset!r}", available=sorted(assets)
        )
    return {
        **assets[asset.upper()],
        "asset": asset.upper(),
        "source": "model",
        "provider": "prism",
        "prism_version": out.get("prism_version"),
        "fetched_at": out["fetched_at"],
    }


TOOLS = {
    "get_regime_state": get_regime_state,
    "get_impact_function": get_impact_function,
    "get_confirmed_regularities": get_confirmed_regularities,
    "get_tail_risk": get_tail_risk,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
