"""Nightly PRISM batch: lake -> models -> DynamoDB/S3 results.

All math lives in prism/ (pure functions); this file is the only AWS-aware
layer. Results are graded via the validation protocol; NaN/inf are stripped
before writing (DynamoDB rejects them, and a payload that silently drops a
number is worse than one that says null).
"""

import gzip
import io
import json
import os
from datetime import datetime, timezone
from decimal import Decimal

import boto3

from prism import (
    PRISM_VERSION,
    build_panel,
    causality_scan,
    confirm,
    factor_series,
    fit_gpd_by_regime,
    fit_gpd_pot,
    fit_vol_filtered_var,
    bipower_jump_stat,
    fit_regimes,
    local_projection,
    to_returns,
    walk_forward,
)

LOG_COLS = ["NASDAQCOM", "DCOILWTICO", "DTWEXBGS", "DCOILBRENTEU"]
DIFF_COLS = ["DGS10", "DGS2", "VIXCLS", "T10YIE", "DFF"]
REGIME_COLS = [
    "NASDAQCOM_ret",
    "slope_diff",
    "VIXCLS_diff",
    "DCOILWTICO_ret",
    "DTWEXBGS_ret",
]
MARKET_SOURCES = ["DCOILWTICO_ret", "VIXCLS_diff", "DTWEXBGS_ret"]
TARGETS = ["NASDAQCOM_ret", "DGS10_diff"]
FACTOR_MIN_DAYS = 60
# always publish these headline pairs even if not significant (grade applies)
ALWAYS_IMPACT = [("DCOILWTICO_ret", "DGS10_diff"), ("VIXCLS_diff", "NASDAQCOM_ret")]

_s3 = boto3.client("s3")
_ddb = boto3.resource("dynamodb")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _json_safe(obj):
    """NaN/inf -> None recursively (DynamoDB + honest payloads)."""
    if isinstance(obj, float):
        return None if (obj != obj or obj in (float("inf"), float("-inf"))) else obj
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


def _to_decimal(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_decimal(v) for v in obj]
    return obj


def _write(pk: str, payload: dict) -> None:
    tbl = _ddb.Table(os.environ["MARKET_SNAPSHOTS_TABLE"])
    payload = _json_safe({**payload, "prism_version": PRISM_VERSION})
    tbl.put_item(
        Item={
            "pk": pk,
            "sk": "latest",
            "payload": _to_decimal(payload),
            "provider": "prism",
            "fetched_at": _now_iso(),
            "delay": "nightly",
        }
    )


def _read_history() -> dict[str, list[dict]]:
    bucket = os.environ["MARKET_LAKE_BUCKET"]
    out = {}
    resp = _s3.list_objects_v2(Bucket=bucket, Prefix="market/history/")
    for obj in resp.get("Contents", []):
        sid = obj["Key"].rsplit("/", 1)[-1].replace(".jsonl.gz", "")
        body = _s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
        out[sid] = [json.loads(line) for line in gzip.decompress(body).splitlines()]
    return out


def _read_factors() -> list[dict]:
    bucket = os.environ["MARKET_LAKE_BUCKET"]
    rows = []
    token = None
    while True:
        kw = {"Bucket": bucket, "Prefix": "market/factors/"}
        if token:
            kw["ContinuationToken"] = token
        resp = _s3.list_objects_v2(**kw)
        for obj in resp.get("Contents", []):
            body = _s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            rows.extend(json.loads(x) for x in gzip.decompress(body).splitlines())
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")
    return rows


def _compact_month() -> str:
    """JSONL -> Parquet for the current month's dt-partitioned datasets."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    bucket = os.environ["MARKET_LAKE_BUCKET"]
    yyyymm = _today()[:7].replace("-", "")
    for dataset in ("quotes", "fred_daily", "indices", "factors"):
        rows = []
        resp = _s3.list_objects_v2(
            Bucket=bucket, Prefix=f"market/{dataset}/dt={_today()[:7]}"
        )
        for obj in resp.get("Contents", []):
            body = _s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            rows.extend(json.loads(x) for x in gzip.decompress(body).splitlines())
        if not rows:
            continue
        table = pa.Table.from_pylist(rows)
        buf = io.BytesIO()
        pq.write_table(table, buf)
        _s3.put_object(
            Bucket=bucket,
            Key=f"market/parquet/{dataset}/{yyyymm}.parquet",
            Body=buf.getvalue(),
        )
    return "ok"


PANEL_SERIES = set(LOG_COLS + DIFF_COLS) | {"DGS2"}


def lambda_handler(event, context):
    history = _read_history()
    # Daily series only: a monthly series (CPIAUCSL) in the panel would NaN
    # out ~80% of rows after the 5-day ffill cap, and build_panel's dropna
    # would silently shrink 10 years to ~400 rows (observed on first run).
    history = {k: v for k, v in history.items() if k in PANEL_SERIES}
    panel_raw = build_panel(history)
    rets = to_returns(panel_raw, LOG_COLS, DIFF_COLS)
    rets["slope_diff"] = (
        (panel_raw["DGS10"] - panel_raw["DGS2"]).diff().reindex(rets.index)
    )
    rets = rets.dropna()

    # ---- regimes ----
    regime = fit_regimes(rets[[c for c in REGIME_COLS if c in rets]], n_states=3)
    _write("PRISM#REGIME", regime.to_payload())

    # ---- causality (market drivers; factors only once enough history) ----
    sources = list(MARKET_SOURCES)
    factor_note = None
    frows = _read_factors()
    fs = factor_series(frows)
    if len(fs) >= FACTOR_MIN_DAYS:
        joined = rets.join(fs, how="left")
        for col in fs.columns:
            if joined[col].notna().sum() >= FACTOR_MIN_DAYS:
                sources.append(col)
        rets = joined
    else:
        factor_note = {
            "factor_causality": "insufficient_data",
            "days_available": int(len(fs)),
            "days_needed": FACTOR_MIN_DAYS,
        }

    scan = causality_scan(rets, sources, TARGETS)

    # ---- impacts + walk-forward grading ----
    pairs = {(r["source"], r["target"]) for _, r in scan.iterrows() if r["significant"]}
    pairs.update(ALWAYS_IMPACT)
    impact_pairs = []
    edges = scan.to_dict("records")
    wf_cache = {}
    for shock, response in sorted(pairs):
        if shock not in rets or response not in rets:
            continue
        wf = walk_forward(rets[[shock, response]].dropna(), shock, response)
        wf_cache[(shock, response)] = wf
        imp = local_projection(rets, shock, response)
        best_row = min(
            (e for e in edges if e["source"] == shock and e["target"] == response),
            key=lambda e: e["q_value"] if e["q_value"] is not None else 2.0,
            default={},
        )
        imp.grade = confirm(best_row, wf)
        _write(f"PRISM#IMPACT#{shock}__{response}", imp.to_payload())
        impact_pairs.append(f"{shock}__{response}")

    for e in edges:
        wf = wf_cache.get((e["source"], e["target"]))
        e["grade"] = confirm(e, wf) if wf is not None else "HYPOTHESIS"
    causality_payload = {"edges": edges}
    if factor_note:
        causality_payload.update(factor_note)
    _write("PRISM#CAUSALITY", causality_payload)

    # ---- tails: unconditional VaR stays the headline. Per-regime tails
    # are DESCRIPTIVE ONLY: the validation addendum's back-test showed
    # conditioning VaR on the (lagged) estimated regime WORSENS calibration
    # — the H1b detection lag compounds at regime transitions, exactly when
    # violations strike. What survives is the descriptive claim "the
    # stress-regime tail is fatter", which the synthetic test proves the
    # fit recovers correctly. ----
    current_state = regime.to_payload()["current_state"]
    tails = {}
    for asset, col in (("NASDAQCOM", "NASDAQCOM_ret"), ("DGS10", "DGS10_diff")):
        tr = fit_gpd_pot(rets[col])
        jumps = bipower_jump_stat(rets[col])
        by_regime = fit_gpd_by_regime(rets[col], regime.state_probs)
        vol_var = fit_vol_filtered_var(rets[col])
        tails[asset] = {
            **tr.to_payload(),
            # headline forward-looking VaR: the only variant that PASSED the
            # point-in-time calibration back-test (green Kupiec/CC/Basel)
            "calibrated": vol_var,
            "jump_stat": (
                round(float(jumps.dropna().iloc[-1]), 4)
                if jumps.notna().any()
                else None
            ),
            "by_regime": {state: res.to_payload() for state, res in by_regime.items()},
            "by_regime_note": (
                "descriptive only — regime-conditional VaR back-tested WORSE "
                "than unconditional (validation addendum); use for tail-shape "
                "context, not risk limits"
            ),
            "unconditional_note": (
                "long-run tail shape; for tomorrow's risk level prefer "
                "'calibrated' (vol-filtered, back-tested green)"
            ),
            "current_regime": current_state,
        }
    _write("PRISM#TAILS", {"assets": tails})

    confirmed_n = sum(1 for e in edges if e.get("grade") == "CONFIRMED")
    summary = {
        "regime": regime.to_payload()["current_state"],
        "causality": {
            "n_tested": len(edges),
            "n_significant": int(scan["significant"].sum()) if len(scan) else 0,
        },
        "impact_pairs": impact_pairs,
        "confirmed": confirmed_n,
        "panel_rows": int(len(rets)),
        **({"factor_note": factor_note} if factor_note else {}),
    }
    _write("PRISM#SUMMARY", summary)

    # lake copy of everything, one JSONL per nightly run
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        for name, payload in (
            ("regime", regime.to_payload()),
            ("causality", causality_payload),
            ("tails", {"assets": tails}),
            ("summary", summary),
        ):
            gz.write(
                (json.dumps(_json_safe({"result": name, **payload})) + "\n").encode()
            )
    _s3.put_object(
        Bucket=os.environ["MARKET_LAKE_BUCKET"],
        Key=f"market/prism/dt={_today()}/results.jsonl.gz",
        Body=buf.getvalue(),
    )

    try:
        compaction = _compact_month()
    except Exception as exc:  # noqa: BLE001 — compaction must not sink PRISM
        compaction = f"error: {type(exc).__name__}: {exc}"

    result = {**summary, "compaction": compaction}
    print(json.dumps(_json_safe(result)))
    return _json_safe(result)
