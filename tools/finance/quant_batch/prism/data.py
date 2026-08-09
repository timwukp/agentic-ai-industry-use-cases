"""Panel construction from lake JSONL rows. Pure pandas, no AWS."""

import pandas as pd


def build_panel(series: dict[str, list[dict]]) -> pd.DataFrame:
    """{series_id: [{date, value}, ...]} -> business-day panel.

    Forward-fill is capped at 5 days: enough to bridge holidays/weekends in
    mixed-frequency FRED data, short enough that a stale monthly series
    cannot masquerade as daily variation.
    """
    cols = {}
    for sid, rows in series.items():
        if not rows:
            continue
        s = pd.Series(
            [r["value"] for r in rows],
            index=pd.to_datetime([r["date"] for r in rows]),
            name=sid,
        )
        cols[sid] = s[~s.index.duplicated(keep="last")].sort_index()
    if not cols:
        return pd.DataFrame()
    panel = pd.DataFrame(cols)
    bdays = pd.bdate_range(panel.index.min(), panel.index.max())
    panel = panel.reindex(bdays).ffill(limit=5).dropna()
    panel.index.name = "date"
    return panel


def to_returns(
    panel: pd.DataFrame, log_cols: list[str], diff_cols: list[str]
) -> pd.DataFrame:
    """Log-returns for prices, first differences for yields/levels."""
    import numpy as np

    out = {}
    for c in log_cols:
        if c in panel:
            out[f"{c}_ret"] = np.log(panel[c]).diff()
    for c in diff_cols:
        if c in panel:
            out[f"{c}_diff"] = panel[c].diff()
    return pd.DataFrame(out).dropna()


def factor_series(rows: list[dict]) -> pd.DataFrame:
    """Daily factor loadings [{date, factor, loading, ...}] -> wide frame.

    Early on this is only a few days — callers must gate on len(), and this
    function must simply return whatever exists without complaint.
    """
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    if not {"date", "factor", "loading"}.issubset(df.columns):
        return pd.DataFrame()
    df["date"] = pd.to_datetime(df["date"])
    wide = df.pivot_table(index="date", columns="factor", values="loading")
    wide.index.name = "date"
    return wide.sort_index()
