"""GDELT 1.0 aggregate -> factor proxy panel via the frozen CAMEO map.

Consumes the output of research/fetch_gdelt.sql (daily aggregates by root
code x actor pair) and produces one daily series per mappable factor:
goldstein-based intensity (sign-flipped so higher = more conflictual),
z-scored within a trailing year for spike detection.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cameo_map import CAMEO_FACTORS  # noqa: E402


def _match(df: pd.DataFrame, spec: dict) -> pd.Series:
    m = pd.Series(True, index=df.index)
    if spec["root_codes"] is not None:
        m &= df["root_code"].astype(str).str.zfill(2).isin(spec["root_codes"])
    af = spec["actor_filter"]
    if af is not None:
        a1, a2 = af
        if isinstance(a1, list):
            m &= df["actor1"].isin(a1) | df["actor2"].isin(a1)
        elif a1 == "USAGOV":
            m &= df["actor1"].astype(str).str.startswith("USA")
        elif a1 is not None and a2 is not None:
            m &= (
                df["actor1"].astype(str).str.startswith(a1)
                & df["actor2"].astype(str).str.startswith(a2)
            ) | (
                df["actor1"].astype(str).str.startswith(a2)
                & df["actor2"].astype(str).str.startswith(a1)
            )
        elif a1 is not None:
            m &= df["actor1"].astype(str).str.startswith(a1)
    return m


def factor_proxy_panel(agg: pd.DataFrame) -> pd.DataFrame:
    """agg columns: date, root_code, actor1, actor2, n_events,
    sum_goldstein, sum_tone. Returns date x factor intensity panel."""
    agg = agg.copy()
    agg["date"] = pd.to_datetime(agg["date"])
    out = {}
    for factor, spec in CAMEO_FACTORS.items():
        sub = agg[_match(agg, spec)]
        if sub.empty:
            continue
        daily = sub.groupby("date").agg(
            n=("n_events", "sum"), g=("sum_goldstein", "sum")
        )
        # intensity: event-weighted mean Goldstein, sign flipped (conflict
        # is negative on the Goldstein scale; our loadings treat higher =
        # more intense), volume-damped by log1p(n)
        mean_g = daily["g"] / daily["n"].clip(lower=1)
        out[factor] = (-mean_g) * np.log1p(daily["n"])
    if not out:
        return pd.DataFrame()
    panel = pd.DataFrame(out)
    bdays = pd.bdate_range(panel.index.min(), panel.index.max())
    return panel.reindex(bdays).fillna(0.0)


def spike_flags(series: pd.Series, window: int = 250, z: float = 2.0) -> pd.Series:
    """>zσ spikes vs trailing-window mean/std (shifted 1 day: no same-day
    leakage into the baseline)."""
    mu = series.rolling(window).mean().shift(1)
    sd = series.rolling(window).std().shift(1)
    return (series - mu) > z * sd.replace(0, np.nan)
