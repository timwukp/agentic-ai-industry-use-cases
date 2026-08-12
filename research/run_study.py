"""PRISM historical validation study — main orchestrator.

Executes the pre-registered protocol (research/protocol.md, frozen at tag
`study-preregistered`) over the cohorts in §2 and hypotheses H1–H8 in §3.
PRISM is imported LIVE from tools/finance/quant_batch (sys.path below), so
re-runs use the estimator as of the current checkout, not as of the tag:
the sealed C10–C40 results and report.md were generated under the pre-
2026-08-12 NIG prior (see findings_addendum "H3 root cause"); band-gate
verdicts from re-runs after that fix are NOT comparable with the sealed
artifacts. Point-in-time machinery (data discipline) lives in studylib.

Usage:
    .venv/bin/python research/run_study.py [--cohort C36] [--skip-h1b]

Per-cohort results checkpoint to research/results/<cohort>.json so a crash
resumes without recomputation. `make study` runs everything and renders
research/report.md.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

RESEARCH = Path(__file__).resolve().parent
REPO = RESEARCH.parent
sys.path.insert(0, str(RESEARCH))
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))

from prism import (  # noqa: E402
    build_panel,
    causality_scan,
    fit_gpd_pot,
    bipower_jump_stat,
    fit_regimes,
    local_projection,
    to_returns,
    walk_forward,
)
from studylib import (  # noqa: E402
    auroc,
    basel_traffic_light,
    conditional_coverage,
    detection_lags,
    diebold_mariano,
    event_hit_test,
    pit_regime_probs,
    rolling_var_series,
    spa_test,
    sup_chow,
)
from studylib.gdelt import factor_proxy_panel, spike_flags  # noqa: E402
import chronology  # noqa: E402

DATA = RESEARCH / "data"
RESULTS = RESEARCH / "results"
RESULTS.mkdir(exist_ok=True)

SEED = 7

COHORTS = {
    "C50": ("1976-06-01", ["NASDAQCOM", "DGS10", "DGS2", "DFF"]),
    "C40": (
        "1986-06-01",
        ["NASDAQCOM", "DGS10", "DGS2", "DFF", "DCOILWTICO", "BAA10Y"],
    ),
    "C36": (
        "1990-01-02",
        ["NASDAQCOM", "DGS10", "DGS2", "DFF", "DCOILWTICO", "BAA10Y", "VIXCLS"],
    ),
    "C20": (
        "2006-01-02",
        [
            "NASDAQCOM",
            "DGS10",
            "DGS2",
            "DFF",
            "DCOILWTICO",
            "BAA10Y",
            "VIXCLS",
            "DTWEXBGS",
            "T10YIE",
            "XAUUSD",
        ],
    ),
    "C10": (
        "2016-01-04",
        [
            "NASDAQCOM",
            "DGS10",
            "DGS2",
            "DFF",
            "DCOILWTICO",
            "BAA10Y",
            "VIXCLS",
            "DTWEXBGS",
            "T10YIE",
            "XAUUSD",
        ],
    ),
}
LOG_COLS = ["NASDAQCOM", "DCOILWTICO", "DTWEXBGS", "XAUUSD"]
DIFF_COLS = ["DGS10", "DGS2", "VIXCLS", "T10YIE", "DFF", "BAA10Y"]
TARGETS = ["NASDAQCOM_ret", "DGS10_diff"]
REGIME_BASE = ["NASDAQCOM_ret", "slope_diff"]
REGIME_EXTRA = ["VIXCLS_diff", "DCOILWTICO_ret"]


def _load_series(sids: list[str]) -> dict:
    out = {}
    for sid in sids:
        p = DATA / f"{sid}.csv"
        if not p.exists():
            continue
        df = pd.read_csv(p)
        out[sid] = [{"date": r.date, "value": float(r.value)} for r in df.itertuples()]
    return out


def _stress_labels(index: pd.DatetimeIndex) -> np.ndarray:
    """NBER recessions ∪ crash windows -> boolean series on the panel index."""
    lab = pd.Series(False, index=index)
    for start, end in chronology.NBER_RECESSIONS + chronology.CRASH_WINDOWS:
        lab.loc[start:end] = True
    return lab.to_numpy()


def _era_slices(panel: pd.DataFrame) -> dict:
    out = {}
    for era, (start, end) in chronology.ERAS.items():
        sub = panel.loc[start:end]
        if len(sub) >= 250:
            out[era] = sub
    return out


def build_cohort_panel(cohort: str) -> pd.DataFrame:
    start, sids = COHORTS[cohort]
    series = _load_series(sids)
    panel_raw = build_panel(series).loc[start:]
    rets = to_returns(
        panel_raw,
        [c for c in LOG_COLS if c in panel_raw],
        [c for c in DIFF_COLS if c in panel_raw],
    )
    if {"DGS10", "DGS2"}.issubset(panel_raw.columns):
        rets["slope_diff"] = (
            (panel_raw["DGS10"] - panel_raw["DGS2"]).diff().reindex(rets.index)
        )
    rets = rets.dropna()
    rets.attrs["raw"] = panel_raw
    return rets


def audit_gate(cohort: str, rets: pd.DataFrame) -> dict:
    start, _ = COHORTS[cohort]
    expected = len(
        pd.bdate_range(max(pd.Timestamp(start), rets.index.min()), rets.index.max())
    )
    got = len(rets)
    frac = got / max(1, expected)
    return {
        "expected_bdays": expected,
        "rows": got,
        "fraction": round(frac, 4),
        "passed": frac >= 0.90,
    }


# ---------------- hypotheses ----------------


def h1a_descriptive(rets: pd.DataFrame) -> dict:
    cols = [c for c in REGIME_BASE + REGIME_EXTRA if c in rets]
    res = fit_regimes(rets[cols], n_states=3, seed=SEED)
    stress = res.state_probs["stress"].to_numpy()
    labels = _stress_labels(rets.index)
    a = auroc(stress, labels)
    verdict = "支持" if a >= 0.80 else ("大體一致" if a >= 0.65 else "分歧")
    return {
        "auroc": round(float(a), 4),
        "converged": res.converged,
        "stress_days": int(labels.sum()),
        "verdict": verdict,
    }


def h1b_point_in_time(rets: pd.DataFrame) -> dict:
    cols = [c for c in REGIME_BASE + REGIME_EXTRA if c in rets]
    pit = pit_regime_probs(rets[cols], min_train_years=3, n_states=3, seed=SEED)
    if pit.empty:
        return {"verdict": "分歧", "note": "no PIT probabilities produced"}
    joined = pit.join(
        pd.Series(_stress_labels(rets.index), index=rets.index, name="label"),
        how="inner",
    )
    a = auroc(joined["stress"].to_numpy(), joined["label"].to_numpy())
    lags = detection_lags(
        joined["stress"].to_numpy(), joined["label"].to_numpy(), threshold=0.5
    )
    med_lag = float(np.median(lags)) if lags else np.nan
    if a >= 0.70 and med_lag <= 10:
        verdict = "支持"
    elif a >= 0.70:
        verdict = "大體一致"
    else:
        verdict = "分歧"
    return {
        "auroc": round(float(a), 4),
        "median_lag_bd": med_lag,
        "n_episodes": len(lags),
        "n_days": len(joined),
        "verdict": verdict,
    }


def h2_literature(rets: pd.DataFrame) -> dict:
    eras = _era_slices(rets)
    out = {"edges": []}
    for edge in chronology.LITERATURE_EDGES:
        src, tgt = edge["source"], edge["target"]
        if src not in rets or tgt not in rets:
            out["edges"].append({**edge, "verdict": "n/a (series absent)"})
            continue
        per_era = {}
        for era, sub in eras.items():
            scan = causality_scan(sub, [src], [tgt], seed=SEED)
            if len(scan):
                best = scan.loc[scan["q_value"].idxmin()]
                per_era[era] = {
                    "q": None if pd.isna(best["q_value"]) else float(best["q_value"]),
                    "h": int(best["horizon"]),
                }
        out["edges"].append({**edge, "per_era": per_era})
    return out


def h3_impact(rets: pd.DataFrame) -> dict:
    out = {}
    pairs = [("VIXCLS_diff", "NASDAQCOM_ret"), ("DCOILWTICO_ret", "DGS10_diff")]
    for shock, resp in pairs:
        if shock not in rets or resp not in rets:
            continue
        imp = local_projection(rets, shock, resp)
        wf = walk_forward(rets[[shock, resp]].dropna(), shock, resp)
        band_ok = all(
            not (lo <= 0 <= hi)
            for (lo, hi), b in zip(imp.band95[:5], imp.beta_mean[:5])
            if not np.isnan(b)
        )
        sign = np.sign(np.nanmean(imp.beta_mean[:5]))
        # DM: PRISM prediction loss vs AR(1) loss across folds — approximate
        # with per-fold MSE series (fold-pooled)
        dm = (
            diebold_mariano(wf["mse"].to_numpy(), wf["mse_zero_baseline"].to_numpy())
            if len(wf) >= 10
            else {"dm": np.nan, "p": np.nan}
        )
        edge_frac = float((wf["edge_vs_ar1"] > 0).mean()) if len(wf) else np.nan
        if band_ok and not np.isnan(dm["p"]) and dm["p"] < 0.05 and dm["dm"] < 0:
            verdict = "支持"
        elif band_ok:
            verdict = "大體一致"
        else:
            verdict = "分歧"
        out[f"{shock}->{resp}"] = {
            "beta_h1_5": [
                None if np.isnan(b) else round(b, 6) for b in imp.beta_mean[:5]
            ],
            "band95_excludes_zero_h1_5": band_ok,
            "sign": float(sign),
            "wf_folds": len(wf),
            "wf_edge_frac": None if np.isnan(edge_frac) else round(edge_frac, 3),
            "dm_p": None if np.isnan(dm["p"]) else round(dm["p"], 4),
            "verdict": verdict,
        }
    return out


def h4_var_calibration(rets: pd.DataFrame) -> dict:
    out = {}
    for asset, col in (("NASDAQCOM", "NASDAQCOM_ret"), ("DGS10", "DGS10_diff")):
        if col not in rets:
            continue
        var_series = rolling_var_series(rets[col])
        if var_series.empty:
            out[asset] = {"verdict": "分歧", "note": "no OOS VaR produced"}
            continue
        v = var_series["violation"].to_numpy()
        cc = conditional_coverage(v, alpha=0.01)
        zone = basel_traffic_light(v, alpha=0.01)
        kup = cc["pof"]
        if kup["p"] > 0.05 and cc["p"] > 0.05 and zone == "green":
            verdict = "支持"
        elif zone == "green" and kup["p"] > 0.05:
            verdict = "大體一致"
        else:
            verdict = "分歧"
        out[asset] = {
            "n_days": int(kup["n"]),
            "violations": int(kup["violations"]),
            "rate": round(float(kup["rate"]), 5),
            "kupiec_p": round(float(kup["p"]), 4),
            "cc_p": None if np.isnan(cc["p"]) else round(float(cc["p"]), 4),
            "basel": zone,
            "verdict": verdict,
        }
    return out


def h8_tails(rets: pd.DataFrame) -> dict:
    out = {}
    eras = _era_slices(rets)
    for asset, col in (("NASDAQCOM", "NASDAQCOM_ret"), ("DGS10", "DGS10_diff")):
        if col not in rets:
            continue
        xis = {}
        for era, sub in eras.items():
            tr = fit_gpd_pot(sub[col])
            if tr.valid:
                xis[era] = round(float(tr.xi), 4)
        jumps = bipower_jump_stat(rets[col]).reindex(rets.index)
        labels = _stress_labels(rets.index)
        a = auroc(jumps.to_numpy(), labels)
        xi_vals = list(xis.values())
        xi_stable = (max(xi_vals) - min(xi_vals) < 0.5) if len(xi_vals) >= 2 else None
        if xi_stable and a >= 0.70:
            verdict = "支持"
        elif (xi_stable is not False) and a >= 0.60:
            verdict = "大體一致"
        else:
            verdict = "分歧"
        out[asset] = {
            "xi_per_era": xis,
            "jump_auroc": round(float(a), 4),
            "verdict": verdict,
        }
    return out


def h5_factors(rets: pd.DataFrame) -> dict:
    agg_path = DATA / "gdelt_agg.csv"
    if not agg_path.exists():
        return {"verdict": "n/a", "note": "gdelt_agg.csv absent"}
    agg = pd.read_csv(agg_path)
    fpanel = factor_proxy_panel(agg)
    if fpanel.empty:
        return {"verdict": "分歧", "note": "empty factor panel"}
    joined = rets.join(fpanel, how="inner")
    factor_cols = [c for c in fpanel.columns if joined[c].notna().sum() >= 500]
    targets = [t for t in TARGETS + ["DCOILWTICO_ret"] if t in joined]
    if not factor_cols or not targets:
        return {"verdict": "n/a", "note": "insufficient overlap"}
    scan = causality_scan(joined, factor_cols, targets, seed=SEED)
    sig = scan[scan["significant"]]
    return {
        "n_tested": len(scan),
        "n_significant": int(scan["significant"].sum()),
        "overlap_days": len(joined),
        "significant_edges": sig[["source", "target", "horizon", "q_value"]].to_dict(
            "records"
        ),
        "scan": scan.to_dict("records"),
    }


def h5b_event_study(rets_index_min, rets_index_max) -> dict:
    agg_path = DATA / "gdelt_agg.csv"
    if not agg_path.exists():
        return {"verdict": "n/a"}
    agg = pd.read_csv(agg_path)
    fpanel = factor_proxy_panel(agg)
    out = {}
    for factor in fpanel.columns:
        events = [
            (pd.Timestamp(d), lbl)
            for d, f, lbl in chronology.FACTOR_EVENTS
            if f == factor
            and fpanel.index.min() <= pd.Timestamp(d) <= fpanel.index.max()
        ]
        if len(events) < 3:
            continue
        flags = spike_flags(fpanel[factor]).fillna(False).to_numpy()
        positions = [
            fpanel.index.get_indexer([d], method="nearest")[0] for d, _ in events
        ]
        r = event_hit_test(flags, positions, window=3)
        if r["hit_rate"] >= 0.70 and r["p"] < 0.05:
            verdict = "支持"
        elif r["hit_rate"] >= 0.50:
            verdict = "大體一致"
        else:
            verdict = "分歧"
        out[factor] = {
            **{k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()},
            "verdict": verdict,
        }
    return out


def h7_stability(rets: pd.DataFrame, candidate_edges: list[dict]) -> dict:
    eras = _era_slices(rets)
    out = {}
    for e in candidate_edges:
        src, tgt = e["source"], e["target"]
        if src not in rets or tgt not in rets:
            continue
        per_era = {}
        signs = []
        for era, sub in eras.items():
            if src not in sub or len(sub) < 300:
                continue
            imp = local_projection(sub, src, tgt, horizons=[5])
            b = imp.beta_mean[0]
            if b is None or np.isnan(b):
                continue
            lo, hi = imp.band95[0]
            sig = not (lo <= 0 <= hi)
            per_era[era] = {"beta5": round(float(b), 6), "sig95": bool(sig)}
            if sig:
                signs.append(np.sign(b))
        same_sign_sig = len(signs) > 0 and all(s == signs[0] for s in signs)
        n_sig = sum(1 for v in per_era.values() if v["sig95"])
        # sup-Chow on the full-sample regression
        shock = (rets[src] - rets[src].mean()) / rets[src].std(ddof=0)
        y = rets[tgt].rolling(5).sum().shift(-5)
        df = pd.DataFrame({"y": y, "x": shock}).dropna()
        X = np.column_stack([np.ones(len(df)), df["x"].to_numpy()])
        chow = sup_chow(df["y"].to_numpy(), X)
        if same_sign_sig and n_sig >= min(3, len(per_era)):
            verdict = "支持"
        elif same_sign_sig:
            verdict = "大體一致"
        else:
            verdict = "分歧"
        out[f"{src}->{tgt}"] = {
            "per_era": per_era,
            "sup_chow_reject": chow["reject_5pct"],
            "verdict": verdict,
        }
    return out


def h6_spa(rets: pd.DataFrame, scan_records: list[dict]) -> dict:
    """Naive sign strategy per scanned edge (5bp/side), SPA over the grid."""
    cost = 0.0005
    perf_cols = []
    names = []
    for rec in scan_records:
        src, tgt, h = rec["source"], rec["target"], int(rec["horizon"])
        if src not in rets or tgt not in rets:
            continue
        sig_dir = np.sign(rec.get("te") or 0.0) or 1.0
        pos = np.sign(rets[src]).shift(1) * sig_dir  # yesterday's shock sign
        fwd = rets[tgt]
        ret = (pos * fwd).fillna(0.0)
        trades = pos.diff().abs().fillna(0.0) / 2.0
        net = ret - trades * cost
        perf_cols.append(net.to_numpy())
        names.append(f"{src}->{tgt}@h{h}")
    if not perf_cols:
        return {"verdict": "n/a"}
    perf = np.column_stack(perf_cols)
    spa = spa_test(perf, n_boot=1000, block=20, seed=SEED)
    ann = 252
    sharpes = (
        perf.mean(axis=0) / np.maximum(perf.std(axis=0, ddof=1), 1e-12)
    ) * np.sqrt(ann)
    best_i = int(np.argmax(sharpes))
    if spa["p"] < 0.10:
        verdict = "支持"
    elif sharpes[best_i] > 0.5:
        verdict = "大體一致 (apparent edge consistent with snooping)"
    else:
        verdict = "分歧 (no economic predictability)"
    return {
        "n_strategies": len(names),
        "best": names[best_i],
        "best_sharpe_net": round(float(sharpes[best_i]), 3),
        "spa_p": round(float(spa["p"]), 4),
        "verdict": verdict,
    }


def run_cohort(cohort: str, skip_h1b: bool = False) -> dict:
    t0 = time.time()
    rets = build_cohort_panel(cohort)
    gate = audit_gate(cohort, rets)
    result = {
        "cohort": cohort,
        "audit": gate,
        "window": [str(rets.index.min().date()), str(rets.index.max().date())],
    }
    if not gate["passed"]:
        result["aborted"] = True
        return result

    result["H1a"] = h1a_descriptive(rets)
    if not skip_h1b:
        result["H1b"] = h1b_point_in_time(rets)
    result["H2"] = h2_literature(rets)
    result["H3"] = h3_impact(rets)
    result["H4"] = h4_var_calibration(rets)
    result["H8"] = h8_tails(rets)

    h5 = h5_factors(rets)
    result["H5"] = {k: v for k, v in h5.items() if k != "scan"}
    result["H5b"] = h5b_event_study(rets.index.min(), rets.index.max())

    sources = [
        c for c in ("DCOILWTICO_ret", "VIXCLS_diff", "DTWEXBGS_ret") if c in rets
    ]
    market_scan = causality_scan(
        rets, sources, [t for t in TARGETS if t in rets], seed=SEED
    )
    # C50 has no oil/VIX sources -> empty scan without a 'significant' column
    candidates = (
        market_scan[market_scan["significant"]].to_dict("records")
        if len(market_scan)
        else []
    )
    lit_pairs = [
        {"source": e["source"], "target": e["target"]}
        for e in chronology.LITERATURE_EDGES
    ]
    result["H7"] = h7_stability(rets, candidates + lit_pairs)

    all_scanned = market_scan.to_dict("records") + h5.get("scan", [])
    result["H6"] = h6_spa(rets, all_scanned)

    result["runtime_s"] = round(time.time() - t0, 1)
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cohort", default=None, choices=list(COHORTS))
    ap.add_argument("--skip-h1b", action="store_true")
    args = ap.parse_args()
    cohorts = [args.cohort] if args.cohort else list(COHORTS)
    for cohort in cohorts:
        out_path = RESULTS / f"{cohort}.json"
        if out_path.exists():
            print(f"{cohort}: cached, skipping (delete {out_path} to rerun)")
            continue
        print(f"=== {cohort} ===")
        res = run_cohort(cohort, skip_h1b=args.skip_h1b)
        out_path.write_text(json.dumps(res, indent=2, default=str))
        print(
            json.dumps(
                {k: v for k, v in res.items() if k in ("audit", "runtime_s")},
                default=str,
            )
        )


if __name__ == "__main__":
    main()
