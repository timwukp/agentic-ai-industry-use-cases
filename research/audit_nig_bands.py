"""Planted-truth audit of the local-projection prior, per horizon — the
committed-data anchor for the band-inflation numbers quoted in
findings_addendum.md ("H3 root cause", 2026-08-12).

Two blocks, one JSON (research/results/nig_band_audit.json):

1. synthetic: the 2026-08-12 audit design (50 seeds, n=2600, sigma=1%,
   beta=20bp, h in {1,5,20}) run through the production entry point
   `local_projection` under BOTH priors — the removed absolute prior
   (a0=b0=1, reimplemented below verbatim) and the current scale-matched
   prior. Reports band-halfwidth/oracle ratios and 95% coverage.
   Reproduction gate: the absolute-prior ratios must land within +/-0.05
   of the addendum's 2.96/1.61/1.19 or this script exits non-zero — a
   correction inherits no credibility from the error it replaces.
2. production_pair: the same two priors on the nightly batch's headline
   VIXCLS_diff -> NASDAQCOM_ret pair (real FRED data, 10-year window
   pinned below), reporting the old/new band-width ratio per horizon —
   the reproducible counterfactual behind "production bands narrowed by
   the predicted factor" (replaces a post-deploy spot check that was
   never committed).

Data: research/data/{VIXCLS,NASDAQCOM}.csv via fetch_data.py (FRED).
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "finance" / "quant_batch"))
from prism import impact  # noqa: E402
from prism.data import build_panel, to_returns  # noqa: E402
from prism.impact import local_projection  # noqa: E402

RESULTS = REPO / "research" / "results" / "nig_band_audit.json"
DATA = REPO / "research" / "data"

# --- the 2026-08-12 audit design (findings_addendum.md "H3 root cause") ---
N, SIGMA, BETA, SEEDS = 2600, 0.01, 0.002, 50
HORIZONS = [1, 5, 20]
ADDENDUM_RATIOS = {1: 2.96, 5: 1.61, 20: 1.19}
REPRO_TOL = 0.05

# --- production counterfactual: the ALWAYS_IMPACT vol-index/equity pair ---
PAIR = ("VIXCLS_diff", "NASDAQCOM_ret")
PANEL_END = "2026-08-06"  # last observation in the committed fetch
PANEL_YEARS = 10  # the nightly lake's seeded history depth


def _nig_posterior_absolute(X, y, ridge_lambda, prior_a0=None, n_eff=None):
    """The pre-2026-08-12 prior, verbatim: a0 = b0 = 1 in absolute units.
    prior_a0 is accepted (local_projection passes it) and ignored."""
    n, k = X.shape
    n_stat = n if n_eff is None else n_eff
    prior_prec = ridge_lambda * np.eye(k)
    prec = X.T @ X + prior_prec
    cov = np.linalg.inv(prec)
    mean = cov @ (X.T @ y)
    resid = y - X @ mean
    a_post = 1.0 + n_stat / 2.0
    b_post = 1.0 + 0.5 * (resid @ resid + mean @ prior_prec @ mean)
    return mean, cov, 2 * a_post, b_post / a_post


class _prior:
    """Context manager swapping the posterior the entry point resolves."""

    def __init__(self, fn):
        self.fn = fn

    def __enter__(self):
        self.saved = impact._nig_posterior
        impact._nig_posterior = self.fn

    def __exit__(self, *exc):
        impact._nig_posterior = self.saved


def synthetic_block():
    out = {}
    for name, fn in [
        ("absolute_prior", _nig_posterior_absolute),
        ("scale_matched_prior", None),
    ]:
        halves = {h: [] for h in HORIZONS}
        covered = {h: 0 for h in HORIZONS}
        for seed in range(SEEDS):
            rng = np.random.default_rng(seed)
            shock = rng.normal(0, 1, N)
            resp = BETA * np.roll(shock, 1) + rng.normal(0, SIGMA, N)
            resp[0] -= BETA * shock[-1]  # np.roll wraps; undo the wrap term
            panel = pd.DataFrame(
                {"x": shock, "y": resp},
                index=pd.bdate_range("2015-01-01", periods=N),
            )
            ctx = _prior(fn) if fn else _null_ctx()
            with ctx:
                imp = local_projection(panel, "x", "y", horizons=HORIZONS)
            for h_i, h in enumerate(HORIZONS):
                lo, hi = imp.band95[h_i]
                halves[h].append((hi - lo) / 2)
                # cumulative truth is BETA at every h (lag-1 response only)
                covered[h] += int(lo <= BETA <= hi)
        out[name] = {
            str(h): {
                "band95_halfwidth_over_oracle": round(
                    float(np.mean(halves[h]))
                    / (1.96 * np.sqrt(h) * SIGMA / np.sqrt(N)),
                    3,
                ),
                "coverage_at_nominal_95": round(covered[h] / SEEDS, 3),
            }
            for h in HORIZONS
        }
    return out


class _null_ctx:
    def __enter__(self):
        pass

    def __exit__(self, *exc):
        pass


def production_block():
    series = {}
    for sid in ("VIXCLS", "NASDAQCOM"):
        df = pd.read_csv(DATA / f"{sid}.csv")
        series[sid] = df.to_dict("records")
    panel = build_panel(series)
    end = pd.Timestamp(PANEL_END)
    panel = panel[end - pd.DateOffset(years=PANEL_YEARS) : end]
    rets = to_returns(panel, log_cols=["NASDAQCOM"], diff_cols=["VIXCLS"])

    widths = {}
    for name, fn in [
        ("absolute_prior", _nig_posterior_absolute),
        ("scale_matched_prior", None),
    ]:
        ctx = _prior(fn) if fn else _null_ctx()
        with ctx:
            imp = local_projection(rets, *PAIR)
        widths[name] = [(hi - lo) / 2 for lo, hi in imp.band95]
    ratio = [
        round(a / b, 3) if np.isfinite(a) and np.isfinite(b) and b > 0 else None
        for a, b in zip(widths["absolute_prior"], widths["scale_matched_prior"])
    ]
    return {
        "pair": {"shock": PAIR[0], "response": PAIR[1]},
        "window": [str(rets.index.min().date()), str(rets.index.max().date())],
        "n_obs": int(len(rets)),
        "horizons": list(range(1, 21)),
        "band95_halfwidth_ratio_absolute_over_scale_matched": ratio,
    }


def main():
    result = {
        "design": {
            "seeds": SEEDS,
            "n": N,
            "sigma": SIGMA,
            "beta": BETA,
            "oracle": "1.96*sqrt(h)*sigma/sqrt(n)",
            "entry_point": "prism.impact.local_projection (production path)",
        },
        "synthetic": synthetic_block(),
        "production_pair": production_block(),
    }

    # Reproduction gate: anchor the addendum's prose numbers as data
    failures = []
    for h, want in ADDENDUM_RATIOS.items():
        got = result["synthetic"]["absolute_prior"][str(h)][
            "band95_halfwidth_over_oracle"
        ]
        if abs(got - want) > REPRO_TOL:
            failures.append(f"h={h}: reproduced {got} vs addendum {want}")
    result["reproduction_gate"] = {
        "tolerance": REPRO_TOL,
        "passes": not failures,
        "failures": failures,
    }

    RESULTS.write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))
    if failures:
        print("REPRODUCTION GATE FAILED", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
