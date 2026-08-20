"""Derive the full h=1..12 local-projection curve behind the sealed ENSO
verdict (research/results/enso_test.json) — the plotting-resolution
artifact for the fast-fail figure.

Calls the frozen runner's own load_panel/lp_betas_bands (identical code
path, identical data window), and refuses to write unless the curve
matches the sealed gate-horizon values (h in {6,9,12}) to the sealed
rounding — the curve must be a superset of the verdict, never a re-run
that could drift from it.

Data: research/data/enso/{oni.txt,WPU01.json} (refetch instructions in
run_enso_power_check.py).
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_enso_test  # noqa: E402

OUT = REPO / "research" / "results" / "enso_lp_curve.json"
SEALED = REPO / "research" / "results" / "enso_test.json"


def main():
    panel = run_enso_test.load_panel()
    betas, bands = run_enso_test.lp_betas_bands(panel)

    sealed = json.loads(SEALED.read_text())["gate2"]["detail"]
    mismatches = []
    for h in (6, 9, 12):
        for got, want in [
            (betas[h - 1], sealed[str(h)]["beta"]),
            (bands[h - 1][0], sealed[str(h)]["lo95"]),
            (bands[h - 1][1], sealed[str(h)]["hi95"]),
        ]:
            if round(float(got), 6) != want:
                mismatches.append(f"h={h}: {round(float(got), 6)} != {want}")
    if mismatches:
        print("SEALED-VERDICT MISMATCH — refusing to write:", file=sys.stderr)
        print("\n".join(mismatches), file=sys.stderr)
        sys.exit(1)

    OUT.write_text(
        json.dumps(
            {
                "source": "run_enso_test.load_panel/lp_betas_bands (frozen path)",
                "n_months": int(len(panel)),
                "window": [
                    str(panel.index.min().date()),
                    str(panel.index.max().date()),
                ],
                "h": list(range(1, 13)),
                "beta": [round(float(b), 6) for b in betas],
                "lo95": [round(float(lo), 6) for lo, _ in bands],
                "hi95": [round(float(hi), 6) for _, hi in bands],
                "sealed_verdict_check": "betas/bands at h in {6,9,12} match enso_test.json",
            },
            indent=1,
        )
    )
    print(f"wrote {OUT.relative_to(REPO)} (sealed-verdict check passed)")


if __name__ == "__main__":
    main()
