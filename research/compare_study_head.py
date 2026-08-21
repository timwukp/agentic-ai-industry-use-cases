"""Reproduction experiment for the sealed 50-year study: re-run the study
at repository HEAD and record, field by field, what moved against the
sealed cohort artifacts and why that is expected.

The sealed verdicts (tag `study-preregistered`, 2026-08-09) predate three
instrument changes that the study itself triggered: the promoted Fisher
causality combination, the promoted volatility-filtered VaR, and the
2026-08-12 local-projection prior repair. A HEAD re-run also consumes
newer data (the cohort windows are open-ended). This script quantifies
the resulting drift so the paper can state precisely what "reproducible"
means: the sealed artifacts regenerate their report deterministically;
a HEAD re-run is new evidence under a better instrument, not a failed
reproduction.

Usage: python research/compare_study_head.py <sealed_dir> <head_dir>
Writes research/results/study_head_reproduction.json.
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "research" / "results" / "study_head_reproduction.json"
COHORTS = ["C50", "C40", "C36", "C20", "C10"]


def flat(d, pre=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(flat(v, pre + k + "."))
        elif isinstance(v, (int, float, str, bool)) or v is None:
            out[pre + k] = v
    return out


def main(sealed_dir: Path, head_dir: Path):
    cohorts = {}
    for c in COHORTS:
        s = flat(json.loads((sealed_dir / f"{c}.json").read_text()))
        h = flat(json.loads((head_dir / f"{c}.json").read_text()))
        moved = sorted(k for k in set(s) | set(h) if s.get(k) != h.get(k))
        moved = [k for k in moved if k != "runtime_s"]  # machine-dependent
        cohorts[c] = {
            "n_fields": len(set(s) | set(h)),
            "n_moved": len(moved),
            "moved": {k: {"sealed": s.get(k), "head": h.get(k)} for k in moved},
        }
    result = {
        "sealed_tag": "study-preregistered",
        "head_note": (
            "HEAD re-run consumes data through the fetch date and the "
            "post-seal instrument (Fisher combination, vol-filtered VaR, "
            "2026-08-12 prior repair); differences are expected and are "
            "the instrument-version discontinuity the study report "
            "declares, not a failed reproduction."
        ),
        "cohorts": cohorts,
    }
    OUT.write_text(json.dumps(result, indent=1))
    for c, r in cohorts.items():
        print(f"{c}: {r['n_moved']}/{r['n_fields']} fields moved")
    print(f"wrote {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
