"""Stream-aggregate the GDELT MASTERREDUCEDV2 file to the study's schema.

PROTOCOL DEVIATION (logged): the pre-registered route was BigQuery over
`gdelt-bq.full.events` (1979→present). The bq CLI is unavailable on the
study machine, so Track A1 uses the official GDELT reduced backfile
(1979–2013-03) from the project's own mirror instead — same events, fewer
columns (no AvgTone; the factor panel only consumes count + Goldstein, so
this is immaterial). The 2013-04→present extension can be added later by
running research/fetch_gdelt.sql in BigQuery; H5/H7 factor-era coverage is
correspondingly limited to the volcker/moderation/zirp(partial) eras.

Reduced format (tab-separated): DATE SOURCE TARGET CAMEOCODE NUMEVENTS
NUMARTS QUADCLASS GOLDSTEIN ... (geo columns ignored).

Output: research/data/gdelt_agg.csv with columns
date, root_code, actor1, actor2, n_events, sum_goldstein, sum_tone
(matching fetch_gdelt.sql's output; sum_tone = 0 placeholder).
"""

import csv
import io
import zipfile
from collections import defaultdict
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
SRC = DATA / "GDELT.MASTERREDUCEDV2.1979-2013.zip"
OUT = DATA / "gdelt_agg.csv"

COUNTRIES = {
    "USA",
    "CHN",
    "RUS",
    "SAU",
    "IRN",
    "IRQ",
    "KWT",
    "VEN",
    "LBY",
    "ARE",
    "QAT",
    "UKR",
    "ISR",
}
ROOTS = {f"{i:02d}" for i in range(1, 21)}


def main() -> None:
    agg = defaultdict(lambda: [0, 0.0])  # key -> [n_events, sum_goldstein]
    n_lines = 0
    with zipfile.ZipFile(SRC) as zf:
        name = zf.namelist()[0]
        with zf.open(name) as fh:
            for raw in io.TextIOWrapper(fh, encoding="utf-8", errors="replace"):
                n_lines += 1
                parts = raw.rstrip("\n").split("\t")
                if len(parts) < 8:
                    continue
                date, source, target, cameo = parts[0], parts[1], parts[2], parts[3]
                if len(date) != 8 or not date.isdigit():
                    continue
                # actor codes start with 3-letter country code when present
                a1, a2 = source[:3], target[:3]
                if a1 not in COUNTRIES and a2 not in COUNTRIES:
                    continue
                root = cameo[:2].zfill(2)
                if root not in ROOTS:
                    continue
                try:
                    n = int(parts[4])
                    gold = float(parts[7])
                except ValueError:
                    continue
                key = (f"{date[:4]}-{date[4:6]}-{date[6:]}", root, a1, a2)
                cell = agg[key]
                cell[0] += n
                cell[1] += gold * n
    with open(OUT, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "date",
                "root_code",
                "actor1",
                "actor2",
                "n_events",
                "sum_goldstein",
                "sum_tone",
            ]
        )
        for (date, root, a1, a2), (n, g) in sorted(agg.items()):
            w.writerow([date, root, a1, a2, n, round(g, 3), 0.0])
    print(f"lines={n_lines} groups={len(agg)} -> {OUT}")


if __name__ == "__main__":
    main()
