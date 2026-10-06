#!/usr/bin/env python3
"""Turn a Watchdog `scorecard.json` (written beside its report.sarif) into the `--scores` input of
`python3 -m cai_bench score`: {dimension id: score on 0..100}. Dimensions that abstained (no score) are left out,
so their score-band entries report as `unscored` rather than as a guessed number.

    python3 mappings/watchdog_scores.py <scan-dir>/scorecard.json > scores.json
"""
import json
import sys


def scores(scorecard: dict) -> dict:
    out = {}
    for lens in scorecard.get("lenses", []):
        for dim in lens.get("dimensions", []):
            pct = dim.get("scorePct")
            if pct is not None:
                out[dim["id"]] = pct
    return out


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as f:
        json.dump(scores(json.load(f)), sys.stdout, indent=1, sort_keys=True)
    print()
