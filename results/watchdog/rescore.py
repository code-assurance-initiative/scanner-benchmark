"""Score a NEW set of Watchdog scans of every baseline repository at its registered tag, into a final-scores.json
that `python3 -m cai_bench compare` can set against a frozen baseline.

    python3 results/watchdog/rescore.py --baseline results/watchdog/baseline-2026-10-07.json \
        --units-dir <materialised units> --scans-root <dir> --instrument "Watchdog, kennel main <sha>, ..." \
        --out final-scores-<label>.json
    python3 results/watchdog/rescore.py --baseline results/watchdog/baseline-2026-10-07.json --baseline-scans \
        --out /tmp/x.json                                   # reproduce the baseline from its own scans

For each repository of the baseline: the key is read at its tag from the first source that has it — materialised units
(`--units-dir <dir>/<repo>`, made by the training set's `tools/materialize.sh`), the training set's bundles
(`--set-dir`, default: a `training-set-2026` checkout next to scanner-benchmark), or a legacy clone `<workspace>/<repo>`
— and its sha256 must equal the baseline's; the scan is the one directory
under `<scans-root>/<repo>/` holding a `report.sarif` (and `scorecard.json`, for the score bands) — the sidecar
directory `tools/multilang/scan.py` prints. With `--baseline-scans` the scans named in the baseline are used instead.
Standard library only.
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "mappings"))

from cai_bench import CONTRACT_VERSION, __version__  # noqa: E402
from cai_bench.mapping import Mapping  # noqa: E402
from cai_bench.sarif import read_results  # noqa: E402
from cai_bench.units import default_set_dir, read_key  # noqa: E402
from cai_bench.scoring import score  # noqa: E402
from watchdog_scores import scores as scorecard_scores  # noqa: E402


def sha(b):
    return hashlib.sha256(b).hexdigest()


def find_scan(root, name):
    base = os.path.join(root, name)
    hits = [dp for dp, _dn, fn in os.walk(base) if "report.sarif" in fn]
    if len(hits) != 1:
        raise SystemExit(f"{name}: expected exactly one report.sarif under {base}, found {len(hits)}: {hits}")
    return hits[0]


def rows(d):
    return [dict(v, id=k) for k, v in d.items()]


def rescore_repo(b, workspace, scan_dir, mapping, units_dir=None, set_dir=None):
    name, tag = b["name"], b["tag"]
    try:
        raw = read_key(name, tag, b["keySha256"], units_dir=units_dir, set_dir=set_dir, workspace=workspace)
    except (LookupError, ValueError) as e:
        raise SystemExit(f"{e} (the baseline scored {b['keySha256']})")
    key = json.loads(raw)
    with open(os.path.join(scan_dir, "report.sarif"), "rb") as f:
        sarif_bytes = f.read()
    card = os.path.join(scan_dir, "scorecard.json")
    scores = {}
    if os.path.exists(card):
        with open(card, encoding="utf-8") as f:
            scores = scorecard_scores(json.load(f))
    report = score(key, read_results(json.loads(sarif_bytes), ()), mapping, scores)
    fns = [{"id": e["id"], "concept": e["concept"], "file": e.get("file"), "lines": e.get("lines"),
            "subject": e.get("subject"), "fileLevel": e.get("fileLevel")}
           for e in report["entries"] if e["label"] == "must-fire" and e["outcome"] == "FN"]
    return {"repo": key.get("repo"), "name": name, "tag": tag, "commit": b.get("commit"), "keySha256": b["keySha256"],
            "keyVersion": key.get("keyVersion"), "languages": [b["language"]], "family": b["family"],
            "scan": {"dir": scan_dir, "sarifSha256": sha(sarif_bytes), "scorecard": os.path.exists(card)},
            "summary": report["summary"], "concepts": rows(report["concepts"]),
            "dimensions": rows(report["dimensions"]), "scoreBands": report["scoreBands"], "falseNegatives": fns}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--scans-root", help="<scans-root>/<repo>/…/report.sarif per repository")
    ap.add_argument("--baseline-scans", action="store_true", help="re-score the scans the baseline names")
    ap.add_argument("--units-dir", help="directory of materialised units, <units-dir>/<repo> (tools/materialize.sh)")
    ap.add_argument("--set-dir", help="training-set checkout whose units/<repo>.bundle hold the keys "
                                      "(default: training-set-2026 next to scanner-benchmark, or $BENCH_SET_DIR)")
    ap.add_argument("--workspace", default=os.path.dirname(ROOT),
                    help="legacy: directory holding a clone of every repository; with --baseline-scans also the root "
                         "the baseline's scan directories are relative to (default: scanner-benchmark/..)")
    ap.add_argument("--mapping", default=os.path.join(ROOT, "mappings", "watchdog.json"))
    ap.add_argument("--instrument", default=None, help="what was run (engine commit, rubric, image, mode)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if bool(a.scans_root) == bool(a.baseline_scans):
        ap.error("give exactly one of --scans-root and --baseline-scans")
    with open(a.baseline, encoding="utf-8") as f:
        base = json.load(f)
    with open(a.mapping, encoding="utf-8") as f:
        mapping = Mapping(json.load(f))
    repos = []
    for b in base["repos"]:
        d = os.path.join(a.workspace, b["scanDir"]) if a.baseline_scans else find_scan(a.scans_root, b["name"])
        r = rescore_repo(b, a.workspace, d, mapping, a.units_dir, a.set_dir or default_set_dir(a.workspace))
        s = r["summary"]
        print(f"{b['name']:<36} {b['tag']:<7} recall {s['tp']}/{s['tp'] + s['fn']}  traps {s['trapTn']}/"
              f"{s['trapTn'] + s['trapFp']}  noise {s['noise']}/{s['results']}")
        repos.append(r)
    doc = {"harness": {"name": "cai_bench", "version": __version__, "contract": CONTRACT_VERSION},
           "mapping": {"path": os.path.relpath(a.mapping, ROOT), "scanner": mapping.scanner, "version": mapping.version},
           "instrument": a.instrument or (base["instrument"] if a.baseline_scans else "unspecified"),
           "baseline": os.path.basename(a.baseline), "repos": repos}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
