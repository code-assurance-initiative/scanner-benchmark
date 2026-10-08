"""Score scans of benchmark units against their keys at a registered tag, into a final-scores.json of the same shape
as results/watchdog/rescore-harness-1.6.json (so `cai_bench.baseline.aggregate` and `python3 -m cai_bench compare`
read it), plus — optionally — the full harness report of every unit.

    python3 results/cai-reference/score_units.py --set-registry ../training-set-2026/registry.json \
        --units-dir <materialised units> --scans-root <dir with <unit>/findings.sarif> \
        --mapping mappings/cai-reference.json --instrument "cai-reference <commit>" \
        --out results/cai-reference/final-scores.json [--reports-dir <dir>] [unit ...]

For each unit (default: every unit of the set registry whose language is csharp): the tag is its `latestTag` (or
`--tag unit=vX.Y.Z`); the key is read at that tag through `cai_bench.units.read_key` and sha256-checked against the
set registry's version entry; the unit's files at the tag are the resource source (contract 1.6, as `--repo-dir`);
the scan is `<scans-root>/<unit>/` (or `--scan unit=<dir>`).

Scan formats (`--format`): `cai-reference` reads `findings.sarif` and the engine's `scores.json` ({dimension: 0-100});
`watchdog` reads `report.sarif` and turns `scorecard.json` into scores with mappings/watchdog_scores.py. Nothing
scanner-specific reaches the scorer: it is `cai_bench.scoring.score` with the given mapping. Standard library only.
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
from cai_bench.scoring import score  # noqa: E402
from cai_bench.units import files_source, read_key  # noqa: E402

FORMATS = {"cai-reference": ("findings.sarif", "scores.json"), "watchdog": ("report.sarif", "scorecard.json")}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def rows(d):
    return [dict(v, id=k) for k, v in d.items()]


def key_sha_at(unit, tag):
    for v in unit.get("versions", []):
        if v["tag"] == tag:
            return v["keySha256"]
    if unit.get("latestTag") == tag:
        return unit["keySha256"]
    raise SystemExit(f"{unit['name']}: tag {tag} is not registered in the set registry")


def load_scores(fmt, path):
    if not os.path.exists(path):
        return {}, False
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if fmt == "watchdog":
        from watchdog_scores import scores as scorecard_scores
        return scorecard_scores(doc), True
    if not isinstance(doc, dict):
        raise SystemExit(f"{path}: expected {{dimension: score}}")
    return doc, True


def score_unit(unit, tag, scan_dir, mapping, fmt, units_dir, set_dir, workspace=None):
    name = unit["name"]
    key_sha = key_sha_at(unit, tag)
    key = json.loads(read_key(name, tag, key_sha, units_dir=units_dir, set_dir=set_dir, workspace=workspace))
    sarif_name, scores_name = FORMATS[fmt]
    with open(os.path.join(scan_dir, sarif_name), "rb") as f:
        sarif_bytes = f.read()
    scores, have_scores = load_scores(fmt, os.path.join(scan_dir, scores_name))
    src = files_source(name, tag, units_dir=units_dir, set_dir=set_dir, workspace=workspace)
    report = score(key, read_results(json.loads(sarif_bytes), ()), mapping, scores, source=src)
    fns = [{"id": e["id"], "concept": e["concept"], "file": e.get("file"), "lines": e.get("lines"),
            "subject": e.get("subject"), "fileLevel": e.get("fileLevel"),
            **({"matchScope": e["matchScope"]} if e.get("matchScope") else {})}
           for e in report["entries"] if e["label"] == "must-fire" and e["outcome"] == "FN"]
    commit = next((v.get("commit") for v in unit.get("versions", []) if v["tag"] == tag), unit.get("commit"))
    row = {"repo": key.get("repo"), "name": name, "tag": tag, "commit": commit, "keySha256": key_sha,
           "keyVersion": key.get("keyVersion"), "languages": [unit["language"]], "family": unit.get("family"),
           "scan": {"sarifSha256": sha(sarif_bytes), "scores": have_scores},
           "summary": report["summary"], "concepts": rows(report["concepts"]),
           "dimensions": rows(report["dimensions"]), "scoreBands": report["scoreBands"], "falseNegatives": fns}
    full = {"harness": {"name": "cai_bench", "version": __version__, "contract": CONTRACT_VERSION},
            "key": {"repo": key.get("repo"), "keyVersion": key.get("keyVersion"), "sha256": key_sha},
            "sarif": {"sha256": sha(sarif_bytes)},
            "mapping": {"scanner": mapping.scanner, "version": mapping.version},
            "configuration": {"label": "default", "headline": True}, **report}
    return row, full


def _pairs(items, what):
    out = {}
    for it in items or []:
        if "=" not in it:
            raise SystemExit(f"--{what} expects unit=value, got {it!r}")
        k, v = it.split("=", 1)
        out[k] = v
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("units", nargs="*", help="unit names (default: every csharp unit of the set registry)")
    ap.add_argument("--set-registry", required=True, help="the set's registry.json (units[] with versions)")
    ap.add_argument("--units-dir", help="materialised units, <units-dir>/<unit> (the set's tools/materialize.sh)")
    ap.add_argument("--set-dir", help="the set checkout whose units/<unit>.bundle hold the keys (fallback source)")
    ap.add_argument("--scans-root", help="<scans-root>/<unit>/ holds the scan")
    ap.add_argument("--scan", action="append", help="unit=<scan dir>, overrides --scans-root for that unit")
    ap.add_argument("--tag", action="append", help="unit=vX.Y.Z, instead of the unit's latest registered tag")
    ap.add_argument("--format", choices=sorted(FORMATS), default="cai-reference")
    ap.add_argument("--mapping", default=os.path.join(ROOT, "mappings", "cai-reference.json"))
    ap.add_argument("--instrument", default="unspecified", help="what was run (engine, commit, configuration)")
    ap.add_argument("--out", required=True, help="final-scores.json to write")
    ap.add_argument("--reports-dir", help="also write the full harness report of each unit here, <unit>.report.json")
    a = ap.parse_args(argv)
    with open(a.set_registry, encoding="utf-8") as f:
        reg = json.load(f)
    units = {u["name"]: u for u in reg["units"]}
    names = a.units or [n for n, u in units.items() if u.get("language") == "csharp"]
    tags, scans = _pairs(a.tag, "tag"), _pairs(a.scan, "scan")
    with open(a.mapping, encoding="utf-8") as f:
        mapping = Mapping(json.load(f))
    set_dir = a.set_dir or os.path.dirname(os.path.abspath(a.set_registry))
    repos = []
    for n in names:
        if n not in units:
            raise SystemExit(f"{n}: not in {a.set_registry}")
        tag = tags.get(n, units[n]["latestTag"])
        scan_dir = scans.get(n) or (os.path.join(a.scans_root, n) if a.scans_root else None)
        if not scan_dir:
            raise SystemExit(f"{n}: no scan directory (--scans-root or --scan)")
        row, full = score_unit(units[n], tag, scan_dir, mapping, a.format, a.units_dir, set_dir)
        s = row["summary"]
        print(f"{n:<36} {tag:<7} recall {s['tp']}/{s['tp'] + s['fn']}  traps {s['trapTn']}/"
              f"{s['trapTn'] + s['trapFp']}  noise {s['noise']}/{s['results']}  redundant {s['redundant']}  "
              f"uncovered {s['uncovered']}")
        repos.append(row)
        if a.reports_dir:
            os.makedirs(a.reports_dir, exist_ok=True)
            with open(os.path.join(a.reports_dir, f"{n}.report.json"), "w", encoding="utf-8") as f:
                json.dump(full, f, indent=1)
                f.write("\n")
    doc = {"harness": {"name": "cai_bench", "version": __version__, "contract": CONTRACT_VERSION},
           "mapping": {"path": os.path.relpath(os.path.abspath(a.mapping), ROOT), "scanner": mapping.scanner,
                       "version": mapping.version},
           "instrument": a.instrument, "repos": repos}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
