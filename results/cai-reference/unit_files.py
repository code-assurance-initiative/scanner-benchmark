"""Write one results file per unit (the format of results/watchdog/<repo>.json, see results/watchdog/README.md) from
the full harness reports of score_units.py and a curated verdict file.

    python3 results/cai-reference/unit_files.py --final results/cai-reference/final-scores.json \
        --reports-dir <dir of <unit>.report.json> --scans-root <dir of <unit>/findings.sarif> \
        --verdicts results/cai-reference/verdicts-training.json --out-dir results/cai-reference [--date 2026-10-08]

Every unit file records the scan (sha256 of the three engine outputs), the harness summary, the OUTCOME of every
result (no five-class verdict needed), every false negative with its mechanism, and the five-class verdicts the
verdict file gives (a sample of the noise; the verdict file says which). The mechanism of a false negative is derived
from the report and the mapping, unless the verdict file overrides it for that entry:

- `no-rule`: no rule of the scanner maps the concept (the mapping's `unmapped` reason is quoted);
- `off-site`: a result of the concept lies in the plant's file, not on its lines (file-level found);
- `elsewhere`: the concept is reported in the unit, never in the plant's file;
- `silent`: the concept is reported nowhere in the unit.

Verdict file: {"scope": "…", "units": {"<unit>": {"verdicts": [{"file", "line", "ruleId", "class", "reason",
"action"}], "fnOverrides": {"<entry id>": {"mechanism", "reason"}}}}}. A verdict names its result by (ruleId, file,
line) — narrowed, when two results share them, by `commitSha` (a prefix; null = a result without one) and
`messageContains` — and must match exactly one result of the unit, or the build fails. Standard library only.
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from cai_bench.mapping import Mapping  # noqa: E402

CLASSES = ("valid", "false-positive", "opinion-not-fact", "redundant", "shape-irrelevant")
NOISE = ("trap-fp", "clean-fp", "na-fp", "unmatched-fp")
OUTPUTS = ("findings.sarif", "scores.json", "evidence.json")


def sha_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def fn_mechanism(entry, mapping, report):
    c = entry["concept"]
    if not mapping.concepts.get(c):
        return "no-rule", f"no rule of the scanner maps the concept ({mapping.unmapped.get(c, 'omitted from the mapping')})"
    if entry.get("fileLevel"):
        return "off-site", "a result of the concept lies in the plant's file, but not on its lines (± tolerance)"
    if any(c in (r.get("concepts") or []) or r.get("attributedConcept") == c for r in report["results"]):
        return "elsewhere", "the concept is reported in this unit, never in the plant's file"
    return "silent", "the scanner reports the concept nowhere in this unit"


def build_unit(row, report, scan_dir, messages, mapping, curated, instrument, date):
    results = report["results"]
    outcomes = [{k: r.get(k) for k in ("ruleId", "file", "line", "outcome", "entryId", "attributedConcept",
                                       "locationSource", "matchScope", "commitSha") if r.get(k) is not None}
                for r in results]
    verdicts = []
    for v in curated.get("verdicts", []):
        if v["class"] not in CLASSES:
            raise SystemExit(f"{row['name']}: verdict class {v['class']!r} is not one of {CLASSES}")
        hits = [r for r in results if (r["ruleId"], r["file"], r["line"]) == (v["ruleId"], v.get("file"), v.get("line"))
                and ("commitSha" not in v or (r.get("commitSha") or None) == v["commitSha"]
                     or (v["commitSha"] and (r.get("commitSha") or "").startswith(v["commitSha"])))
                and ("messageContains" not in v or v["messageContains"] in (messages[(r["run"], r["resultIndex"])] or ""))]
        if len(hits) != 1:
            raise SystemExit(f"{row['name']}: verdict {v['ruleId']} {v.get('file')}:{v.get('line')} matches "
                             f"{len(hits)} results (needs exactly 1)")
        r = hits[0]
        verdicts.append({"ruleId": r["ruleId"], "file": r["file"], "line": r["line"],
                         "message": messages[(r["run"], r["resultIndex"])], "outcome": r["outcome"], "entryId": r.get("entryId"),
                         "class": v["class"], "reason": v["reason"],
                         "action": v.get("action", "recorded as noise of the scanner (no key or unit change)")})
    overrides = curated.get("fnOverrides", {})
    fns = []
    for e in report["entries"]:
        if e["label"] == "must-fire" and e["outcome"] == "FN":
            mech, why = fn_mechanism(e, mapping, report)
            o = overrides.get(e["id"])
            if o:
                mech, why = o["mechanism"], o["reason"]
            fns.append({"entryId": e["id"], "concept": e["concept"], "file": e.get("file"), "lines": e.get("lines"),
                        "mechanism": mech, "reason": why})
    unknown = set(overrides) - {f["entryId"] for f in fns}
    if unknown:
        raise SystemExit(f"{row['name']}: fnOverrides name entries that are not FNs: {sorted(unknown)}")
    noise_rows = sum(1 for r in results if r["outcome"] in NOISE)
    return {
        "repo": row["repo"], "tag": row["tag"], "commit": row["commit"], "keySha256": row["keySha256"],
        "keyVersion": row["keyVersion"], "scanner": "cai-reference", "engineVersion": instrument,
        "scans": [{"iteration": 1, "date": date, "sarifSha256": row["scan"]["sarifSha256"],
                   "outputs": {n: sha_file(os.path.join(scan_dir, n)) for n in OUTPUTS
                               if os.path.exists(os.path.join(scan_dir, n))},
                   "harness": report.get("harness"), "mapping": report.get("mapping"),
                   "configuration": {"label": "default", "headline": True},
                   "outcomes": row["summary"]}],
        "outcomes": outcomes,
        "verdictScope": curated.get("scope") or (f"{len(verdicts)} of {noise_rows} noise rows" if verdicts else
                                                 "no five-class verdicts for this unit"),
        "verdicts": verdicts,
        "falseNegatives": fns,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--final", required=True, help="final-scores.json written by score_units.py")
    ap.add_argument("--reports-dir", required=True, help="the --reports-dir of score_units.py")
    ap.add_argument("--scans-root", required=True)
    ap.add_argument("--verdicts", help="curated verdict file (see the module doc)")
    ap.add_argument("--mapping", default=os.path.join(ROOT, "mappings", "cai-reference.json"))
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--date", default="2026-10-08")
    a = ap.parse_args(argv)
    with open(a.final, encoding="utf-8") as f:
        final = json.load(f)
    with open(a.mapping, encoding="utf-8") as f:
        mapping = Mapping(json.load(f))
    cur = {"scope": None, "units": {}}
    if a.verdicts:
        with open(a.verdicts, encoding="utf-8") as f:
            cur = json.load(f)
    unknown = set(cur["units"]) - {r["name"] for r in final["repos"]}
    if unknown:
        raise SystemExit(f"verdict file names units not in {a.final}: {sorted(unknown)}")
    for row in final["repos"]:
        n = row["name"]
        with open(os.path.join(a.reports_dir, f"{n}.report.json"), encoding="utf-8") as f:
            report = json.load(f)
        scan_dir = os.path.join(a.scans_root, n)
        if sha_file(os.path.join(scan_dir, "findings.sarif")) != row["scan"]["sarifSha256"]:
            raise SystemExit(f"{n}: {scan_dir}/findings.sarif is not the SARIF that was scored")
        with open(os.path.join(scan_dir, "findings.sarif"), encoding="utf-8") as f:
            sarif = json.load(f)
        messages = {(i, j): r.get("message", {}).get("text")
                    for i, run in enumerate(sarif["runs"]) for j, r in enumerate(run.get("results", []))}
        curated = dict(cur["units"].get(n, {}))
        curated.setdefault("scope", cur.get("scope") if curated.get("verdicts") else None)
        doc = build_unit(row, report, scan_dir, messages, mapping, curated, final.get("instrument"), a.date)
        with open(os.path.join(a.out_dir, f"{n}.json"), "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        print(f"{n}: {len(doc['outcomes'])} outcomes, {len(doc['verdicts'])} verdicts, {len(doc['falseNegatives'])} FNs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
