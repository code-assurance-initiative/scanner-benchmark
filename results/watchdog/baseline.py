"""Freeze Watchdog's measured state as the baseline of scanner-benchmark iteration 1, and render its tables.

    python3 results/watchdog/baseline.py                       # rebuild baseline-2026-10-07.json, print the tables
    python3 results/watchdog/baseline.py --update-doc results/watchdog/BASELINE-2026-10-07.md
    python3 results/watchdog/baseline.py --check               # exit 1 when the JSON or the doc is out of date

Standard library only (and the in-repository `cai_bench` package). Inputs:

- results/watchdog/final-scores.json   the final contained re-score of every registry repository at its latest tag
- results/watchdog/SUMMARY.json        the summary those numbers must reconcile with
- results/watchdog/<repo>.json         per-repository verdicts (authoring triage)
- results/watchdog/summarise.py        the curated false-negative mechanism of every FN (FN_MECHANISMS)
- coverage/matrix.json                 dimension names, lenses, scope, evaluator and which keys label each dimension
- mappings/watchdog.json               concept -> dimension
- the authoring workspace (default: the directory holding scanner-benchmark/):
    <repo>/                            a clone of every benchmark repository (the key is read at the registered tag
                                       with `git show <tag>:benchmark/answer-key.json`, its sha256 checked)
    _scans/<repo>/<iter>/src/          the final contained scan named in final-scores.json (report.sarif, scorecard.json;
                                       sha256 of the SARIF checked)
    _scans/backlog-draft.json          the 70 noise mechanisms filed to the Watchdog backlog, and
    _scans/backlog-filed.json          their backlog ids (draft position -> id)
    _scans/<repo>/<pass>/<repo>/       repeated host --with-llm passes (model non-determinism)
- optionally the rubric catalog snapshot (kennel engine/rubrics/rubric-catalog-snapshot.json): cross-checked against
  coverage/matrix.json when present.

Every repository is RE-SCORED in process from those inputs and its outcome must equal final-scores.json exactly; the
per-dimension noise kinds (trap / clean / not-applicable / unlabelled) and the per-dimension outcome of every plant come
from that re-score (matching re-run within the dimension, as `cai_bench.scoring.by_dimension` does).
"""
import argparse
import collections
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # scanner-benchmark/
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from cai_bench.baseline import LANGS, NO_RULE, aggregate, metrics, natural  # noqa: E402
from cai_bench.keyfile import entry_concepts, line_tolerance  # noqa: E402
from cai_bench.mapping import Mapping  # noqa: E402
from cai_bench.sarif import read_results  # noqa: E402
from cai_bench.scoring import STAR, Matcher, score  # noqa: E402
from summarise import FN_MECHANISMS  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "mappings"))
from watchdog_scores import scores as scorecard_scores  # noqa: E402

DATE = "2026-10-07"
OUT = os.path.join(HERE, f"baseline-{DATE}.json")
LANG_LABEL = {"csharp": "C#", "typescript": "TS"}
NOISE_KINDS = ("trap-fp", "clean-fp", "na-fp", "unmatched-fp")

FN_SHORT = {
    "repo-wide-posture-switch": "repo-wide posture switch (one site credits the repo)",
    "no-rule-for-concept": "no rule for the concept",
    "ts-arm-missing-codehealth": "no TypeScript arm (code health / tests)",
    "prefix-less-secret": "prefix-less secret",
    "injection-taint-in-handler-only": "taint confined to the request handler",
    "injection-sink-without-rule": "injection sink without a rule",
    "shallow-heuristic": "pattern too shallow for the defect's shape",
    "structural-population-too-narrow": "structural detector reads too narrow a population",
    "info-level-never-in-sarif": "measured, never reported (Info rows / roll-up only)",
    "call-shape-matching": "matches call names, not data",
    "dm-ts-arm-missing": "DM rules without a TypeScript arm",
    "location-imprecision": "found the file, missed the site",
    "a11y-text-cards-off-by-default": "model-judged a11y card off by default",
    "dependency-hygiene-arm": "dependency-hygiene arm missing",
    "presence-only-runtime-checks": "presence-only runtime check",
    "adr-and-doc-conformance": "ADR / doc conformance model-judged only",
    "a11y-css-not-read": "AC6 does not read .css files",
    "flaky-test-detection": "flaky-test detection too weak",
    "iac-ci-check-absent": "IaC / CI check absent from the pinned rule sets",
}

# Repeated host --with-llm passes over the same code (same commit, or a commit whose code is identical), from the
# results files' scans[] notes. Each pair is (repository, pass dir A, pass dir B, why the code is the same).
REPEAT_PAIRS = [
    ("bench-csharp-codehealth", "iter4-llm1", "iter4-llm2", "two passes on the same commit 29f24c9"),
    ("bench-csharp-maturity-history", "iter1-llm", "iter1-llm2", "two passes on the same commit"),
    ("bench-ts-baseline-clean", "iter2-llm", "iter2-llm2", "two passes on the same commit 017cb1c"),
    ("bench-csharp-architecture", "iter3-llm", "v1.1-iter1-llm", "df6ea32 vs c6a9e9e, code identical (key-only change)"),
    ("bench-csharp-blazor-a11y", "iter3-llm", "final-llm", "5e74f77 vs freestanding v1.0.0 clone, code identical"),
    ("bench-csharp-blazor-a11y", "iter3-wcag", "final-llm-wcag", "as above, WCAG 2.2 framework on (secondary)"),
    ("bench-ts-frontend-a11y", "iter2-llm", "iter3-llm", "a04a767 vs 6d5e9d3 (results file: model scores identical)"),
    ("bench-ts-frontend-a11y", "v1.1-iter2-llm", "final-llm", "503b290 vs freestanding v1.1.0 clone, code identical"),
    ("bench-ts-frontend-a11y", "v1.1-iter2-llm-wcag", "final-llm-wcag", "as above, WCAG 2.2 framework on (secondary)"),
]


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    with open(p, "rb") as f:
        return sha256_bytes(f.read())


def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def pct(v):
    return "n/a" if v is None else f"{100 * v:.1f} %"


def frac(n, d):
    return f"{n}/{d}" if d else "—"


# --- the re-score ---------------------------------------------------------------------------------------------------

def dimension_outcomes(entries, results, mapping, tol):
    """The per-dimension matcher runs of `cai_bench.scoring.by_dimension`, keeping the individual outcomes."""
    dims = []
    for e in entries:
        cs = entry_concepts(e) if e["label"] != "score-band" else []
        for c in (cs if cs != STAR else []):
            for d in mapping.dimensions_of_concept(c):
                if d not in dims:
                    dims.append(d)
    results = [r for r in results if not r.get("ignoreReason")]
    for r in results:
        if r["dimension"] not in dims:
            dims.append(r["dimension"])
    out = {}
    for d in dims:
        ents = [e for e in entries if e["label"] != "score-band"
                and (entry_concepts(e) == STAR or any(d in mapping.dimensions_of_concept(c) for c in entry_concepts(e)))]
        rs = [r for r in results if r["dimension"] == d]
        m = Matcher(ents, rs, tol, mapping)
        run = m.run()
        out[d] = {"entries": {e["id"]: (e, run["entries"][e["id"]]) for e in m.entries},
                  "results": [(r, o) for r, o in zip(rs, run["results"])]}
    return out


def rescore(repo, workspace, mapping):
    name, tag = repo["name"], repo["tag"]
    raw = subprocess.run(["git", "-C", os.path.join(workspace, name), "show", f"{tag}:benchmark/answer-key.json"],
                         capture_output=True, check=True).stdout
    if sha256_bytes(raw) != repo["keySha256"]:
        raise SystemExit(f"{name}: key at {tag} has sha256 {sha256_bytes(raw)}, final-scores says {repo['keySha256']}")
    key = json.loads(raw)
    scan = os.path.join(workspace, repo["scan"]["dir"])
    sarif_path = os.path.join(scan, "report.sarif")
    if sha256_file(sarif_path) != repo["scan"]["sarifSha256"]:
        raise SystemExit(f"{name}: {sarif_path} is not the scored SARIF (sha256 differs from final-scores.json)")
    sarif = load(sarif_path)
    scores = scorecard_scores(load(os.path.join(scan, "scorecard.json")))
    results = read_results(sarif, ())
    report = score(key, results, mapping, scores)
    for k in ("tp", "fn", "trapFp", "trapTn", "results", "noise", "redundant", "uncovered", "fileLevelTp"):
        if report["summary"][k] != repo["summary"][k]:
            raise SystemExit(f"{name}: re-score {k}={report['summary'][k]} != final-scores {repo['summary'][k]}")
    got = {d: {k: v for k, v in row.items()} for d, row in report["dimensions"].items()}
    for row in repo["dimensions"]:
        g = got.get(row["id"])
        if g is None or any(g[k] != row[k] for k in ("tp", "fn", "trapFp", "trapTn", "results", "noise")):
            raise SystemExit(f"{name}: dimension {row['id']} re-scores differently from final-scores.json")
    if [b["outcome"] for b in report["scoreBands"]] != [b["outcome"] for b in repo["scoreBands"]]:
        raise SystemExit(f"{name}: score bands re-score differently")
    tol = line_tolerance(key)
    return {"key": key, "report": report, "results": results,
            "dims": dimension_outcomes(key["entries"], results, mapping, tol)}


# --- mechanisms ------------------------------------------------------------------------------------------------------

def fn_mechanism_index():
    idx = {}
    for mid, _title, sites in FN_MECHANISMS:
        for repo, ids in sites.items():
            for i in ids:
                idx[(repo, i)] = mid
    return idx


def backlog_items(draft_path, filed_path):
    if not (draft_path and filed_path and os.path.exists(draft_path) and os.path.exists(filed_path)):
        return None
    draft, filed = load(draft_path), load(filed_path)["filed"]
    items = []
    for i, it in enumerate(draft):
        m = re.search(r"SITES \((\d+) rows?, (\d+) repositor", it["evidence"])
        dims = [d.strip() for d in re.split(r"[,/ ]+", it.get("dimensions") or it["dimension"]) if d.strip()]
        items.append({"backlogId": filed.get(str(i)), "dimension": it["dimension"], "dimensions": dims,
                      "language": it["language"], "sites": int(m.group(1)) if m else None,
                      "repositories": int(m.group(2)) if m else None,
                      "mechanism": it["evidence"].split("\n")[0].replace("MECHANISM: ", "").strip()})
    items.sort(key=lambda n: (-(n["sites"] or 0), -(n["repositories"] or 0), n["dimension"]))
    return items


def verdict_index(results_dir, name):
    path = os.path.join(results_dir, name + ".json")
    by_site, by_msg = {}, {}
    for v in load(path).get("verdicts", []):
        by_site[(v["ruleId"], v.get("file"), v.get("line"))] = v["class"]  # the latest verdict wins
        by_msg[(v["ruleId"], (v.get("message") or "")[:120])] = v["class"]
    return by_site, by_msg


def short(text, n=150):
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= n else text[:n - 1].rstrip() + "…"


# --- model non-determinism -------------------------------------------------------------------------------------------

def nondeterminism(workspace, llm_dims):
    rows = []
    for repo, a, b, why in REPEAT_PAIRS:
        pa = os.path.join(workspace, "_scans", repo, a, repo)
        pb = os.path.join(workspace, "_scans", repo, b, repo)
        if not (os.path.exists(os.path.join(pa, "scorecard.json")) and os.path.exists(os.path.join(pb, "scorecard.json"))):
            rows.append({"repo": repo, "a": a, "b": b, "why": why, "missing": True})
            continue
        sa, sb = scorecard_scores(load(os.path.join(pa, "scorecard.json"))), scorecard_scores(load(os.path.join(pb, "scorecard.json")))

        def llm_rows(p):
            c = collections.Counter()
            for run in load(os.path.join(p, "report.sarif")).get("runs", []):
                for r in run.get("results", []):
                    if r.get("ruleId") in llm_dims:
                        c[r["ruleId"]] += 1
            return c
        ra, rb = llm_rows(pa), llm_rows(pb)
        dims = sorted({d for d in llm_dims if d in sa or d in sb}, key=natural)
        rows.append({"repo": repo, "a": a, "b": b, "why": why,
                     "sarifIdentical": sha256_file(os.path.join(pa, "report.sarif")) == sha256_file(os.path.join(pb, "report.sarif")),
                     "scores": {d: [sa.get(d), sb.get(d)] for d in dims},
                     "changed": {d: [sa.get(d), sb.get(d)] for d in dims if sa.get(d) != sb.get(d)},
                     "llmRows": [sum(ra.values()), sum(rb.values())],
                     "llmRowsByDim": {d: [ra.get(d, 0), rb.get(d, 0)] for d in sorted(set(ra) | set(rb), key=natural)}})
    return rows


# --- build -----------------------------------------------------------------------------------------------------------

def build(a):
    final = load(os.path.join(HERE, "final-scores.json"))
    summary = load(os.path.join(HERE, "SUMMARY.json"))
    matrix = load(os.path.join(ROOT, "coverage", "matrix.json"))
    mapping_doc = load(os.path.join(ROOT, "mappings", "watchdog.json"))
    mapping = Mapping(mapping_doc)
    rows = {r["id"]: r for r in matrix["rows"]}
    lens_order, lens_labels = [], {}
    for r in matrix["rows"]:
        if r["lens"] not in lens_labels:
            lens_order.append(r["lens"])
            lens_labels[r["lens"]] = r["lensLabel"]
    catalog_note = "not checked (catalog not found)"
    if a.catalog and os.path.exists(a.catalog):
        cat = load(a.catalog)
        cat_lens = {d["id"]: d["lens"] for d in cat["dimensions"]}
        diff = sorted(d for d in set(cat_lens) | set(rows) if cat_lens.get(d) != (rows.get(d) or {}).get("lens"))
        if diff:
            raise SystemExit(f"coverage/matrix.json and the catalog disagree on the lens of {diff}")
        lens_order = [l["key"] for l in cat["lenses"]]
        lens_labels = {l["key"]: l["label"] for l in cat["lenses"]}
        catalog_note = f"{cat['rubricVersion']}: {len(cat_lens)} dimensions, lenses identical to coverage/matrix.json"
    dim_lens = {d: r["lens"] for d, r in rows.items()}
    llm_dims = {d for d, r in rows.items() if r["evaluator"] == "llm"}

    agg = aggregate(final, mapping, dim_lens)
    fn_idx = fn_mechanism_index()
    backlog = backlog_items(a.backlog_draft, a.backlog_filed)

    # in-process re-score of every repository
    extra = collections.defaultdict(lambda: {
        "noiseKinds": collections.Counter(), "noiseVerdicts": collections.Counter(),
        "missGlobal": collections.Counter(), "foundElsewhere": collections.Counter(), "fnSites": [],
        "sarifRows": 0, "sarifRowsByLang": collections.Counter()})
    loc_none = located = 0
    repo_rows = []
    for repo in final["repos"]:
        rs = rescore(repo, a.workspace, mapping)
        lang = repo["languages"][0]
        global_entries = {e["id"]: e for e in rs["report"]["entries"]}
        by_site, by_msg = verdict_index(HERE, repo["name"])
        for r in rs["results"]:
            if r.get("ruleId"):
                extra[r["ruleId"]]["sarifRows"] += 1
                extra[r["ruleId"]]["sarifRowsByLang"][lang] += 1
            if r.get("locationSource") == "none":
                loc_none += 1
            else:
                located += 1
        for d, run in rs["dims"].items():
            x = extra[d]
            for r, o in run["results"]:
                if o["outcome"] in NOISE_KINDS:
                    x["noiseKinds"][o["outcome"]] += 1
                    v = by_msg.get((r["ruleId"], (r.get("message") or "")[:120]))
                    if v is None and r["file"] is not None and r.get("locationSource") == "sarif":
                        v = by_site.get((r["ruleId"], r["file"], r["line"]))
                    x["noiseVerdicts"][v or "not triaged"] += 1
            for eid, (e, o) in run["entries"].items():
                if e["label"] != "must-fire" or o["outcome"] != "FN":
                    continue
                g = global_entries[eid]
                if g["outcome"] == "TP":
                    by = sorted({rs["results"][h["index"]]["dimension"] for h in g["results"]}, key=natural)
                    x["foundElsewhere"][",".join(by)] += 1
                else:
                    mech = fn_idx.get((repo["name"], eid))
                    if mech is None:
                        raise SystemExit(f"{repo['name']} {eid}: missed by the run but has no FN mechanism")
                    x["missGlobal"][mech] += 1
                    x["fnSites"].append({"repo": repo["name"], "id": eid, "concept": e["concept"],
                                         "file": e.get("file"), "mechanism": mech})
        s = metrics({k: repo["summary"][k] for k in ("tp", "fn", "trapFp", "trapTn", "fp", "tn", "results", "noise",
                                                     "redundant", "fileLevelTp")})
        bands = collections.Counter(b["outcome"] for b in repo["scoreBands"])
        repo_rows.append({"name": repo["name"], "tag": repo["tag"], "commit": repo["commit"],
                          "keySha256": repo["keySha256"], "sarifSha256": repo["scan"]["sarifSha256"],
                          "scanDir": repo["scan"]["dir"], "language": lang, "family": repo["family"],
                          "bands": {o: bands.get(o, 0) for o in ("in", "out", "unscored")}, **s})

    # per dimension: every in-scope dimension of the catalog, plus any other dimension the run produced a row for
    by_dim = {}
    for d in sorted(set(rows) | set(agg["byDimension"]), key=natural):
        r = rows.get(d)
        b = agg["byDimension"].get(d)
        if (r is None or r["status"] != "in-scope") and b is None:
            continue
        x = extra.get(d) or extra[d]
        labelled = sorted({c["repo"] for c in (r or {}).get("coverage", []) if c.get("labels")})
        noise_items = []
        if backlog is not None:
            noise_items = [{"backlogId": n["backlogId"], "sites": n["sites"], "repositories": n["repositories"],
                            "mechanism": n["mechanism"]} for n in backlog if n["dimension"] == d]
        entry = {
            "name": (r or {}).get("name", d), "lens": dim_lens.get(d, NO_RULE),
            "status": (r or {}).get("status", "in-scope" if d == NO_RULE else "unknown"),
            "evaluator": (r or {}).get("evaluator"), "kind": (r or {}).get("kind"),
            "reposLabelling": labelled,
            "reposMeasuring": (b or {}).get("repos", []),
            "all": (b or {}).get("all") or metrics({}),
            "csharp": (b or {}).get("csharp") or metrics({}),
            "typescript": (b or {}).get("typescript") or metrics({}),
            "noiseKinds": {k: x["noiseKinds"].get(k, 0) for k in NOISE_KINDS},
            "noiseVerdicts": dict(x["noiseVerdicts"].most_common()),
            "fnMissedByRun": sum(x["missGlobal"].values()),
            "fnFoundByOtherDimension": dict(x["foundElsewhere"].most_common()),
            "missMechanisms": dict(x["missGlobal"].most_common()),
            "fnSites": x["fnSites"],
            "noiseBacklog": noise_items,
            "sarifRows": x["sarifRows"], "sarifRowsByLanguage": dict(x["sarifRowsByLang"]),
            "bands": (b or {}).get("bands", []),
            "bandCounts": (b or {}).get("bandCounts") or {"in": 0, "out": 0, "unscored": 0},
        }
        if d == NO_RULE:
            un = collections.Counter()
            for repo in final["repos"]:
                for c in repo["concepts"]:
                    if c["id"] not in ("*", "(unmapped)") and not mapping.dimensions_of_concept(c["id"]) and c["fn"]:
                        un[c["id"]] += c["fn"]
            entry["unmappedConcepts"] = dict(sorted(un.items()))
            entry["fnMissedByRun"] = entry["all"]["fn"]  # no dimension can find these: every one is a run FN
            entry["missMechanisms"] = {"no-rule-for-concept": entry["all"]["fn"]}
        if sum(entry["noiseKinds"].values()) != entry["all"]["noise"]:
            raise SystemExit(f"{d}: noise kinds {entry['noiseKinds']} do not add up to {entry['all']['noise']}")
        by_dim[d] = entry

    by_lens = {}
    for L in lens_order + [NO_RULE]:
        lb = agg["byLens"].get(L)
        dims_in = [d for d, e in by_dim.items() if e["lens"] == L and e["status"] == "in-scope"]
        by_lens[L] = {"label": lens_labels.get(L, L), "dimensionsInScope": len(dims_in),
                      "dimensionsWithPlants": sum(1 for d in dims_in if by_dim[d]["all"]["tp"] + by_dim[d]["all"]["fn"]),
                      "dimensionsMeasured": sum(1 for d in dims_in if by_dim[d]["reposMeasuring"]),
                      **({k: lb[k] for k in ("all", "csharp", "typescript", "bands", "dimensions")} if lb else
                         {"all": metrics({}), "csharp": metrics({}), "typescript": metrics({}),
                          "bands": {"in": 0, "out": 0, "unscored": 0}, "dimensions": []})}

    # reconciliation with SUMMARY.json
    t = agg["totals"]
    st = summary["totals"]
    recon = []
    for k in ("tp", "fn", "trapFp", "trapTn", "results", "noise", "fileLevelTp"):
        recon.append({"what": f"totals.{k}", "baseline": t[k], "summary": st[k], "ok": t[k] == st[k]})
    for lang, lab in (("csharp", "C#"), ("typescript", "TypeScript")):
        for k in ("tp", "fn", "trapTn", "trapFp", "noise", "results"):
            recon.append({"what": f"{lang}.{k}", "baseline": agg["byLanguage"][lang][k],
                          "summary": summary["byLanguage"][lab][k],
                          "ok": agg["byLanguage"][lang][k] == summary["byLanguage"][lab][k]})
    dim_sum = collections.Counter()
    for d, e in by_dim.items():
        for k in ("tp", "fn", "trapTn", "trapFp", "results", "noise"):
            dim_sum[k] += e["all"][k]
    lens_sum = collections.Counter()
    for L, e in by_lens.items():
        for k in ("tp", "fn", "trapTn", "trapFp", "results", "noise"):
            lens_sum[k] += e["all"][k]
    band_tot = collections.Counter(b["outcome"] for r in final["repos"] for b in r["scoreBands"])
    recon.append({"what": "score bands in/out/unscored", "baseline": [band_tot["in"], band_tot["out"], band_tot["unscored"]],
                  "summary": [st["scoreBands"]["contained"].get(o, 0) for o in ("in", "out", "unscored")],
                  "ok": [band_tot["in"], band_tot["out"], band_tot["unscored"]] ==
                        [st["scoreBands"]["contained"].get(o, 0) for o in ("in", "out", "unscored")]})
    if not all(x["ok"] for x in recon):
        raise SystemExit("does not reconcile with SUMMARY.json: " + json.dumps([x for x in recon if not x["ok"]]))

    zero = sorted((d for d, e in by_dim.items() if e["all"]["fn"] and not e["all"]["tp"]
                   and e["status"] == "in-scope" and d != NO_RULE),
                  key=lambda d: (-by_dim[d]["fnMissedByRun"], -by_dim[d]["all"]["fn"], natural(d)))
    never = sorted((d for d, e in by_dim.items() if e["status"] == "in-scope" and d != NO_RULE and not e["sarifRows"]),
                   key=natural)
    def wkey(d):
        e = by_dim[d]
        return (e["all"]["recall"], -e["fnMissedByRun"], -e["all"]["fn"])
    ranked = sorted((d for d, e in by_dim.items() if e["all"]["tp"] + e["all"]["fn"]
                     and e["status"] == "in-scope" and d != NO_RULE), key=lambda d: (wkey(d), natural(d)))
    worst = [d for d in ranked if wkey(d) <= wkey(ranked[min(9, len(ranked) - 1)])]
    out = {
        "baseline": f"Watchdog — scanner-benchmark iteration 1 baseline ({DATE})",
        "date": DATE,
        "instrument": final["instrument"],
        "engine": {"repo": "kennel", "commit": "6a05dfb6c", "rubric": "rubric-2026.10.1",
                   "image": "codehealth-analyzer:train-src-89d1e8def87553cc", "mode": "contained",
                   "configuration": "default"},
        "harness": final["harness"], "mapping": final["mapping"],
        "inputs": {"final-scores.json": sha256_file(os.path.join(HERE, "final-scores.json")),
                   "SUMMARY.json": sha256_file(os.path.join(HERE, "SUMMARY.json")),
                   "mappings/watchdog.json": sha256_file(os.path.join(ROOT, "mappings", "watchdog.json")),
                   "coverage/matrix.json": sha256_file(os.path.join(ROOT, "coverage", "matrix.json")),
                   "catalog": catalog_note},
        "definitions": {
            "dimension": "sum over repositories of the harness's per-dimension rows (matching re-run within the "
                         "dimension); a plant counts under every dimension its concept maps to, so rows overlap",
            "lens": "plants/traps once per lens from the per-concept rows (found = TP of the whole run); results and "
                    "noise = sum of the lens's dimension rows (every result has one dimension)",
            "noiseKinds": "trap-fp = on a must-not-fire trap; clean-fp = in a certified-clean region; na-fp = a concept "
                          "the key declares not applicable; unmatched-fp = a covered concept's result matching no entry",
            "fnMissedByRun": "dimension-level FNs that no dimension found (global FN); the rest were found by another "
                             "dimension (fnFoundByOtherDimension)",
        },
        "dimensionLens": dim_lens, "lensOrder": lens_order + [NO_RULE],
        "lensLabels": dict(lens_labels, **{NO_RULE: NO_RULE}),
        "totals": dict(t, repositories=len(final["repos"]),
                       scoreBands={o: band_tot.get(o, 0) for o in ("in", "out", "unscored")},
                       tpMatchedBy=summary["totals"].get("tpMatchedBy"),
                       resultsWithoutLocation=loc_none, resultsWithLocation=located),
        "byLanguage": agg["byLanguage"],
        "byFamily": {k: v for k, v in summary["byFamily"].items()},
        "repos": repo_rows,
        "byLens": by_lens,
        "byDimension": by_dim,
        "zeroRecallDimensions": zero,
        "worstByRecall": worst,
        "neverFiringDimensions": never,
        "falseNegativeMechanisms": [{k: m[k] for k in ("id", "title", "count", "languages")}
                                    for m in summary["falseNegativeMechanisms"]],
        "noiseBacklog": backlog,
        "verdictClasses": summary.get("verdictClasses"),
        "modelNonDeterminism": nondeterminism(a.workspace, llm_dims),
        "reconciliation": {"withSummary": recon,
                           "dimensionRowSums": dict(dim_sum), "lensRowSums": dict(lens_sum),
                           "note": "dimension rows overlap (a plant counts under every dimension its concept maps "
                                   "to); lens rows overlap where a concept's dimensions sit in two lenses; results "
                                   "and noise partition exactly"},
    }
    return out


# --- markdown --------------------------------------------------------------------------------------------------------

def slug(lens_key):
    return "no-rule" if lens_key == NO_RULE else lens_key


def md_tables(b):
    T = {}
    L = []

    def flush(name):
        T[name] = "\n".join(L)
        L.clear()

    t = b["totals"]
    L.append("| Slice | Repos | Recall TP/(TP+FN) | Trap resistance | Noise share | File-level recall |")
    L.append("|---|---|---|---|---|---|")
    L.append(f"| **All** | {t['repositories']} | **{t['tp']}/{t['tp'] + t['fn']} ({pct(t['recall'])})** | "
             f"**{t['trapTn']}/{t['trapTn'] + t['trapFp']} ({pct(t['trapResistance'])})** | "
             f"**{t['noise']}/{t['results']} ({pct(t['noiseShare'])})** | {pct(t['fileLevelRecall'])} |")
    for lang in LANGS:
        x = b["byLanguage"][lang]
        n = sum(1 for r in b["repos"] if r["language"] == lang)
        L.append(f"| {LANG_LABEL[lang]} | {n} | {x['tp']}/{x['tp'] + x['fn']} ({pct(x['recall'])}) | "
                 f"{x['trapTn']}/{x['trapTn'] + x['trapFp']} ({pct(x['trapResistance'])}) | "
                 f"{x['noise']}/{x['results']} ({pct(x['noiseShare'])}) | {pct(x['fileLevelRecall'])} |")
    for fam, x in b["byFamily"].items():
        n = sum(1 for r in b["repos"] if r["family"] == fam)
        L.append(f"| family: {fam} | {n} | {x['tp']}/{x['tp'] + x['fn']} ({pct(x['recall'])}) | "
                 f"{x['trapTn']}/{x['trapTn'] + x['trapFp']} ({pct(x['trapResistance'])}) | "
                 f"{x['noise']}/{x['results']} ({pct(x['noiseShare'])}) | {pct(x['fileLevelRecall'])} |")
    flush("headline")

    L.append("| Lens | Dims in scope / with plants | Planted | TP | FN | Recall | Traps held / total | Trap resistance "
             "| Results | Noise | Noise share | File-level recall | Bands in / out / unscored |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for key in b["lensOrder"]:
        e = b["byLens"][key]
        x = e["all"]
        lbl = e["label"] if key != NO_RULE else "(no scanner rule) ‡"
        dims = f"{e['dimensionsInScope']} / {e['dimensionsWithPlants']}" if key != NO_RULE else "—"
        L.append(f"| **{lbl}** | {dims} | {x['tp'] + x['fn']} | {x['tp']} | "
                 f"{x['fn']} | **{pct(x['recall'])}** | {x['trapTn']} / {x['trapTn'] + x['trapFp']} | "
                 f"{pct(x['trapResistance'])} | {x['results']} | {x['noise']} | {pct(x['noiseShare'])} | "
                 f"{pct(x['fileLevelRecall'])} | {e['bands']['in']} / {e['bands']['out']} / {e['bands']['unscored']} |")
    flush("per-lens")

    L.append("| Lens | C# recall | C# traps held | C# noise | TS recall | TS traps held | TS noise |")
    L.append("|---|---|---|---|---|---|---|")
    for key in b["lensOrder"]:
        e = b["byLens"][key]
        cells = []
        for lang in LANGS:
            x = e[lang]
            cells += [f"{frac(x['tp'], x['tp'] + x['fn'])} ({pct(x['recall'])})" if x['tp'] + x['fn'] else "—",
                      f"{frac(x['trapTn'], x['trapTn'] + x['trapFp'])} ({pct(x['trapResistance'])})"
                      if x['trapTn'] + x['trapFp'] else "—",
                      f"{frac(x['noise'], x['results'])} ({pct(x['noiseShare'])})" if x['results'] else "—"]
        L.append(f"| {e['label'] if key != NO_RULE else '(no scanner rule) ‡'} | " + " | ".join(cells) + " |")
    flush("per-lens-language")

    for key in b["lensOrder"]:
        dims = [(d, e) for d, e in b["byDimension"].items() if e["lens"] == key]
        if not dims:
            continue
        L.append("| Dim | Name | Repos | TP/planted | Recall | FN missed by run / found by other dim | Traps held | "
                 "Trap res. | Results | Noise trap/clean/NA/unl | Noise share | File rec. | Bands in/out/uns | "
                 "C# TP/planted | TS TP/planted |")
        L.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for d, e in dims:
            x, cs, ts = e["all"], e["csharp"], e["typescript"]
            nk = e["noiseKinds"]
            planted = x["tp"] + x["fn"]
            fr = pct(x["fileLevelRecall"]) if planted and x["fileLevelTp"] != x["tp"] else ("=" if planted else "—")
            name = e["name"] + (" (out of scope)" if e["status"] == "out-of-scope" else "")
            if e["evaluator"] == "llm":
                name += " ◆"
            reps = len(set(e["reposLabelling"]) | set(e["reposMeasuring"]))
            elsewhere = sum(e["fnFoundByOtherDimension"].values())
            bc = e["bandCounts"]
            L.append(
                f"| {d} | {name} | {reps or '—'} | {frac(x['tp'], planted)} | {pct(x['recall']) if planted else '—'} | "
                f"{(str(e['fnMissedByRun']) + ' / ' + str(elsewhere)) if x['fn'] else '—'} | "
                f"{frac(x['trapTn'], x['trapTn'] + x['trapFp'])} | {pct(x['trapResistance']) if x['trapTn'] + x['trapFp'] else '—'} | "
                f"{x['results']} | {nk['trap-fp']}/{nk['clean-fp']}/{nk['na-fp']}/{nk['unmatched-fp']} | "
                f"{pct(x['noiseShare']) if x['results'] else '—'} | {fr} | "
                f"{(str(bc['in']) + '/' + str(bc['out']) + '/' + str(bc['unscored'])) if sum(bc.values()) else '—'} | "
                f"{frac(cs['tp'], cs['tp'] + cs['fn'])} | {frac(ts['tp'], ts['tp'] + ts['fn'])} |")
        flush(f"dims-{slug(key)}")
        mech = []
        for d, e in dims:
            miss = ""
            if e["missMechanisms"]:
                top, n = next(iter(e["missMechanisms"].items()))
                miss = f"{FN_SHORT.get(top, top)} ({n} of {e['fnMissedByRun']})"
                if len(e["missMechanisms"]) > 1:
                    miss += f"; +{len(e['missMechanisms']) - 1} other"
            if e["fnFoundByOtherDimension"]:
                fe = list(e["fnFoundByOtherDimension"].items())
                other = ", ".join(f"{k} {v}" for k, v in fe[:4]) + (f", +{len(fe) - 4} more" if len(fe) > 4 else "")
                miss = (miss + "; " if miss else "") + f"found instead by {other}"
            noise = ""
            if e["noiseBacklog"]:
                top = e["noiseBacklog"][0]
                noise = f"{short(top['mechanism'], 140)} (`{top['backlogId'][:13]}…`, {top['sites']} sites)"
                if len(e["noiseBacklog"]) > 1:
                    noise += f"; +{len(e['noiseBacklog']) - 1} more item(s)"
            elif e["all"]["noise"]:
                v = ", ".join(f"{k} {n}" for k, n in e["noiseVerdicts"].items())
                noise = f"no backlog item (final-scan noise rows judged: {v})"
            if e.get("unmappedConcepts"):
                miss = "concepts no Watchdog rule maps: " + ", ".join(
                    f"{c} {n}" for c, n in e["unmappedConcepts"].items())
            if miss or noise:
                mech.append(f"| {d} | {miss or '—'} | {noise or '—'} |")
        if mech:
            L.append("| Dim | Main miss mechanism | Main noise mechanism |")
            L.append("|---|---|---|")
            L.extend(mech)
        flush(f"mech-{slug(key)}")

    L.append("| Repository | Tag | Commit | Lang | Family | Recall | Traps held | Noise | File-level recall | "
             "Bands in/out/uns |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in b["repos"]:
        L.append(f"| {r['name']} | {r['tag']} | `{r['commit'][:7]}` | {LANG_LABEL[r['language']]} | {r['family']} | "
                 f"{r['tp']}/{r['tp'] + r['fn']} ({pct(r['recall'])}) | "
                 f"{r['trapTn']}/{r['trapTn'] + r['trapFp']} ({pct(r['trapResistance'])}) | "
                 f"{r['noise']}/{r['results']} ({pct(r['noiseShare'])}) | {pct(r['fileLevelRecall'])} | "
                 f"{r['bands']['in']}/{r['bands']['out']}/{r['bands']['unscored']} |")
    flush("per-repo")

    L.append("| Dim | Lens | Name | Planted | Missed by run | Found by another dimension | Main miss mechanism |")
    L.append("|---|---|---|---|---|---|---|")
    for d in b["zeroRecallDimensions"]:
        e = b["byDimension"][d]
        top = next(iter(e["missMechanisms"]), None)
        L.append(f"| {d} | {b['lensLabels'].get(e['lens'], e['lens'])} | {e['name']} | {e['all']['fn']} | "
                 f"{e['fnMissedByRun']} | {sum(e['fnFoundByOtherDimension'].values())} | "
                 f"{FN_SHORT.get(top, top) if top else '—'} |")
    flush("zero-recall")

    L.append("| # | Dim | Name | Lens | TP/planted | Recall | Missed by run | Found by another dim |")
    L.append("|---|---|---|---|---|---|---|---|")
    for i, d in enumerate(b["worstByRecall"], 1):
        e = b["byDimension"][d]
        x = e["all"]
        L.append(f"| {i} | {d} | {e['name']} | {b['lensLabels'].get(e['lens'], e['lens'])} | {x['tp']}/{x['tp'] + x['fn']} | "
                 f"{pct(x['recall'])} | {e['fnMissedByRun']} | {sum(e['fnFoundByOtherDimension'].values())} |")
    flush("worst-10")

    by_lens = collections.defaultdict(list)
    for d in b["neverFiringDimensions"]:
        by_lens[b["byDimension"][d]["lens"]].append(d)
    L.append("| Lens | Dimensions with no SARIF row in any of the 25 final contained scans |")
    L.append("|---|---|")
    for key in b["lensOrder"]:
        if by_lens.get(key):
            items = []
            for d in by_lens[key]:
                e = b["byDimension"][d]
                tag = []
                if e["evaluator"] == "llm":
                    tag.append("◆")
                if e["all"]["tp"] + e["all"]["fn"]:
                    tag.append(f"{e['all']['fn']} plant(s) missed")
                items.append(d + (f" ({', '.join(tag)})" if tag else ""))
            L.append(f"| {b['lensLabels'][key]} ({len(by_lens[key])}) | {', '.join(items)} |")
    flush("never-firing")

    L.append("| FNs | Mechanism | Languages |")
    L.append("|---|---|---|")
    for m in b["falseNegativeMechanisms"]:
        L.append(f"| {m['count']} | {m['title']} | {', '.join(m['languages'])} |")
    flush("fn-mechanisms")

    if b["noiseBacklog"]:
        L.append("| # | Sites | Repos | Dim | Lang | Mechanism | Backlog id |")
        L.append("|---|---|---|---|---|---|---|")
        for i, n in enumerate(b["noiseBacklog"], 1):
            L.append(f"| {i} | {n['sites']} | {n['repositories']} | {n['dimension']} | {n['language']} | "
                     f"{short(n['mechanism'], 200)} | `{n['backlogId']}` |")
        flush("noise-backlog")

    L.append("| Dim | Lens | Results | Noise | on traps | in clean regions | on N/A concepts | unlabelled | "
             "Final-scan noise rows as judged in authoring |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    noisy = sorted((d for d, e in b["byDimension"].items() if e["all"]["noise"]),
                   key=lambda d: (-b["byDimension"][d]["all"]["noise"], natural(d)))
    for d in noisy:
        e = b["byDimension"][d]
        nk = e["noiseKinds"]
        v = ", ".join(f"{k} {n}" for k, n in e["noiseVerdicts"].items())
        L.append(f"| {d} | {b['lensLabels'].get(e['lens'], e['lens'])} | {e['all']['results']} | {e['all']['noise']} | "
                 f"{nk['trap-fp']} | {nk['clean-fp']} | {nk['na-fp']} | {nk['unmatched-fp']} | {v} |")
    flush("noise-by-dim")

    L.append("| Dim | Name | In | Out | Unscored | Scores (repository: score, band → outcome) |")
    L.append("|---|---|---|---|---|---|")
    for d, e in b["byDimension"].items():
        if not e["bands"]:
            continue
        parts = []
        for x in e["bands"]:
            sc = [s["score"] for s in x["scores"] if s["source"] == d] or [s["score"] for s in x["scores"]]
            parts.append(f"{x['repo'].replace('bench-', '').replace('estate-quellbrook-', 'qb-')}: "
                         f"{sc[0] if sc else '–'} [{x['band'][0]}–{x['band'][1]}] {x['outcome']}")
        bc = e["bandCounts"]
        L.append(f"| {d} | {e['name']}{' ◆' if e['evaluator'] == 'llm' else ''} | {bc['in']} | {bc['out']} | "
                 f"{bc['unscored']} | {'; '.join(parts)} |")
    flush("bands")

    L.append("| Repository | Pass A → pass B | Same code because | SARIF identical | Model-judged scores that moved | "
             "Model-judged rows A → B |")
    L.append("|---|---|---|---|---|---|")
    for r in b["modelNonDeterminism"]:
        if r.get("missing"):
            L.append(f"| {r['repo']} | {r['a']} → {r['b']} | {r['why']} | (pass missing) | | |")
            continue
        moved = ", ".join(f"{d} {v[0]}→{v[1]}" for d, v in r["changed"].items()) or "none of " + str(len(r["scores"]))
        L.append(f"| {r['repo']} | {r['a']} → {r['b']} | {r['why']} | {'yes' if r['sarifIdentical'] else 'no'} | "
                 f"{moved} | {r['llmRows'][0]} → {r['llmRows'][1]} |")
    flush("nondeterminism")

    L.append("| Check | Baseline | SUMMARY.json | Reconciles |")
    L.append("|---|---|---|---|")
    for x in b["reconciliation"]["withSummary"]:
        L.append(f"| {x['what']} | {x['baseline']} | {x['summary']} | {'yes' if x['ok'] else '**NO**'} |")
    ds, ls = b["reconciliation"]["dimensionRowSums"], b["reconciliation"]["lensRowSums"]
    L.append(f"| Σ dimension rows: TP / FN / traps held / caught / results / noise | {ds['tp']} / {ds['fn']} / "
             f"{ds['trapTn']} / {ds['trapFp']} / {ds['results']} / {ds['noise']} | {t['tp']} / {t['fn']} / {t['trapTn']} / "
             f"{t['trapFp']} / {t['results']} / {t['noise']} | results and noise yes; plants/traps overlap by design |")
    L.append(f"| Σ lens rows: TP / FN / traps held / caught / results / noise | {ls['tp']} / {ls['fn']} / "
             f"{ls['trapTn']} / {ls['trapFp']} / {ls['results']} / {ls['noise']} | {t['tp']} / {t['fn']} / {t['trapTn']} / "
             f"{t['trapFp']} / {t['results']} / {t['noise']} | results and noise yes; plants/traps overlap where a "
             f"concept spans two lenses |")
    flush("reconciliation")
    return T


def update_doc(path, tables, check=False):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    seen = set()

    def repl(m):
        name = m.group(1)
        if name not in tables:
            raise SystemExit(f"{path}: unknown table block '{name}'")
        seen.add(name)
        return f"<!-- BEGIN baseline:{name} -->\n{tables[name]}\n<!-- END baseline:{name} -->"
    new = re.sub(r"<!-- BEGIN baseline:([\w-]+) -->.*?<!-- END baseline:\1 -->", repl, text, flags=re.S)
    missing = sorted(set(tables) - seen)
    if missing:
        raise SystemExit(f"{path}: no block for table(s) {missing}")
    if check:
        return new == text
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    return True


def main(argv=None):
    ws = os.path.dirname(ROOT)
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--workspace", default=ws, help="directory holding the benchmark clones and _scans/")
    ap.add_argument("--catalog", default=os.path.join(os.path.dirname(ws), "kennel.canine.dev", "engine", "rubrics",
                                                      "rubric-catalog-snapshot.json"))
    ap.add_argument("--backlog-draft", default=os.path.join(ws, "_scans", "backlog-draft.json"))
    ap.add_argument("--backlog-filed", default=os.path.join(ws, "_scans", "backlog-filed.json"))
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--update-doc", help="rewrite the <!-- BEGIN/END baseline:NAME --> blocks of this markdown file")
    ap.add_argument("--check", action="store_true",
                    help="rebuild in memory; exit 1 when --out (or --update-doc's file) differs from the rebuild")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    b = build(a)
    text = json.dumps(b, indent=1, ensure_ascii=False) + "\n"
    tables = md_tables(b)
    if a.check:
        ok = os.path.exists(a.out) and open(a.out, encoding="utf-8").read() == text
        if a.update_doc:
            ok = update_doc(a.update_doc, tables, check=True) and ok
        print("baseline up to date" if ok else "baseline OUT OF DATE")
        return 0 if ok else 1
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text)
    if a.update_doc:
        update_doc(a.update_doc, tables)
    if not a.quiet:
        for name, t in tables.items():
            print(f"<!-- {name} -->\n{t}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
