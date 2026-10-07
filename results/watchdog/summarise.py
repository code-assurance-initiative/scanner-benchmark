"""Aggregate final-scores.json (+ the per-repository results files) into SUMMARY.json.

    python3 results/watchdog/summarise.py [--backlog-draft PATH --backlog-filed PATH] [--markdown]

Reads results/watchdog/final-scores.json (one headline score per registry repository at its latest tag) and every
results/watchdog/<repo>.json (verdicts). Writes results/watchdog/SUMMARY.json; with --markdown also prints the tables
used in SUMMARY.md. The noise-mechanism table needs the backlog draft that the benchmark filed (kept outside this
repository, with the scans); without it that section is omitted from the JSON.

The false-negative mechanisms below are a CURATED classification: every must-fire FN of the final re-score is assigned
to exactly one general mechanism (the reason recorded in its results file, and the "Engine facts" of the authoring
log). The script asserts that the table and the re-score agree, so a changed score cannot silently drift from it.
"""
import argparse
import collections
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

FN_MECHANISMS = [
    ("repo-wide-posture-switch",
     "Repository-wide posture switches: one qualifying site anywhere credits the whole repository, so the defective "
     "site is never itemised (P7, P8, C2, S1, D40, D42, P10, P11, P6)",
     {"bench-csharp-readiness": ["RDY-001", "RDY-004", "RDY-005", "RDY-008", "RDY-010", "RDY-011"],
      "bench-ts-readiness": ["MIG-001", "LIB-001", "LIB-002", "BDD-001", "EGR-001", "ADM-001", "RDY-003"],
      "bench-csharp-maturity-history": ["REL-001"],
      "estate-quellbrook-gateway": ["GW-001"]}),
    ("no-rule-for-concept",
     "No rule for the concept at all (scanner-neutral concepts beyond the reference scanner: unmapped or unevidenced "
     "in the mapping)",
     {"bench-csharp-architecture": ["BLC-001"],
      "bench-csharp-domain-events": ["VOM-001", "DEH-001", "DEH-002", "ESC-001"],
      "bench-ts-frontend-a11y": ["A11Y-010", "A11Y-013", "A11Y-021", "A11Y-022", "A11Y-023", "A11Y-024"],
      "bench-csharp-blazor-a11y": ["BA-010", "BA-013", "BA-018"],
      "bench-ts-domain-privacy": ["CON-001"],
      "bench-ts-readiness": ["RDY-004"],
      "bench-ts-codehealth": ["CH-023"],
      "bench-csharp-codehealth": ["CH-021"],
      "bench-csharp-tests": ["TQ-007"]}),
    ("ts-arm-missing-codehealth",
     "Code-health and test rules with no TypeScript arm (suppressions, commented-out code, empty catch, dead private "
     "code, @deprecated use, catch-rethrow, null dereference, swallowed test failures, mock dominance)",
     {"bench-ts-codehealth": ["CH-010", "CH-013", "CH-014", "CH-015", "CH-018", "CH-022", "CH-026", "CH-047",
                              "CH-048", "CH-049", "CH-050"],
      "bench-ts-readiness": ["RDY-006"]}),
    ("prefix-less-secret",
     "Prefix-less secrets: every vendor-prefixed secret was found, every secret without a vendor prefix was missed "
     "(punctuated Password=, credentials in connection URIs, inline Bearer, unquoted dotenv, .http files, Vite define)",
     {"bench-csharp-security-secrets": ["SEC-005", "SEC-006", "SEC-007", "SEC-013", "SEC-014", "SEC-017"],
      "bench-ts-security-secrets": ["SEC-004", "SEC-005", "SEC-006", "SEC-014", "SEC-016"]}),
    ("injection-taint-in-handler-only",
     "Injection taint confined to the request handler: the tainted value arrives as a method parameter, model-bound "
     "argument, component state or ternary, or passes a function assumed safe (path.join)",
     {"bench-csharp-security-injection": ["CMD-001", "SSRF-001"],
      "bench-ts-security-injection": ["SQL-001", "SQL-002", "CMD-001", "PATH-001", "XXE-001", "CODE-001",
                                      "PROTO-001", "REDIR-001"],
      "bench-ts-frontend-a11y": ["A11Y-016"]}),
    ("injection-sink-without-rule",
     "Injection sink or library with no rule in the baked packs (Dapper, EF FromSqlRaw, Newtonsoft TypeNameHandling, "
     "ContentResult XSS, Redirect, Regex without timeout, MongoDB filters, dynamic RegExp, log injection, Blazor "
     "MarkupString)",
     {"bench-csharp-security-injection": ["SQL-001", "SQL-002", "DESER-001", "XSS-001", "REDIR-001", "REDOS-001"],
      "bench-ts-security-injection": ["NOSQL-001", "REDOS-001", "LOG-001"],
      "bench-csharp-blazor-a11y": ["BA-019"]}),
    ("shallow-heuristic",
     "Pattern recognisers too shallow for the defect's shape (.Result, Assert.True(true), WarningsNotAsErrors, eslint "
     "config off-switches, Error('Not implemented'), hollow methods, density bars, bare floating promises, inert "
     "options, undrained stderr, vitest test without expect, truncation loops)",
     {"bench-csharp-codehealth": ["CH-023", "CH-034", "CH-049"],
      "bench-csharp-tests": ["TQ-002"],
      "bench-ts-codehealth": ["CH-012", "CH-019", "CH-020", "CH-025", "CH-027", "CH-033", "CH-036", "CH-045"]}),
    ("structural-population-too-narrow",
     "Architecture / domain detectors read too narrow a population (project-reference cycles only, test edges in "
     "instability, no pass-through detection, attributes and projections ignored, entities without Id, declared "
     "references excuse co-change, test-support project not seen as test code)",
     {"bench-csharp-architecture": ["DOM-001", "SDP-001", "CYC-001", "IND-001"],
      "bench-csharp-domain-events": ["DM6-001", "ES1-002"],
      "estate-quellbrook-orders": ["ORD-001"],
      "bench-csharp-maturity-history": ["CPL-001"],
      "bench-csharp-tests": ["AX8-001"]}),
    ("info-level-never-in-sarif",
     "Measured but never reported: per-site rows at Info/Recommendation level or below a score threshold never reach "
     "SARIF; only a location-less roll-up does (X2 CancellationToken, D12/npm outdated, R7 unused exports, R3 size)",
     {"bench-csharp-security-dependencies": ["DEP-006"],
      "bench-ts-security-dependencies": ["OUT-001"],
      "bench-ts-codehealth": ["CH-016", "CH-030"],
      "bench-ts-frontend-a11y": ["A11Y-017"],
      "bench-csharp-codehealth": ["CH-026"],
      "bench-csharp-readiness": ["RDY-003"],
      "estate-quellbrook-orders": ["ORD-002"]}),
    ("call-shape-matching",
     "Data-flow rules that match call NAMES, not data: source-generated [LoggerMessage] methods, structured log "
     "fields, headers inside a logged object, localStorage under a neutral key, MD5.HashData / createHash('md5') for "
     "passwords",
     {"bench-csharp-security-injection": ["PII-001", "HASH-001"],
      "estate-quellbrook-notifier": ["NTF-002"],
      "bench-ts-security-injection": ["PII-001", "PII-003", "HASH-001"],
      "estate-quellbrook-gateway": ["GW-002"]}),
    ("dm-ts-arm-missing",
     "DM9-DM11 have no TypeScript arm, and DM6/DM7 only partial ones (decorators only; no interface type arguments)",
     {"bench-ts-domain-privacy": ["DIB-001", "REP-001", "SDR-001", "MAT-001", "CIE-001"]}),
    ("location-imprecision",
     "Found the file, missed the site: checkov/trivy Kubernetes rows at line 1 or the pod spec, a duplicate-block "
     "window that starts early, a misplaced dependency reported at its importer",
     {"bench-csharp-security-iac": ["IAC-004", "IAC-006", "IAC-010"],
      "estate-quellbrook-dispatch": ["DSP-003"],
      "bench-ts-security-dependencies": ["MIS-001"]}),
    ("a11y-text-cards-off-by-default",
     "Model-judged accessibility text cards (LA2 alt text, LA5 link text, LA6 labels) are composed only with a "
     "compliance framework configured, so the default configuration measures nothing",
     {"bench-ts-frontend-a11y": ["A11Y-019", "A11Y-020"],
      "bench-csharp-blazor-a11y": ["BA-023", "BA-024", "BA-025"]}),
    ("dependency-hygiene-arm",
     "Dependency hygiene arms missing: npm deprecation not graded, EOL ignores engines.node and nested packages, "
     "R8 unused/undeclared blind on TypeScript",
     {"bench-ts-security-dependencies": ["DPR-001", "DPR-002", "EOL-001", "UNU-001", "UND-001"]}),
    ("presence-only-runtime-checks",
     "Presence-only runtime checks: X2 checks that a token parameter exists, not that it is forwarded; an injected "
     "fetch hides outbound HTTP from P7/X2; Console output is neither a log call nor flagged",
     {"bench-csharp-readiness": ["RDY-002", "RDY-006"],
      "bench-ts-readiness": ["RDY-001", "RDY-002", "RDY-005"]}),
    ("adr-and-doc-conformance",
     "ADR / documentation conformance is model-judged: absent from contained scans and unreliable in host passes "
     "(prose-enforced ADRs, README drift, ADR contradicted by an endpoint)",
     {"bench-csharp-architecture": ["ARU-001"],
      "bench-csharp-maturity-history": ["ADR-001", "DOC-001"],
      "estate-quellbrook-dispatch": ["DSP-004"]}),
    ("a11y-css-not-read",
     "AC6 reads <style> blocks and inline styles only: motion and focus-outline defects in .css / .razor.css files "
     "are invisible",
     {"bench-ts-frontend-a11y": ["A11Y-014", "A11Y-015"],
      "bench-csharp-blazor-a11y": ["BA-015", "BA-017"]}),
    ("flaky-test-detection",
     "Flaky tests: detection is three re-runs (a 1e-4 flake never shows), no time-zone/clock-read rule, the "
     "fixed-sleep rule reads C# only",
     {"bench-csharp-tests": ["TQ-006"],
      "bench-ts-readiness": ["FLK-001", "FLK-002"]}),
    ("iac-ci-check-absent",
     "IaC / CI checks absent in the pinned rule sets: Ingress without TLS, pull_request_target checking out and "
     "building the PR head",
     {"bench-csharp-security-iac": ["IAC-013", "IAC-017"]}),
]


def ratio(n, d):
    return round(n / d, 4) if d else None


def add(acc, s):
    for k in ("tp", "fn", "trapFp", "trapTn", "results", "noise", "fileLevelTp", "redundant", "uncovered",
              "summaryOfConcept"):
        acc[k] = acc.get(k, 0) + (s.get(k) or 0)
    return acc


def metrics(acc):
    acc["recall"] = ratio(acc["tp"], acc["tp"] + acc["fn"])
    acc["trapResistance"] = ratio(acc["trapTn"], acc["trapTn"] + acc["trapFp"])
    acc["noiseShare"] = ratio(acc["noise"], acc["results"])
    acc["fileLevelRecall"] = ratio(acc["fileLevelTp"], acc["tp"] + acc["fn"])
    return acc


LANG = {"csharp": "C#", "typescript": "TypeScript"}


def build(final, results_dir, draft=None, filed=None):
    repos = final["repos"]
    out = {"source": "results/watchdog/final-scores.json", "harness": final["harness"], "mapping": final["mapping"],
           "instrument": final["instrument"], "headline": "contained scan, scanner default configuration",
           "repos": [], "totals": {}, "byLanguage": {}, "byFamily": {}}
    total, by_lang, by_fam = {}, collections.defaultdict(dict), collections.defaultdict(dict)
    for r in repos:
        s = metrics(add({}, r["summary"]))
        row = {"name": r["name"], "tag": r["tag"], "language": LANG[r["languages"][0]], "family": r["family"], **s}
        if "hostModelPass" in r:
            row["hostModelPass"] = metrics(add({}, r["hostModelPass"]["summary"]))
        out["repos"].append(row)
        add(total, r["summary"])
        add(by_lang[row["language"]], r["summary"])
        add(by_fam[r["family"]], r["summary"])
    out["totals"] = metrics(total)
    out["totals"]["repositories"] = len(repos)
    out["byLanguage"] = {k: metrics(v) for k, v in sorted(by_lang.items())}
    out["byFamily"] = {k: metrics(v) for k, v in sorted(by_fam.items())}
    matched = collections.Counter()
    for r in repos:
        matched.update(r.get("tpMatchedBy", {}))
    out["totals"]["tpMatchedBy"] = dict(matched)
    bands = collections.Counter(b["outcome"] for r in repos for b in r["scoreBands"])
    host_bands = collections.Counter(b["outcome"] for r in repos for b in r.get("hostModelPass", {}).get("scoreBands", []))
    out["totals"]["scoreBands"] = {"contained": dict(bands), "hostModelPass": dict(host_bands)}

    dims = collections.defaultdict(dict)
    for r in repos:
        for d in r["dimensions"]:
            add(dims[d["id"]], d)
    out["byDimension"] = {k: metrics(v) for k, v in sorted(dims.items())
                          if v["tp"] + v["fn"] + v["trapFp"] + v["trapTn"] >= 3}

    fns = {(r["name"], f["id"]): dict(f, repo=r["name"]) for r in repos for f in r["falseNegatives"]}
    seen = {}
    mech = []
    for mid, title, sites in FN_MECHANISMS:
        rows = []
        for repo, ids in sites.items():
            for i in ids:
                k = (repo, i)
                if k not in fns:
                    raise SystemExit(f"FN table names {repo} {i}, which is not an FN of the final re-score")
                if k in seen:
                    raise SystemExit(f"{repo} {i} is classified twice ({seen[k]}, {mid})")
                seen[k] = mid
                f = fns[k]
                rows.append({"repo": repo, "id": i, "concept": f["concept"], "file": f["file"], "lines": f["lines"]})
        mech.append({"id": mid, "title": title, "count": len(rows),
                     "languages": sorted({LANG[next(r["languages"][0] for r in repos if r["name"] == x["repo"])]
                                          for x in rows}),
                     "sites": rows})
    missing = sorted(set(fns) - set(seen))
    if missing:
        raise SystemExit(f"FNs of the final re-score without a mechanism: {missing}")
    mech.sort(key=lambda m: -m["count"])
    out["falseNegativeMechanisms"] = mech

    verdicts = collections.Counter()
    for r in repos:
        with open(os.path.join(results_dir, r["name"] + ".json"), encoding="utf-8") as f:
            for v in json.load(f).get("verdicts", []):
                verdicts[v["class"]] += 1
    out["verdictClasses"] = dict(verdicts.most_common())

    if draft and filed:
        with open(draft, encoding="utf-8") as f:
            items = json.load(f)
        with open(filed, encoding="utf-8") as f:
            ids = json.load(f)["filed"]
        noise = []
        for i, it in enumerate(items):
            m = re.search(r"SITES \((\d+) rows?, (\d+) repositor", it["evidence"])
            noise.append({"backlogId": ids.get(str(i)), "dimension": it["dimension"], "language": it["language"],
                          "sites": int(m.group(1)), "repositories": int(m.group(2)),
                          "mechanism": it["evidence"].split("\n")[0].replace("MECHANISM: ", "")})
        noise.sort(key=lambda n: (-n["sites"], -n["repositories"]))
        out["noiseMechanisms"] = {"filedItems": len(noise), "sites": sum(n["sites"] for n in noise),
                                  "top": [n for n in noise if n["sites"] >= noise[min(9, len(noise) - 1)]["sites"]]}
    return out


def pct(v):
    return "n/a" if v is None else f"{100 * v:.1f} %"


def markdown(s):
    p = print
    p("| Repository | Tag | Lang | Family | Recall TP/(TP+FN) | Trap resistance | Noise share | File-level recall |")
    p("|---|---|---|---|---|---|---|---|")
    for r in s["repos"]:
        p(f"| {r['name']} | {r['tag']} | {r['language']} | {r['family']} | {r['tp']}/{r['tp'] + r['fn']} "
          f"({pct(r['recall'])}) | {r['trapTn']}/{r['trapTn'] + r['trapFp']} ({pct(r['trapResistance'])}) | "
          f"{r['noise']}/{r['results']} ({pct(r['noiseShare'])}) | {pct(r['fileLevelRecall'])} |")
    p()
    p(f"score bands: {s['totals']['scoreBands']}")
    p()
    p("| Slice | Repos | Recall | Trap resistance | Noise share | File-level recall |")
    p("|---|---|---|---|---|---|")
    groups = [("**All**", s["totals"], s["totals"]["repositories"])]
    groups += [(k, v, sum(1 for r in s["repos"] if r["language"] == k)) for k, v in s["byLanguage"].items()]
    groups += [(f"family: {k}", v, sum(1 for r in s["repos"] if r["family"] == k)) for k, v in s["byFamily"].items()]
    for name, t, n in groups:
        p(f"| {name} | {n} | {t['tp']}/{t['tp'] + t['fn']} ({pct(t['recall'])}) | "
          f"{t['trapTn']}/{t['trapTn'] + t['trapFp']} ({pct(t['trapResistance'])}) | "
          f"{t['noise']}/{t['results']} ({pct(t['noiseShare'])}) | {pct(t['fileLevelRecall'])} |")
    p()
    p("| Dimension | Plants found | Traps held | Noise share |")
    p("|---|---|---|---|")
    for k, t in s["byDimension"].items():
        p(f"| {k} | {t['tp']}/{t['tp'] + t['fn']} ({pct(t['recall'])}) | {t['trapTn']}/{t['trapTn'] + t['trapFp']} "
          f"({pct(t['trapResistance'])}) | {t['noise']}/{t['results']} ({pct(t['noiseShare'])}) |")
    p()
    for m in s["falseNegativeMechanisms"]:
        ex = "; ".join(f"{x['repo'].replace('bench-', '')} {x['id']} (`{x['file']}`)" for x in m["sites"][:3])
        p(f"| {m['count']} | {m['title']} | {', '.join(m['languages'])} | {ex} |")
    if "noiseMechanisms" in s:
        p()
        for n in s["noiseMechanisms"]["top"]:
            p(f"| {n['sites']} | {n['repositories']} | {n['dimension']} | {n['mechanism'][:200]} | `{n['backlogId']}` |")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--final", default=os.path.join(HERE, "final-scores.json"))
    ap.add_argument("--backlog-draft")
    ap.add_argument("--backlog-filed")
    ap.add_argument("--out", default=os.path.join(HERE, "SUMMARY.json"))
    ap.add_argument("--markdown", action="store_true")
    a = ap.parse_args(argv)
    with open(a.final, encoding="utf-8") as f:
        final = json.load(f)
    s = build(final, HERE, a.backlog_draft, a.backlog_filed)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=1, ensure_ascii=False)
        f.write("\n")
    if a.markdown:
        markdown(s)


if __name__ == "__main__":
    sys.exit(main())
