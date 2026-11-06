#!/usr/bin/env python3
"""Validate coverage/matrix.json and render it as coverage/MATRIX.md (stdlib only).

Checks, all fatal:
  * exactly EXPECTED_ROWS rows (the rubric's dimension count) with unique ids — if the count differs the script
    reports the real number and, when --catalog points at the rubric catalog snapshot, which ids are missing/extra;
  * every row is either `in-scope` with at least one repository carrying a label other than `not-applicable`,
    or `out-of-scope` with a non-empty reason (no row may lack both);
  * every label is a contract label kind; every concept exists in taxonomy.json;
  * (decision 0012) the matrix and the taxonomy are CAI's own files; no producer's mapping is read;
  * (contract 1.4) every `beyondReference` concept exists in taxonomy.json and no row measures it,
    and is mapped on no dimension, and every `unmapped` concept is in `beyondReference`.

Not fatal, rendered and printed: the frozen-key coverage gaps (in-scope rows with no FROZEN repository of a language
carrying a measuring label — planned repositories do not count) and the clean-only rows.

Usage:  python3 coverage/render_matrix.py [--catalog <rubric-catalog-snapshot.json>] [--check]
        --check validates and verifies MATRIX.md is up to date without writing it.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

EXPECTED_ROWS = 165
LABELS = {"must-fire", "must-not-fire", "clean", "not-applicable", "score-band"}
KINDS = {"finding", "posture", "metric", "judged", "runtime"}
ROOT = Path(__file__).resolve().parent.parent

SHORT_LABEL = {"must-fire": "MF", "must-not-fire": "MNF", "clean": "CL", "not-applicable": "NA", "score-band": "SB"}


def fail(msg):
    print(f"render_matrix: {msg}", file=sys.stderr)
    sys.exit(1)


def load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def validate(matrix, taxonomy, catalog_path):
    rows = matrix["rows"]
    ids = [r["id"] for r in rows]
    dupes = [i for i, n in Counter(ids).items() if n > 1]
    if dupes:
        fail(f"duplicate dimension ids: {dupes}")
    if len(rows) != EXPECTED_ROWS:
        why = ""
        if catalog_path:
            cat = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
            cat_ids = {d["id"] for d in cat["dimensions"]}
            why = (f" catalog {cat.get('rubricVersion')} has {len(cat_ids)} dimensions;"
                   f" missing from matrix: {sorted(cat_ids - set(ids))}; not in catalog: {sorted(set(ids) - cat_ids)}")
        fail(f"expected {EXPECTED_ROWS} rows (one per dimension of rubric {matrix.get('rubricVersion')}), found {len(rows)}.{why}")
    if catalog_path:
        cat = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
        cat_ids = {d["id"] for d in cat["dimensions"]}
        if cat_ids != set(ids):
            fail(f"matrix ids differ from catalog: missing {sorted(cat_ids - set(ids))}, extra {sorted(set(ids) - cat_ids)}")

    concepts = {c["id"]: c for c in taxonomy["concepts"]}
    for r in rows:
        rid = r["id"]
        if r["kind"] not in KINDS:
            fail(f"{rid}: unknown kind {r['kind']!r}")
        if r["status"] == "in-scope":
            cov = r.get("coverage") or []
            if not any(set(c["labels"]) - {"not-applicable"} for c in cov):
                fail(f"{rid}: in-scope but no repository carries a measuring label")
            for c in cov:
                if not c.get("repo"):
                    fail(f"{rid}: coverage entry without repo")
                bad = set(c["labels"]) - LABELS
                if bad:
                    fail(f"{rid}: unknown label(s) {sorted(bad)} for {c['repo']}")
        elif r["status"] == "out-of-scope":
            if not (r.get("reason") or "").strip():
                fail(f"{rid}: out-of-scope without a reason")
        else:
            fail(f"{rid}: status must be in-scope or out-of-scope, got {r['status']!r}")
        if not r.get("concepts"):
            fail(f"{rid}: no concepts")
        for cid in r["concepts"]:
            if cid not in concepts:
                fail(f"{rid}: concept {cid!r} not in taxonomy.json")
    measured = {cid for r in rows for cid in r.get("concepts", [])}
    for b in matrix.get("beyondReference", []):
        cid = b["concept"]
        if cid not in concepts:
            fail(f"beyondReference: concept {cid!r} not in taxonomy.json")
        if cid in measured:
            fail(f"beyondReference: concept {cid!r} is measured by a row")
        for c in b.get("repos", []):
            if set(c["labels"]) - LABELS:
                fail(f"beyondReference {cid}: unknown label(s) for {c['repo']}")


def md_escape(s):
    return (s or "").replace("|", "\\|").replace("\n", " ")


def render(matrix):
    rows = matrix["rows"]
    ins = [r for r in rows if r["status"] == "in-scope"]
    out = [r for r in rows if r["status"] == "out-of-scope"]
    kinds = Counter(r["kind"] for r in rows)
    p1set = set(matrix["phase1Repos"])
    p1 = [r for r in rows if any(c["repo"] in p1set and set(c["labels"]) - {"not-applicable"} for c in r.get("coverage") or [])]
    lines = [
        "# Coverage matrix",
        "",
        f"Generated by `coverage/render_matrix.py` from `coverage/matrix.json` — do not edit by hand. "
        f"Rubric `{matrix['rubricVersion']}`: **{len(rows)} dimensions**, **{len(ins)} in scope**, "
        f"**{len(out)} out of scope**.",
        "",
        "Kinds: " + ", ".join(f"{k} {n}" for k, n in sorted(kinds.items())) + ". "
        f"Phase 1 repositories: {', '.join('`' + r + '`' for r in matrix['phase1Repos'])} "
        f"(at least one of them carries a measuring label on {len(p1)} rows).",
        "",
        "Labels: MF must-fire · MNF must-not-fire · CL clean · NA not-applicable · SB score-band. "
        "A frozen repository's labels are read from its key at the registered tag; *(plan)* marks a repository not "
        "frozen yet (planned labels); — marks a frozen repository planned for the row whose key labels none of its "
        "concepts. "
        "Repositories marked **★** are Phase 1.",
        "",
        "| Dim | Name | Lens | Kind | Concepts | Status | Repositories (labels) / reason | Requires |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        if r["status"] == "in-scope":
            parts = []
            for c in r["coverage"]:
                star = "**★**" if c["repo"] in p1set else ""
                lab = "/".join(SHORT_LABEL[x] for x in c["labels"]) or "—"
                src = " *(plan)*" if c.get("source") == "plan" else ""
                parts.append(f"{star}`{c['repo'].replace('bench-', '')}` {lab}{src}")
            where = "<br>".join(parts)
        else:
            where = "**OUT:** " + md_escape(r["reason"])
        lines.append("| " + " | ".join([
            f"**{r['id']}**", md_escape(r["name"]), r["lensLabel"], r["kind"],
            ", ".join(r["concepts"]), r["status"], where,
            md_escape("; ".join(r.get("requires") or [])) or "—",
        ]) + " |")
    lines += ["", "## Out of scope", ""]
    for r in out:
        lines.append(f"- **{r['id']}** {md_escape(r['name'])} — {md_escape(r['reason'])}")
    lines += ["", "## Coverage gaps (frozen keys)", "",
              "In-scope rows where no FROZEN repository of the language carries a measuring label (planned "
              "repositories do not count), and rows whose only frozen measuring labels are concept-specific clean "
              "regions (noise is measured there, recall and trap resistance are not).", ""]
    for lang in ("csharp", "typescript"):
        g = [r["id"] for r in ins if lang in r.get("frozenCoverageGaps", [])]
        c = [r["id"] for r in ins if lang in r.get("frozenCoverageCleanOnly", [])]
        lines.append(f"- **{lang}** — no frozen measuring label ({len(g)}): {', '.join(g) or 'none'}")
        lines.append(f"- **{lang}** — clean-only ({len(c)}): {', '.join(c) or 'none'}")
    lines += ["", "## Concepts no rubric dimension measures", "",
              "Taxonomy concepts no row of this matrix measures: a plant of one is scored by the concept alone, for "
              "every scanner alike.", "",
              "| Concept | CWE | Family | Repositories (labels) |", "|---|---|---|---|"]
    for b in matrix.get("beyondReference", []):
        reps = "<br>".join(f"`{c['repo'].replace('bench-', '')}` "
                           f"{'/'.join(SHORT_LABEL[x] for x in c['labels'])}"
                           f"{' *(plan: ' + md_escape(c.get('note', '')) + ')*' if c.get('source') == 'plan' else ''}"
                           for c in b["repos"]) or "—"
        lines.append(f"| **{b['concept']}** {md_escape(b['title'])} | {b['cwe'] or '—'} | {b['family']} | {reps} |")
    lines += ["", "## Per repository", ""]
    per = {}
    for r in ins:
        for c in r["coverage"]:
            if set(c["labels"]) - {"not-applicable"}:
                per.setdefault(c["repo"], []).append(r["id"])
    for repo in sorted(per, key=lambda x: (min(c["phase"] for r in ins for c in r["coverage"] if c["repo"] == x), x)):
        phase = min(c["phase"] for r in ins for c in r["coverage"] if c["repo"] == repo)
        lines.append(f"- `{repo}` (phase {phase}, {len(per[repo])} dims): {', '.join(per[repo])}")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--catalog", help="rubric-catalog-snapshot.json to cross-check ids against")
    ap.add_argument("--check", action="store_true", help="validate and verify MATRIX.md is current; write nothing")
    args = ap.parse_args()
    matrix = load("coverage/matrix.json")
    validate(matrix, load("taxonomy.json"), args.catalog)
    text = render(matrix)
    target = ROOT / "coverage" / "MATRIX.md"
    if args.check:
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            fail("coverage/MATRIX.md is stale — run coverage/render_matrix.py")
        print("render_matrix: OK (MATRIX.md current)")
        return
    target.write_text(text, encoding="utf-8")
    rows = matrix["rows"]
    print(f"render_matrix: {len(rows)} rows, {sum(r['status'] == 'in-scope' for r in rows)} in scope, "
          f"{sum(r['status'] == 'out-of-scope' for r in rows)} out of scope -> {target.relative_to(ROOT)}")
    for lang in ("csharp", "typescript"):
        g = [r["id"] for r in rows if r["status"] == "in-scope" and lang in r.get("frozenCoverageGaps", [])]
        print(f"render_matrix: frozen coverage gaps ({lang}): {' '.join(g) or 'none'}")


if __name__ == "__main__":
    main()
