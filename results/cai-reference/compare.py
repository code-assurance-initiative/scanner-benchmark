"""Side-by-side aggregates of two scanners scored by the same harness over the same units.

    python3 results/cai-reference/compare.py \
        --a results/cai-reference/final-scores.json --a-mapping mappings/cai-reference.json --a-label "CAI RI" \
        --b results/watchdog/rescore-harness-1.6.json --b-mapping mappings/watchdog.json --b-label Watchdog \
        [--units <unit> ...] [--json comparison.json] [--md tables.md] [--no-dimensions]

Both sides are aggregated by `cai_bench.baseline.aggregate` (the definitions of BASELINE-2026-10-07 §2: plants and
traps once per lens from the per-concept rows, results partitioned by dimension), with the frozen dimension -> lens
map of results/watchdog/baseline-2026-10-07.json for both, so a lens means the same rubric dimensions on each side.
`--units` restricts BOTH sides to the named units, and every named unit must be present on both sides with the same
tag and key sha256 — otherwise the comparison is refused unless `--allow-key-mismatch` is given, and each mismatch is
printed. Recall and trap resistance carry Wilson 95 % intervals. Standard library only.
"""
import argparse
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from cai_bench.baseline import NO_RULE, aggregate, metrics, natural  # noqa: E402
from cai_bench.mapping import Mapping  # noqa: E402

BASELINE = os.path.join(ROOT, "results", "watchdog", "baseline-2026-10-07.json")


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def pct(k, n):
    return "n/a" if not n else f"{100 * k / n:.1f} %"


def frac(k, n, ci=False):
    if not n:
        return "– (n/a)"
    s = f"{k}/{n} ({pct(k, n)})"
    if ci:
        lo, hi = wilson(k, n)
        s += f" [{100 * lo:.0f}–{100 * hi:.0f}]"
    return s


def load(path, mapping_path, units):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    with open(mapping_path, encoding="utf-8") as f:
        mapping = Mapping(json.load(f))
    if units:
        doc = dict(doc, repos=[r for r in doc["repos"] if r["name"] in units])
    return doc, mapping


def measured_dims(mapping):
    """Dimensions at least one rule of the scanner maps a concept to: the scanner can report there at all."""
    return {d for c, rules in mapping.concepts.items() if rules for d in mapping.dims.get(c, [])}


def canonical_dimension(concept, ma, mb):
    """The catalog dimension a concept is counted under on BOTH sides: side A's mapping first, else side B's; an
    umbrella (contract 1.3 parent) under its children's dimension, since its plants are matched by their results."""
    for m in (ma, mb):
        kids = sorted(c for c, p in m.parents.items() if p == concept)
        if kids:
            return canonical_dimension(kids[0], ma, mb)
    for m in (ma, mb):
        if m.concepts.get(concept) and m.dims.get(concept):
            return m.dims[concept][0]
    for m in (ma, mb):
        if m.dims.get(concept):
            return m.dims[concept][0]
    return NO_RULE


def by_canonical_dimension(da, db, ma, mb):
    """Per-concept rows of both sides (the same plants and traps: a concept row is the key's, whichever scanner ran)
    summed under one canonical dimension per concept, so a plant is counted once and on both sides."""
    keys = ("tp", "fn", "trapTn", "trapFp", "results", "noise", "redundant", "fileLevelTp")
    out = {}
    for side, doc in (("a", da), ("b", db)):
        for r in doc["repos"]:
            for c in r["concepts"]:
                if c["id"] in ("*", "(unmapped)"):
                    continue
                d = canonical_dimension(c["id"], ma, mb)
                acc = out.setdefault(d, {"a": {k: 0 for k in keys}, "b": {k: 0 for k in keys}, "concepts": set()})
                for k in keys:
                    acc[side][k] += c.get(k) or 0
                if c["tp"] + c["fn"] + c["trapTn"] + c["trapFp"]:
                    acc["concepts"].add(c["id"])
    rows = {}
    for d in sorted(out, key=natural):
        r = out[d]
        if any(r[s][k] for s in ("a", "b") for k in ("tp", "fn", "trapTn", "trapFp", "results")):
            rows[d] = {"a": metrics(r["a"]), "b": metrics(r["b"]), "concepts": sorted(r["concepts"])}
    return rows


def headline(agg):
    t = agg["totals"]
    return {"plants": t["tp"] + t["fn"], "tp": t["tp"], "traps": t["trapTn"] + t["trapFp"], "trapTn": t["trapTn"],
            "results": t["results"], "noise": t["noise"], "redundant": t["redundant"],
            "fileLevelTp": t["fileLevelTp"], "recall": t["recall"], "trapResistance": t["trapResistance"],
            "noiseShare": t["noiseShare"], "fileLevelRecall": t["fileLevelRecall"]}


def extra(doc):
    out = {"uncovered": 0, "summaryOfConcept": 0}
    for r in doc["repos"]:
        for k in out:
            out[k] += r["summary"].get(k) or 0
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--a", required=True)
    ap.add_argument("--a-mapping", required=True)
    ap.add_argument("--a-label", default="A")
    ap.add_argument("--b", required=True)
    ap.add_argument("--b-mapping", required=True)
    ap.add_argument("--b-label", default="B")
    ap.add_argument("--units", nargs="*")
    ap.add_argument("--baseline", default=BASELINE, help="frozen baseline whose dimension -> lens map both sides use")
    ap.add_argument("--allow-key-mismatch", action="store_true")
    ap.add_argument("--no-dimensions", action="store_true", help="omit the per-dimension table")
    ap.add_argument("--json")
    ap.add_argument("--md")
    a = ap.parse_args(argv)
    with open(a.baseline, encoding="utf-8") as f:
        base = json.load(f)
    dim_lens, lens_order, labels = base["dimensionLens"], base["lensOrder"], base.get("lensLabels", {})
    da, ma = load(a.a, a.a_mapping, a.units)
    db, mb = load(a.b, a.b_mapping, a.units)
    ra, rb = {r["name"]: r for r in da["repos"]}, {r["name"]: r for r in db["repos"]}
    names = a.units or sorted(set(ra) | set(rb))
    problems = []
    for n in names:
        if n not in ra or n not in rb:
            problems.append(f"{n}: missing from {a.a_label if n not in ra else a.b_label}")
        elif (ra[n]["tag"], ra[n]["keySha256"]) != (rb[n]["tag"], rb[n]["keySha256"]):
            problems.append(f"{n}: {a.a_label} {ra[n]['tag']} (key {ra[n]['keySha256'][:12]}) vs {a.b_label} "
                            f"{rb[n]['tag']} (key {rb[n]['keySha256'][:12]})")
    for p in problems:
        print(f"WARNING {p}", file=sys.stderr)
    if problems and not a.allow_key_mismatch:
        raise SystemExit("refusing: the two sides are not scored on the same units and keys (--allow-key-mismatch)")
    aa, ab = aggregate(da, ma, dim_lens), aggregate(db, mb, dim_lens)
    ha, hb = headline(aa), headline(ab)
    xa, xb = extra(da), extra(db)
    md = []
    md.append(f"| Metric | {a.a_label} | {a.b_label} |")
    md.append("|---|---|---|")
    md.append(f"| Units | {len(da['repos'])} | {len(db['repos'])} |")
    md.append(f"| Recall (TP / plants) [Wilson 95 %] | **{frac(ha['tp'], ha['plants'], True)}** | "
              f"**{frac(hb['tp'], hb['plants'], True)}** |")
    md.append(f"| Trap resistance (held / traps) [Wilson 95 %] | **{frac(ha['trapTn'], ha['traps'], True)}** | "
              f"**{frac(hb['trapTn'], hb['traps'], True)}** |")
    md.append(f"| Noise share (noise / results of covered concepts) | **{frac(ha['noise'], ha['results'])}** | "
              f"**{frac(hb['noise'], hb['results'])}** |")
    md.append(f"| File-level recall (secondary) | {frac(ha['fileLevelTp'], ha['plants'])} | "
              f"{frac(hb['fileLevelTp'], hb['plants'])} |")
    md.append(f"| Redundant results (2nd hit on a found plant; no metric) | {ha['redundant']} | {hb['redundant']} |")
    md.append(f"| Uncovered results (concept not in the key; no metric) | {xa['uncovered']} | {xb['uncovered']} |")
    md.append("")
    md.append(f"| Lens | {a.a_label} recall | {a.a_label} traps | {a.a_label} noise | {a.b_label} recall | "
              f"{a.b_label} traps | {a.b_label} noise |")
    md.append("|---|---|---|---|---|---|---|")
    lens_rows = {}
    for L in lens_order + sorted((set(aa["byLens"]) | set(ab["byLens"])) - set(lens_order)):
        x = (aa["byLens"].get(L) or {}).get("all") or metrics({})
        y = (ab["byLens"].get(L) or {}).get("all") or metrics({})
        if not any(v[k] for v in (x, y) for k in ("tp", "fn", "trapTn", "trapFp", "results")):
            continue
        lens_rows[L] = {"a": x, "b": y}
        md.append(f"| {labels.get(L, L)} | {frac(x['tp'], x['tp'] + x['fn'])} | "
                  f"{frac(x['trapTn'], x['trapTn'] + x['trapFp'])} | {frac(x['noise'], x['results'])} | "
                  f"{frac(y['tp'], y['tp'] + y['fn'])} | {frac(y['trapTn'], y['trapTn'] + y['trapFp'])} | "
                  f"{frac(y['noise'], y['results'])} |")
    meas_a, meas_b = measured_dims(ma), measured_dims(mb)
    canon_rows = {}
    if not a.no_dimensions:
        canon_rows = by_canonical_dimension(da, db, ma, mb)
        md.append("")
        md.append(f"Per dimension, SAME PLANTS on both sides: each concept counted once, under its canonical catalog "
                  f"dimension (the one {a.a_label}'s mapping names, else {a.b_label}'s); recall and traps from the "
                  f"harness's per-concept rows, noise from the results each scanner attributed to those concepts.")
        md.append("")
        md.append(f"| Dimension | Lens | Plants | {a.a_label} found | {a.b_label} found | Δ TP | Traps | "
                  f"{a.a_label} held | {a.b_label} held | {a.a_label} noise | {a.b_label} noise | "
                  f"{a.a_label} rule? | {a.b_label} rule? |")
        md.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|")
        for d, r in canon_rows.items():
            x, y = r["a"], r["b"]
            lens = NO_RULE if d == NO_RULE else labels.get(dim_lens.get(d, ""), dim_lens.get(d, "?"))
            md.append(f"| {d} | {lens} | {x['tp'] + x['fn']} | {x['tp']} | {y['tp']} | {x['tp'] - y['tp']:+d} | "
                      f"{x['trapTn'] + x['trapFp']} | {x['trapTn']} | {y['trapTn']} | {x['noise']}/{x['results']} | "
                      f"{y['noise']}/{y['results']} | {'yes' if d in meas_a else 'no'} | "
                      f"{'yes' if d in meas_b else 'no'} |")
    dim_rows = {}
    for d in sorted(set(aa["byDimension"]) | set(ab["byDimension"]), key=natural):
        x = (aa["byDimension"].get(d) or {}).get("all") or metrics({})
        y = (ab["byDimension"].get(d) or {}).get("all") or metrics({})
        if any(v[k] for v in (x, y) for k in ("tp", "fn", "trapTn", "trapFp", "results")):
            dim_rows[d] = {"a": x, "b": y, "aMeasures": d in meas_a, "bMeasures": d in meas_b}
    text = "\n".join(md) + "\n"
    if a.md:
        with open(a.md, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text)
    if a.json:
        doc = {"a": {"label": a.a_label, "instrument": da.get("instrument"), "harness": da.get("harness"),
                     "headline": ha, **xa},
               "b": {"label": a.b_label, "instrument": db.get("instrument"), "harness": db.get("harness"),
                     "headline": hb, **xb},
               "units": names, "keyMismatches": problems, "byLens": lens_rows,
               "byCanonicalDimension": canon_rows, "byHarnessDimension": dim_rows}
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
