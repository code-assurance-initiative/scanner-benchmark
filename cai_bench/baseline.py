"""Baselines: aggregate a scanner's per-repository final scores into per-dimension and per-lens figures, and compare
a later run against a frozen baseline.

    python3 -m cai_bench compare --baseline results/watchdog/baseline-2026-10-07.json \
        --current <new final-scores.json> [--mapping mappings/watchdog.json] [--all] [--json delta.json]

Input `final-scores.json` (results/<scanner>/final-scores.json): one headline score report per registry repository,
each with `summary`, `concepts`, `dimensions` and `scoreBands` exactly as `python3 -m cai_bench score --json` writes
them (plus `name`, `tag`, `keySha256`, `languages`, `family`).

Definitions (the same for the baseline and every later run, so deltas are like for like):

- **Per dimension**: the sum over repositories of the harness's per-dimension rows (contract 1.4: matching re-run
  within the dimension). A plant is counted under every dimension its concept maps to, so dimension rows overlap.
- **Per lens**: plants and traps are counted ONCE per lens, from the per-concept rows: a concept belongs to every lens
  one of its dimensions belongs to, and a plant is found when Watchdog found it (TP of the whole run). Results and
  noise are the sum of the lens's dimension rows: every result has exactly one dimension, so lenses partition them.
  Concepts no scanner dimension maps go to the `(no scanner rule)` lens.
- **Score bands**: a band belongs to the dimension(s) whose score was read for it, or, when unscored, to the
  dimensions the mapping says measure its concept (`scoreDimensions`, defaulting to `dimensions`).
"""
import json

NO_RULE = "(no scanner rule)"
UNKNOWN_LENS = "(dimension not in the baseline's catalog)"
LANGS = ("csharp", "typescript")
PLANT_KEYS = ("tp", "fn", "trapFp", "trapTn", "fileLevelTp")
RESULT_KEYS = ("results", "noise", "redundant")
DIM_KEYS = PLANT_KEYS + RESULT_KEYS + ("fp", "tn")


def ratio(n, d):
    return round(n / d, 4) if d else None


def metrics(acc):
    for k in DIM_KEYS:
        acc.setdefault(k, 0)
    acc["recall"] = ratio(acc["tp"], acc["tp"] + acc["fn"])
    acc["trapResistance"] = ratio(acc["trapTn"], acc["trapTn"] + acc["trapFp"])
    acc["noiseShare"] = ratio(acc["noise"], acc["results"])
    acc["fileLevelRecall"] = ratio(acc["fileLevelTp"], acc["tp"] + acc["fn"])
    return acc


def _add(acc, row, keys):
    for k in keys:
        acc[k] = acc.get(k, 0) + (row.get(k) or 0)


def _bucket():
    return {"all": {}, "csharp": {}, "typescript": {}}


def _measures(row):
    return row["tp"] + row["fn"] + row["trapFp"] + row["trapTn"] + row["results"] > 0


def aggregate(final, mapping, dim_lens):
    """Per dimension, per lens, per language and in total. `mapping` is a cai_bench.mapping.Mapping (concept ->
    dimensions); `dim_lens` maps a dimension id to its lens key."""
    def lens_of(d):
        return NO_RULE if d == NO_RULE else dim_lens.get(d, UNKNOWN_LENS)

    totals, by_lang, by_dim, by_lens = {}, {l: {} for l in LANGS}, {}, {}
    for r in final["repos"]:
        lang = r["languages"][0]
        _add(totals, r["summary"], DIM_KEYS)
        _add(by_lang[lang], r["summary"], DIM_KEYS)
        for d in r["dimensions"]:
            b = by_dim.setdefault(d["id"], dict(_bucket(), repos=[], bands=[]))
            for k in ("all", lang):
                _add(b[k], d, DIM_KEYS)
            if _measures(d):
                b["repos"].append(r["name"])
            lb = by_lens.setdefault(lens_of(d["id"]), dict(_bucket(), dimensions=set(), bands={}))
            lb["dimensions"].add(d["id"])
            for k in ("all", lang):
                _add(lb[k], d, RESULT_KEYS)
        for c in r["concepts"]:
            if c["id"] in ("*", "(unmapped)"):
                continue
            lenses = sorted({lens_of(d) for d in mapping.dimensions_of_concept(c["id"])}) or [NO_RULE]
            for L in lenses:
                lb = by_lens.setdefault(L, dict(_bucket(), dimensions=set(), bands={}))
                for k in ("all", lang):
                    _add(lb[k], c, PLANT_KEYS)
        for band in r["scoreBands"]:
            dims = [s["source"] for s in band["scores"]] or list(mapping.score_dimensions_of_concept(band["concept"]))
            dims = list(dict.fromkeys(dims))
            row = {"repo": r["name"], "id": band["id"], "concept": band["concept"], "band": band["band"],
                   "scores": band["scores"], "outcome": band["outcome"]}
            for d in dims:
                b = by_dim.setdefault(d, dict(_bucket(), repos=[], bands=[]))
                b["bands"].append(row)
                if r["name"] not in b["repos"]:
                    b["repos"].append(r["name"])
            for L in sorted({lens_of(d) for d in dims}) or [NO_RULE]:
                lb = by_lens.setdefault(L, dict(_bucket(), dimensions=set(), bands={}))
                lb["bands"][band["outcome"]] = lb["bands"].get(band["outcome"], 0) + 1
    for b in by_dim.values():
        for k in ("all",) + LANGS:
            metrics(b[k])
        b["bandCounts"] = {o: sum(1 for x in b["bands"] if x["outcome"] == o) for o in ("in", "out", "unscored")}
    for lb in by_lens.values():
        for k in ("all",) + LANGS:
            metrics(lb[k])
        lb["dimensions"] = sorted(lb["dimensions"], key=natural)
        lb["bands"] = {o: lb["bands"].get(o, 0) for o in ("in", "out", "unscored")}
    return {"totals": metrics(totals), "byLanguage": {k: metrics(v) for k, v in by_lang.items()},
            "byDimension": {k: by_dim[k] for k in sorted(by_dim, key=natural)}, "byLens": by_lens}


def natural(s):
    import re
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


# --- compare --------------------------------------------------------------------------------------------------------

def _pct(v):
    return "  n/a" if v is None else f"{100 * v:5.1f}"


def _delta_pp(a, b):
    if a is None or b is None:
        return "    "
    d = 100 * (b - a)
    return f"{d:+5.1f}" if abs(d) >= 0.05 else "    ="


def _line(name, a, b):
    """name | recall base -> cur (Δpp) TP Δ | traps | noise."""
    a = a or metrics({})
    return (f"{name[:34]:<34} recall {_pct(a['recall'])} -> {_pct(b['recall'])} {_delta_pp(a['recall'], b['recall'])}"
            f"  TP {a['tp']:>3}->{b['tp']:<3} FN {a['fn']:>3}->{b['fn']:<3}"
            f" | traps {_pct(a['trapResistance'])} -> {_pct(b['trapResistance'])} "
            f"{_delta_pp(a['trapResistance'], b['trapResistance'])}"
            f" | noise {a['noise']:>3}/{a['results']:<3} -> {b['noise']:>3}/{b['results']:<3} "
            f"{_delta_pp(a['noiseShare'], b['noiseShare'])}")


def _same(a, b):
    keys = PLANT_KEYS + RESULT_KEYS
    return all((a or {}).get(k, 0) == b.get(k, 0) for k in keys)


def compare(baseline, current_final, mapping, show_all=False):
    """Recompute the baseline's aggregates over `current_final` (a final-scores.json document) and return
    (delta document, printable text). Uses the baseline's frozen dimension -> lens map."""
    dim_lens = baseline["dimensionLens"]
    cur = aggregate(current_final, mapping, dim_lens)
    warnings = []
    base_repos = {r["name"]: r for r in baseline["repos"]}
    cur_repos = {r["name"]: r for r in current_final["repos"]}
    for name, b in base_repos.items():
        c = cur_repos.get(name)
        if c is None:
            warnings.append(f"{name}: in the baseline, missing from the current run — totals are not like for like")
        elif (c["tag"], c["keySha256"]) != (b["tag"], b["keySha256"]):
            warnings.append(f"{name}: baseline {b['tag']} (key {b['keySha256'][:12]}) vs current {c['tag']} "
                            f"(key {c['keySha256'][:12]}) — a different answer key, not like for like")
    for name in sorted(set(cur_repos) - set(base_repos)):
        warnings.append(f"{name}: not in the baseline — included in the current totals")

    lines = [f"baseline: {baseline.get('instrument', '?')}",
             f"current:  {current_final.get('instrument', '?')}", ""]
    lines += [f"WARNING {w}" for w in warnings] + ([""] if warnings else [])
    lines.append("TOTAL")
    lines.append(_line("all repositories", baseline["totals"], cur["totals"]))
    for lang in LANGS:
        lines.append(_line(lang, baseline["byLanguage"].get(lang), cur["byLanguage"][lang]))
    lines += ["", "PER LENS (plants counted once per lens; results partitioned by dimension)"]
    lens_order = list(baseline["lensOrder"]) + [k for k in cur["byLens"] if k not in baseline["lensOrder"]]
    lens_rows = {}
    for L in lens_order:
        b = (baseline["byLens"].get(L) or {}).get("all")
        c = (cur["byLens"].get(L) or {}).get("all") or metrics({})
        if b is None and not c.get("results") and not (c["tp"] + c["fn"]):
            continue
        lens_rows[L] = {"baseline": b, "current": c}
        lines.append(_line(baseline.get("lensLabels", {}).get(L, L), b, c))
    lines += ["", "PER DIMENSION" + ("" if show_all else " (changed rows only; --all for every row)")]
    dim_rows, changed = {}, 0
    for d in sorted(set(baseline["byDimension"]) | set(cur["byDimension"]), key=natural):
        b = (baseline["byDimension"].get(d) or {}).get("all")
        c = (cur["byDimension"].get(d) or {}).get("all") or metrics({})
        same = _same(b, c)
        changed += 0 if same else 1
        dim_rows[d] = {"baseline": b, "current": c, "changed": not same}
        if show_all or not same:
            lines.append(_line(d, b, c))
    if not show_all and not changed:
        lines.append("(no dimension changed)")
    doc = {"baseline": baseline.get("instrument"), "current": current_final.get("instrument"), "warnings": warnings,
           "totals": {"baseline": baseline["totals"], "current": cur["totals"]},
           "byLanguage": {l: {"baseline": baseline["byLanguage"].get(l), "current": cur["byLanguage"][l]}
                          for l in LANGS},
           "byLens": lens_rows, "byDimension": dim_rows, "changedDimensions": changed}
    return doc, "\n".join(lines)


def load_baseline(path):
    with open(path, encoding="utf-8") as f:
        b = json.load(f)
    for k in ("dimensionLens", "lensOrder", "totals", "byLanguage", "byLens", "byDimension", "repos"):
        if k not in b:
            raise ValueError(f"{path}: not a baseline document (no '{k}')")
    return b
