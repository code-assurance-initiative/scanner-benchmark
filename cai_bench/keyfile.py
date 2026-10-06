"""Loading and validating answer keys (docs/CONTRACT.md) and taxonomies.

The checks are a hand-rolled mirror of schema/answer-key.schema.json — no third-party jsonschema library — plus the
cross-entry checks a JSON Schema cannot express: unique ids, concepts that exist in the taxonomy, cwe that agrees with
the taxonomy, and entries whose labels contradict each other on one concept and site.
"""
import json
import re

from .paths import norm, path_match

LABELS = ("must-fire", "must-not-fire", "clean", "not-applicable", "score-band")
SINGLE_CONCEPT_LABELS = ("must-fire", "must-not-fire", "not-applicable")
TOP_KEYS = {"$schema", "schema", "schemaVersion", "repo", "keyVersion", "languages", "theme", "lineTolerance", "entries"}
ENTRY_KEYS = {"id", "label", "concept", "concepts", "cwe", "file", "lines", "band", "rationale", "watchdog"}
CONCEPT_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
CWE_RE = re.compile(r"^CWE-[0-9]+$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
DEFAULT_TOLERANCE = 3


class KeyError_(Exception):
    pass


def load_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def line_tolerance(key):
    return key.get("lineTolerance", DEFAULT_TOLERANCE)


def entry_concepts(e):
    """The concepts an entry speaks about: a list, or "*" for a clean-for-everything region."""
    if e.get("label") == "clean":
        return e.get("concepts")
    return [e["concept"]] if "concept" in e else []


def _check_entry(i, e):
    where = f"entries[{i}]"
    if not isinstance(e, dict):
        return [f"{where}: must be an object"]
    if isinstance(e.get("id"), str) and e["id"]:
        where += f" ({e['id']})"
    p = []
    for k in sorted(set(e) - ENTRY_KEYS):
        p.append(f"{where}: unknown property '{k}'")
    if not (isinstance(e.get("id"), str) and e["id"]):
        p.append(f"{where}: 'id' is required and must be a non-empty string")
    label = e.get("label")
    if label not in LABELS:
        p.append(f"{where}: 'label' must be one of {', '.join(LABELS)} (got {label!r})")
    if not (isinstance(e.get("rationale"), str) and e["rationale"].strip()):
        p.append(f"{where}: 'rationale' is required and must be a non-empty string")

    if "concept" in e and not (isinstance(e["concept"], str) and CONCEPT_RE.match(e["concept"])):
        p.append(f"{where}: 'concept' must be a kebab-case concept id (got {e['concept']!r})")
    if "concepts" in e:
        c = e["concepts"]
        ok = c == "*" or (isinstance(c, list) and c and all(isinstance(x, str) and CONCEPT_RE.match(x) for x in c)
                          and len(set(c)) == len(c))
        if not ok:
            p.append(f"{where}: 'concepts' must be \"*\" or a non-empty array of unique kebab-case concept ids")
    if "cwe" in e and not (isinstance(e["cwe"], str) and CWE_RE.match(e["cwe"])):
        p.append(f"{where}: 'cwe' must look like CWE-<number> (got {e['cwe']!r})")
    if "file" in e and not (isinstance(e["file"], str) and e["file"].strip()):
        p.append(f"{where}: 'file' must be a non-empty string")
    if "lines" in e:
        ln = e["lines"]
        if not (isinstance(ln, list) and len(ln) == 2 and all(_is_int(x) for x in ln)):
            p.append(f"{where}: 'lines' must be [start, end] integers")
        elif ln[0] < 1 or ln[1] < 1:
            p.append(f"{where}: 'lines' must be >= 1 (got {ln})")
        elif ln[0] > ln[1]:
            p.append(f"{where}: 'lines' start {ln[0]} is after end {ln[1]}")
        if "file" not in e:
            p.append(f"{where}: 'lines' requires 'file'")
    if "band" in e:
        b = e["band"]
        if not (isinstance(b, list) and len(b) == 2 and all(_is_num(x) for x in b)):
            p.append(f"{where}: 'band' must be [min, max] numbers")
        elif not all(0 <= x <= 100 for x in b):
            p.append(f"{where}: 'band' values must lie in 0..100 (got {b})")
        elif b[0] > b[1]:
            p.append(f"{where}: 'band' min {b[0]} is above max {b[1]}")
    if "watchdog" in e and not (isinstance(e["watchdog"], list) and all(isinstance(x, str) and x for x in e["watchdog"])):
        p.append(f"{where}: 'watchdog' must be an array of non-empty strings")

    if label in SINGLE_CONCEPT_LABELS:
        if "concept" not in e:
            p.append(f"{where}: label '{label}' requires 'concept'")
        for k in ("concepts", "band"):
            if k in e:
                p.append(f"{where}: label '{label}' does not take '{k}'")
    elif label == "clean":
        if "concepts" not in e:
            p.append(f"{where}: label 'clean' requires 'concepts' (an array of concept ids, or \"*\")")
        for k in ("concept", "band", "cwe"):
            if k in e:
                p.append(f"{where}: label 'clean' does not take '{k}'")
    elif label == "score-band":
        for k in ("concept", "band"):
            if k not in e:
                p.append(f"{where}: label 'score-band' requires '{k}'")
        for k in ("concepts", "file"):
            if k in e:
                p.append(f"{where}: label 'score-band' does not take '{k}'")
    return p


def _site_overlap(a, b, gap):
    """True when the sites of two entries are closer than `gap` lines apart (both repo-level, or the same file with
    either one whole-file, or line ranges within `gap`)."""
    fa, fb = a.get("file"), b.get("file")
    if fa is None and fb is None:
        return True
    if fa is None or fb is None:
        return False
    if not path_match(norm(fa), norm(fb)):
        return False
    if "lines" not in a or "lines" not in b:
        return True
    (a0, a1), (b0, b1) = a["lines"], b["lines"]
    return a0 - gap <= b1 and b0 - gap <= a1


def _check_cross(entries, tol):
    p = []
    good = [e for e in entries if isinstance(e, dict) and e.get("label") in LABELS
            and ("lines" not in e or (isinstance(e["lines"], list) and len(e["lines"]) == 2
                                      and all(_is_int(x) for x in e["lines"])))]
    mf = [e for e in good if e["label"] == "must-fire" and "concept" in e]
    mnf = [e for e in good if e["label"] == "must-not-fire" and "concept" in e]
    clean = [e for e in good if e["label"] == "clean" and "concepts" in e]
    na = [e for e in good if e["label"] == "not-applicable" and "concept" in e and "file" not in e]
    for a in mf:
        for b in mnf:
            if a["concept"] == b["concept"] and _site_overlap(a, b, tol):
                p.append(f"{a['id']} (must-fire) and {b['id']} (must-not-fire) overlap on concept '{a['concept']}' "
                         f"(same site, within lineTolerance {tol}): a result on the trap would be scored as a hit "
                         f"on the plant")
        for c in clean:
            cs = c["concepts"]
            if (cs == "*" or a["concept"] in cs) and _site_overlap(a, c, 0):
                p.append(f"{a['id']} (must-fire) lies inside {c['id']} (clean for "
                         f"{'every concept' if cs == '*' else repr(a['concept'])}): a region cannot be both")
    for n in na:
        for e in good:
            if e is not n and e["label"] in ("must-fire", "must-not-fire") and e.get("concept") == n["concept"]:
                p.append(f"{n['id']} marks concept '{n['concept']}' not-applicable to the repository, but "
                         f"{e['id']} ({e['label']}) labels a site of it")
    return p


def validate_key(key, taxonomy=None):
    """Every problem with `key` (a parsed answer key), as human-readable strings. Empty means valid."""
    if not isinstance(key, dict):
        return ["answer key: the top level must be an object"]
    p = [f"answer key: unknown top-level property '{k}'" for k in sorted(set(key) - TOP_KEYS)]
    for k in ("schemaVersion", "repo", "keyVersion", "entries"):
        if k not in key:
            p.append(f"answer key: '{k}' is required")
    if "schemaVersion" in key and key["schemaVersion"] != "1.0":
        p.append(f"answer key: 'schemaVersion' must be \"1.0\" (got {key['schemaVersion']!r})")
    if "repo" in key and not (isinstance(key["repo"], str) and REPO_RE.match(key["repo"])):
        p.append(f"answer key: 'repo' must be owner/name (got {key['repo']!r})")
    if "keyVersion" in key and not (isinstance(key["keyVersion"], str) and SEMVER_RE.match(key["keyVersion"])):
        p.append(f"answer key: 'keyVersion' must be MAJOR.MINOR.PATCH (got {key['keyVersion']!r})")
    if "languages" in key and not (isinstance(key["languages"], list)
                                   and all(isinstance(x, str) and x for x in key["languages"])
                                   and len(set(key["languages"])) == len(key["languages"])):
        p.append("answer key: 'languages' must be an array of unique non-empty strings")
    if "theme" in key and not isinstance(key["theme"], str):
        p.append("answer key: 'theme' must be a string")
    tol = key.get("lineTolerance", DEFAULT_TOLERANCE)
    if not (_is_int(tol) and tol >= 0):
        p.append(f"answer key: 'lineTolerance' must be an integer >= 0 (got {tol!r})")
        tol = DEFAULT_TOLERANCE
    entries = key.get("entries", [])
    if not isinstance(entries, list):
        return p + ["answer key: 'entries' must be an array"]

    for i, e in enumerate(entries):
        p += _check_entry(i, e)

    seen = {}
    for i, e in enumerate(entries):
        if isinstance(e, dict) and isinstance(e.get("id"), str):
            if e["id"] in seen:
                p.append(f"entries[{i}]: duplicate id '{e['id']}' (first used by entries[{seen[e['id']]}])")
            else:
                seen[e["id"]] = i

    if taxonomy is not None:
        concepts = taxonomy_index(taxonomy)
        for i, e in enumerate(entries):
            if not isinstance(e, dict):
                continue
            where = f"entries[{i}] ({e.get('id')})"
            cs = entry_concepts(e)
            for c in (cs if isinstance(cs, list) else []):
                if not isinstance(c, str):
                    continue
                if c not in concepts:
                    p.append(f"{where}: concept '{c}' is not in the taxonomy")
                elif "cwe" in e and concepts[c].get("cwe") and concepts[c]["cwe"] != e["cwe"]:
                    p.append(f"{where}: cwe {e['cwe']} disagrees with the taxonomy's {concepts[c]['cwe']} "
                             f"for concept '{c}'")

    p += _check_cross(entries, tol)
    return p


def taxonomy_index(taxonomy):
    """{concept id: concept} from a parsed taxonomy.json."""
    if not isinstance(taxonomy, dict) or not isinstance(taxonomy.get("concepts"), list):
        raise KeyError_("taxonomy: expected {\"version\": …, \"concepts\": [ … ]}")
    out = {}
    for c in taxonomy["concepts"]:
        if isinstance(c, dict) and isinstance(c.get("id"), str):
            out[c["id"]] = c
    return out
