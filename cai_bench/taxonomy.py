"""The harness's scanner-neutral taxonomy (taxonomy.json at the repository root) and what matching reads from it.

Contract 1.5: a concept may carry `"matchScope": "file"` — its defect IS a whole class, file or module, so a result of
the concept anywhere in an entry's file is on the entry's site (see scoring.py).
Contract 1.6: or `"matchScope": "resource"` — an IaC concept whose defect is a property (usually an absence) of a whole
resource, so a result of the concept anywhere in the entry's resource (YAML document, Dockerfile stage, top-level HCL
block; see resources.py) is on the entry's site.
Contract 1.7: or `"matchScope": "element"` — a markup element's property that can be an absence (no accessible name, no
label, a missing required ARIA state …), so a result of the concept anywhere in the element's START TAG is on the site
of an entry whose lines lie in it; or `"matchScope": "group"` — a relation among several files or modules none of
which is more its site than another (a dependency cycle), so a result of the concept located in, or listing, the
entry's file is on the entry's site. Absent, the scope is the site: the entry's lines decide, within the line
tolerance. No other value is valid.
"""
import json
import os

TAXONOMY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "taxonomy.json")
MATCH_SCOPES = ("file", "resource", "element", "group")

_default = {}


def load_taxonomy(path=TAXONOMY_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def scope_concepts(scope, taxonomy=None):
    """The ids of the concepts whose `matchScope` is `scope` — of `taxonomy` (a parsed taxonomy.json) or, by default,
    of the harness's own taxonomy.json. Raises ValueError on a matchScope that is not one of MATCH_SCOPES."""
    if taxonomy is None:
        if scope not in _default:
            _default[scope] = scope_concepts(scope, load_taxonomy())
        return _default[scope]
    out = set()
    for c in taxonomy.get("concepts") or []:
        got = c.get("matchScope")
        if got is None:
            continue
        if got not in MATCH_SCOPES:
            raise ValueError(f"taxonomy: concept {c.get('id')!r} has matchScope {got!r}; valid: {MATCH_SCOPES}")
        if got == scope:
            out.add(c["id"])
    return frozenset(out)


def file_scope_concepts(taxonomy=None):
    """Contract 1.5: the concepts whose defect is a whole class, file or module."""
    return scope_concepts("file", taxonomy)


def resource_scope_concepts(taxonomy=None):
    """Contract 1.6: the IaC concepts whose defect is a property of a whole resource."""
    return scope_concepts("resource", taxonomy)


def element_scope_concepts(taxonomy=None):
    """Contract 1.7: the markup concepts whose defect is a property — possibly an absence — of one element."""
    return scope_concepts("element", taxonomy)


def group_scope_concepts(taxonomy=None):
    """Contract 1.7: the concepts whose defect is a relation among several files, each equally its site."""
    return scope_concepts("group", taxonomy)
