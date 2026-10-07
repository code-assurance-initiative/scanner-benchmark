"""The harness's scanner-neutral taxonomy (taxonomy.json at the repository root) and what matching reads from it.

Contract 1.5: a concept may carry `"matchScope": "file"` — its defect IS a whole class, file or module, so a result of
the concept anywhere in an entry's file is on the entry's site (see scoring.py). Absent, the scope is the site: the
entry's lines decide, within the line tolerance. No other value is valid.
"""
import json
import os

TAXONOMY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "taxonomy.json")
MATCH_SCOPES = ("file",)

_default = None


def load_taxonomy(path=TAXONOMY_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def file_scope_concepts(taxonomy=None):
    """The ids of the concepts whose `matchScope` is "file" — of `taxonomy` (a parsed taxonomy.json) or, by default,
    of the harness's own taxonomy.json. Raises ValueError on a matchScope other than "file"."""
    global _default
    if taxonomy is None:
        if _default is None:
            _default = file_scope_concepts(load_taxonomy())
        return _default
    out = set()
    for c in taxonomy.get("concepts") or []:
        scope = c.get("matchScope")
        if scope is None:
            continue
        if scope not in MATCH_SCOPES:
            raise ValueError(f"taxonomy: concept {c.get('id')!r} has matchScope {scope!r}; the only value is \"file\"")
        out.add(c["id"])
    return frozenset(out)
