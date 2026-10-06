"""Hand-made keys and SARIF for the tests."""
import json
import os

from cai_bench.keyfile import load_json
from cai_bench.mapping import Mapping
from cai_bench.sarif import read_results
from cai_bench.scoring import score

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
TAXONOMY = load_json(os.path.join(FIXTURES, "taxonomy.json"))
MAPPING_DOC = load_json(os.path.join(FIXTURES, "mapping.json"))


def key(*entries, **top):
    k = {"schemaVersion": "1.0", "repo": "code-assurance-initiative/bench-test", "keyVersion": "1.0.0",
         "entries": list(entries)}
    k.update(top)
    return k


def mf(id, concept, file=None, lines=None, **kw):
    return _e(id, "must-fire", concept=concept, file=file, lines=lines, **kw)


def mnf(id, concept, file=None, lines=None, **kw):
    return _e(id, "must-not-fire", concept=concept, file=file, lines=lines, **kw)


def clean(id, concepts, file=None, lines=None, **kw):
    return _e(id, "clean", concepts=concepts, file=file, lines=lines, **kw)


def na(id, concept, **kw):
    return _e(id, "not-applicable", concept=concept, **kw)


def band(id, concept, lo, hi, **kw):
    return _e(id, "score-band", concept=concept, band=[lo, hi], **kw)


def _e(id, label, **kw):
    e = {"id": id, "label": label, "rationale": "test"}
    e.update({k: v for k, v in kw.items() if v is not None})
    return e


def res(rule, uri=None, line=None, message=None, commit=None):
    """One SARIF result; no uri = repository-level (no locations)."""
    r = {"ruleId": rule, "message": {"text": message if message is not None else f"{rule} says so"}}
    if commit is not None:
        r["properties"] = {"commitSha": commit}
    if uri is not None:
        loc = {"artifactLocation": {"uri": uri}}
        if line is not None:
            loc["region"] = {"startLine": line}
        r["locations"] = [{"physicalLocation": loc}]
    return r


def sarif(*results):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": list(results)}]}


def run(k, *results, scores=None, prefixes=(), mapping=None):
    """Score hand-made results against a hand-made key; returns the report."""
    doc = sarif(*results)
    return score(json.loads(json.dumps(k)), read_results(doc, prefixes), Mapping(mapping or MAPPING_DOC), scores)


def outcomes(report):
    """[(result index, outcome, entry id)] — what each result became."""
    return [(r["index"], r["outcome"], r["entryId"]) for r in report["results"]]


def entry(report, id):
    return next(e for e in report["entries"] if e["id"] == id)
