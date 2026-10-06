"""python3 -m cai_bench validate | score | sha256"""
import argparse
import hashlib
import json
import sys

from . import CONTRACT_VERSION, __version__
from .keyfile import KeyError_, load_json, validate_key
from .mapping import Mapping, MappingError
from .sarif import SarifError, read_results
from .scoring import render, score


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _load(path, what):
    try:
        return load_json(path)
    except OSError as ex:
        raise SystemExit(_fail(f"{what}: cannot read {path}: {ex.strerror}"))
    except (ValueError, UnicodeDecodeError) as ex:
        raise SystemExit(_fail(f"{what}: {path} is not valid JSON: {ex}"))


def _fail(msg, code=2):
    print(f"error: {msg}", file=sys.stderr)
    return code


def cmd_validate(a):
    key = _load(a.key, "answer key")
    taxonomy = _load(a.taxonomy, "taxonomy") if a.taxonomy else None
    try:
        problems = validate_key(key, taxonomy)
    except KeyError_ as ex:
        return _fail(str(ex))
    if problems:
        for p in problems:
            print(f"INVALID {a.key}: {p}", file=sys.stderr)
        print(f"{len(problems)} problem(s) in {a.key}", file=sys.stderr)
        return 1
    n = len(key["entries"])
    print(f"OK {a.key}: {n} entries" + ("" if taxonomy else " (concepts not checked: no --taxonomy)"))
    return 0


def cmd_score(a):
    key = _load(a.key, "answer key")
    problems = validate_key(key)
    if problems:
        for p in problems:
            print(f"INVALID {a.key}: {p}", file=sys.stderr)
        return _fail(f"refusing to score against an invalid key ({len(problems)} problem(s))", 1)
    sarif = _load(a.sarif, "SARIF")
    try:
        mapping = Mapping(_load(a.mapping, "mapping"))
        results = read_results(sarif, a.repo_root_prefix or ())
    except (MappingError, SarifError) as ex:
        return _fail(str(ex))
    scores = _load(a.scores, "scores") if a.scores else {}
    if not isinstance(scores, dict):
        return _fail("scores: expected an object {concept-or-dimension: score}")

    report = score(key, results, mapping, scores)
    report = {
        "harness": {"name": "cai_bench", "version": __version__, "contract": CONTRACT_VERSION},
        "key": {"path": a.key, "sha256": sha256_file(a.key), "repo": key.get("repo"), "keyVersion": key.get("keyVersion")},
        "sarif": {"path": a.sarif, "sha256": sha256_file(a.sarif), "results": len(results)},
        "mapping": {"path": a.mapping, "scanner": mapping.scanner, "version": mapping.version},
        **report,
    }
    print(f"{key.get('repo')} v{key.get('keyVersion')}  x  {mapping.scanner} {mapping.version or ''}  "
          f"({len(results)} results, line tolerance ±{report['lineTolerance']})\n")
    print(render(report))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"\nwrote {a.json}")
    return 0


def cmd_sha256(a):
    try:
        print(sha256_file(a.key))
    except OSError as ex:
        return _fail(f"cannot read {a.key}: {ex.strerror}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m cai_bench", description="Scanner benchmark harness (contract v1).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="check an answer key against the schema and (optionally) the taxonomy")
    v.add_argument("--key", required=True)
    v.add_argument("--taxonomy")
    v.set_defaults(fn=cmd_validate)

    s = sub.add_parser("score", help="score a scanner's SARIF report against an answer key")
    s.add_argument("--key", required=True)
    s.add_argument("--sarif", required=True)
    s.add_argument("--mapping", required=True, help="mappings/<scanner>.json")
    s.add_argument("--scores", help="JSON {concept-or-dimension: 0-100 score} for score-band entries")
    s.add_argument("--repo-root-prefix", action="append",
                   help="path prefix to strip from result paths (repeatable); suffix matching works without it")
    s.add_argument("--json", help="write the full report, every individual outcome included, here")
    s.set_defaults(fn=cmd_score)

    h = sub.add_parser("sha256", help="print the sha256 of an answer key's bytes (for registry.json)")
    h.add_argument("--key", required=True)
    h.set_defaults(fn=cmd_sha256)

    a = ap.parse_args(argv)
    return a.fn(a)
