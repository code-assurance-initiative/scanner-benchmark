"""Reading SARIF 2.1.0 results into flat records."""
from .paths import norm


class SarifError(Exception):
    pass


def _rule_id(result, run):
    if isinstance(result.get("ruleId"), str):
        return result["ruleId"]
    rule = result.get("rule")
    if isinstance(rule, dict) and isinstance(rule.get("id"), str):
        return rule["id"]
    idx = result.get("ruleIndex", rule.get("index") if isinstance(rule, dict) else None)
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    if isinstance(idx, int) and 0 <= idx < len(rules) and isinstance(rules[idx], dict):
        return rules[idx].get("id")
    return None


def _location(result, run):
    """(uri, startLine) of the result's first physical location; (None, None) for a repository-level result."""
    locs = result.get("locations") or []
    if not locs or not isinstance(locs[0], dict):
        return None, None
    phys = locs[0].get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    uri = art.get("uri")
    if uri is None and isinstance(art.get("index"), int):
        arts = run.get("artifacts") or []
        if 0 <= art["index"] < len(arts):
            uri = ((arts[art["index"]] or {}).get("location") or {}).get("uri")
    region = phys.get("region") or {}
    line = region.get("startLine")
    if not (isinstance(line, int) and not isinstance(line, bool) and line >= 1):
        line = None
    return uri, line


def read_results(sarif, prefixes=()):
    """Every result in every run, in document order: dicts with index, run, resultIndex, ruleId, uri (as written),
    file (normalised, or None), line (or None), message, properties (the result's property bag) and commitSha (set
    on a history finding: SARIF properties.commitSha)."""
    if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
        raise SarifError("SARIF: expected a top-level object with a 'runs' array")
    out = []
    for ri, run in enumerate(sarif["runs"]):
        if not isinstance(run, dict):
            raise SarifError(f"SARIF: runs[{ri}] is not an object")
        for xi, res in enumerate(run.get("results") or []):
            if not isinstance(res, dict):
                raise SarifError(f"SARIF: runs[{ri}].results[{xi}] is not an object")
            uri, line = _location(res, run)
            msg = res.get("message") or {}
            props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
            sha = props.get("commitSha")
            out.append({
                "index": len(out), "run": ri, "resultIndex": xi,
                "ruleId": _rule_id(res, run), "uri": uri, "file": norm(uri, prefixes) if uri else None,
                "line": line if uri else None,
                "message": msg.get("text") if isinstance(msg, dict) else None,
                "properties": props, "commitSha": sha if isinstance(sha, str) and sha else None,
            })
    return out
