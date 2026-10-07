"""Reading SARIF 2.1.0 results into flat records."""
from .paths import is_relative, norm, repo_relative


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
    """(uri, startLine, uriBaseId) of the result's first physical location; (None, None, None) for a
    repository-level result."""
    locs = result.get("locations") or []
    if not locs or not isinstance(locs[0], dict):
        return None, None, None
    phys = locs[0].get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    uri, base = art.get("uri"), art.get("uriBaseId")
    if uri is None and isinstance(art.get("index"), int):
        arts = run.get("artifacts") or []
        if 0 <= art["index"] < len(arts):
            loc = (arts[art["index"]] or {}).get("location") or {}
            uri, base = loc.get("uri"), base or loc.get("uriBaseId")
    region = phys.get("region") or {}
    line = region.get("startLine")
    if not (isinstance(line, int) and not isinstance(line, bool) and line >= 1):
        line = None
    return uri, line, base if isinstance(base, str) and base else None


def _is_absolute_uri(u):
    return u.lower().startswith("file:") or u.startswith("/") or u.startswith("\\\\") or (len(u) >= 2 and u[1] == ":")


def resolve_path(uri, base_id, run, prefixes=()):
    """(file, exact) for a result uri (contract 1.4). A uri relative to a `uriBaseId` is resolved through the run's
    `originalUriBaseIds`: bases that are themselves relative contribute their path; the top-most base is the root
    the scanner declares, so the path below it is repo-relative — unless the full absolute path reduces under a
    configured prefix, which wins. Without a base the uri goes through paths.repo_relative."""
    if base_id is None or _is_absolute_uri(uri):
        return repo_relative(uri, prefixes)
    bases = run.get("originalUriBaseIds") if isinstance(run.get("originalUriBaseIds"), dict) else {}
    rel, seen, top = [uri], set(), None
    while base_id is not None and base_id not in seen:
        seen.add(base_id)
        b = bases.get(base_id)
        if not isinstance(b, dict) or not isinstance(b.get("uri"), str) or not b["uri"]:
            break  # an undeclared root: the uri is relative to the analysis root
        if _is_absolute_uri(b["uri"]):
            top = b["uri"]
            break
        rel.insert(0, b["uri"])
        base_id = b.get("uriBaseId")
    below = norm("/".join(x.strip("/") for x in rel))
    if top is not None and prefixes:
        f, exact = repo_relative(top.rstrip("/") + "/" + below, prefixes)
        if exact:
            return f, True
    return below, is_relative(below)


def read_results(sarif, prefixes=()):
    """Every result in every run, in document order: dicts with index, run, resultIndex, ruleId, uri (as written),
    file (repo-relative when that could be established, else normalised; None without a location), pathExact
    (contract 1.4: file is repo-relative and is compared exactly), line (or None), message, properties (the result's property bag) and commitSha (set
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
            uri, line, base = _location(res, run)
            file, exact = resolve_path(uri, base, run, prefixes) if uri else (None, False)
            msg = res.get("message") or {}
            props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
            sha = props.get("commitSha")
            out.append({
                "index": len(out), "run": ri, "resultIndex": xi,
                "ruleId": _rule_id(res, run), "uri": uri, "file": file, "pathExact": bool(file) and exact,
                "line": line if uri else None,
                "message": msg.get("text") if isinstance(msg, dict) else None,
                "properties": props, "commitSha": sha if isinstance(sha, str) and sha else None,
            })
    return out
