"""A scanner mapping (mappings/<scanner>.json): concept -> the scanner results that evidence it, and dimensions.

Contract 1.1. A result belongs to a concept when one of the concept's `rules` accepts it. A rule is either
  * a regex string over the SARIF ruleId — conditioned by the concept-level `messages` / `properties`, when given; or
  * an object {"rule": regex, "messages"?: [regex], "properties"?: [name]} whose own conditions replace the
    concept-level ones for that rule (one concept often spans several scanner rules with different message formats).
`messages`: at least one regex must match the result's message.text (case-insensitive search).
`properties`: every named SARIF result property must be present and non-null (e.g. commitSha).
Mapping-level `ignore`: [{rule?, message?, reason}] — a result matching every regex given is a scanner roll-up row
(`summary`), excluded from all matching and metrics. `family` on a concept groups siblings (see scoring.py).
Contract 1.2: `scoreDimensions` on a concept names the dimensions whose SCORE measures it, for score-band lookup, when
`dimensions` (which attribute findings) is broader; without it a band looks up `dimensions`.
"""
import re

UNMAPPED = "(unmapped)"


class MappingError(Exception):
    pass


def _rx(pattern, where, flags=0):
    if not isinstance(pattern, str):
        raise MappingError(f"mapping: {where} must be a regex string (got {pattern!r})")
    try:
        return re.compile(pattern, flags)
    except re.error as ex:
        raise MappingError(f"mapping: {where} has a bad regex {pattern!r}: {ex}")


def _messages(spec, where):
    if "messages" not in spec:
        return None
    if not isinstance(spec["messages"], list) or not spec["messages"]:
        raise MappingError(f"mapping: {where}.messages must be a non-empty array of regexes")
    return [_rx(m, f"{where}.messages", re.IGNORECASE) for m in spec["messages"]]


def _properties(spec, where):
    if "properties" not in spec:
        return None
    p = spec["properties"]
    if not (isinstance(p, list) and p and all(isinstance(x, str) and x for x in p)):
        raise MappingError(f"mapping: {where}.properties must be a non-empty array of property names")
    return list(p)


class _Rule:
    def __init__(self, rule, messages, properties):
        self.rule, self.messages, self.properties = rule, messages, properties

    def accepts(self, rule_id, message, properties):
        if rule_id is None or not self.rule.search(rule_id):
            return False
        if self.messages is not None and not any(m.search(message or "") for m in self.messages):
            return False
        if self.properties is not None and not all((properties or {}).get(p) is not None for p in self.properties):
            return False
        return True


class Mapping:
    def __init__(self, doc):
        if not isinstance(doc, dict) or not isinstance(doc.get("concepts"), dict):
            raise MappingError("mapping: expected {\"scanner\": …, \"concepts\": { … }}")
        self.scanner = doc.get("scanner")
        self.version = doc.get("version")
        self.concepts = {}   # concept -> [_Rule]
        self.dims = {}       # concept -> [dimension]
        self.families = {}   # concept -> family id
        self.score_dims = {}  # concept -> [dimension] whose score measures it (1.2; default: dims)
        for c, spec in doc["concepts"].items():
            where = f"concepts.{c}"
            if not isinstance(spec, dict):
                raise MappingError(f"mapping: {where} must be an object")
            c_msgs, c_props = _messages(spec, where), _properties(spec, where)
            rules = []
            for i, r in enumerate(spec.get("rules", [])):
                w = f"{where}.rules[{i}]"
                if isinstance(r, dict):
                    if "rule" not in r:
                        raise MappingError(f"mapping: {w} needs a 'rule' regex")
                    m, p = _messages(r, w), _properties(r, w)
                    rules.append(_Rule(_rx(r["rule"], w), m if "messages" in r else c_msgs,
                                       p if "properties" in r else c_props))
                else:
                    rules.append(_Rule(_rx(r, w), c_msgs, c_props))
            self.concepts[c] = rules
            self.dims[c] = list(spec.get("dimensions", []))
            if "scoreDimensions" in spec:
                sd = spec["scoreDimensions"]
                if not (isinstance(sd, list) and sd and all(isinstance(x, str) and x for x in sd)):
                    raise MappingError(f"mapping: {where}.scoreDimensions must be a non-empty array of dimension ids")
                self.score_dims[c] = list(sd)
            if spec.get("family") is not None:
                if not isinstance(spec["family"], str) or not spec["family"]:
                    raise MappingError(f"mapping: {where}.family must be a non-empty string")
                self.families[c] = spec["family"]
        self.rule_dimension = []
        for i, rd in enumerate(doc.get("ruleDimension", []) or []):
            try:
                self.rule_dimension.append((re.compile(rd["rule"]), rd["dimension"]))
            except (KeyError, TypeError, re.error) as ex:
                raise MappingError(f"mapping: ruleDimension[{i}] is invalid: {ex}")
        self.ignore = []
        for i, ig in enumerate(doc.get("ignore", []) or []):
            w = f"ignore[{i}]"
            if not isinstance(ig, dict) or not ("rule" in ig or "message" in ig):
                raise MappingError(f"mapping: {w} needs a 'rule' and/or 'message' regex")
            self.ignore.append((_rx(ig["rule"], f"{w}.rule") if "rule" in ig else None,
                                _rx(ig["message"], f"{w}.message", re.IGNORECASE) if "message" in ig else None,
                                ig.get("reason")))

    def ignored(self, rule_id, message):
        """The reason of the first `ignore` entry matching this result, or None."""
        for rule, msg, reason in self.ignore:
            if rule is not None and (rule_id is None or not rule.search(rule_id)):
                continue
            if msg is not None and not msg.search(message or ""):
                continue
            return reason or "ignored by the mapping"
        return None

    def concepts_of(self, rule_id, message=None, properties=None):
        """The concepts that accept this result, in mapping order."""
        return [c for c, rules in self.concepts.items() if any(r.accepts(rule_id, message, properties) for r in rules)]

    def dimensions_of_concept(self, concept):
        return self.dims.get(concept, [])

    def score_dimensions_of_concept(self, concept):
        """The dimensions whose score measures the concept: `scoreDimensions` when given, else `dimensions`."""
        return self.score_dims.get(concept, self.dims.get(concept, []))

    def family_of(self, concept):
        return self.families.get(concept)

    def dimension_of(self, rule_id, concepts):
        """The scanner dimension a result belongs to: the first ruleDimension that matches its ruleId; else the
        dimension of its concept when that is unambiguous; else (unmapped)."""
        if rule_id is not None:
            for rx, template in self.rule_dimension:
                m = rx.search(rule_id)
                if m:
                    return re.sub(r"\$(\d+)", lambda g: m.group(int(g.group(1))) or "", template)
        dims = {d for c in concepts for d in self.dimensions_of_concept(c)}
        return dims.pop() if len(dims) == 1 else UNMAPPED
