"""A scanner mapping (mappings/<scanner>.json): concept -> the scanner's rule-id regexes and dimensions."""
import re

UNMAPPED = "(unmapped)"


class MappingError(Exception):
    pass


class Mapping:
    def __init__(self, doc):
        if not isinstance(doc, dict) or not isinstance(doc.get("concepts"), dict):
            raise MappingError("mapping: expected {\"scanner\": …, \"concepts\": { … }}")
        self.scanner = doc.get("scanner")
        self.version = doc.get("version")
        self.concepts = {}  # concept -> ([compiled rule regex], [dimension])
        for c, spec in doc["concepts"].items():
            if not isinstance(spec, dict):
                raise MappingError(f"mapping: concepts.{c} must be an object")
            try:
                rules = [re.compile(r) for r in spec.get("rules", [])]
            except re.error as ex:
                raise MappingError(f"mapping: concepts.{c}.rules has a bad regex: {ex}")
            self.concepts[c] = (rules, list(spec.get("dimensions", [])))
        self.rule_dimension = []
        for i, rd in enumerate(doc.get("ruleDimension", []) or []):
            try:
                self.rule_dimension.append((re.compile(rd["rule"]), rd["dimension"]))
            except (KeyError, TypeError, re.error) as ex:
                raise MappingError(f"mapping: ruleDimension[{i}] is invalid: {ex}")

    def concepts_of(self, rule_id):
        """The concepts whose rules match `rule_id`, in mapping order."""
        if rule_id is None:
            return []
        return [c for c, (rules, _) in self.concepts.items() if any(r.search(rule_id) for r in rules)]

    def dimensions_of_concept(self, concept):
        return self.concepts.get(concept, ([], []))[1]

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
