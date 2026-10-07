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
Contract 1.3: `parent` on a concept names its umbrella concept (a key entry naming the umbrella also matches the
child's results, see scoring.py); a mapping-level `locationFromMessage` list [{rule, message?, pattern, source?}]
gives a location-less result the `file` (and `line`) its message names.
Contract 1.4: a mapping-level `unmapped` list [{concept, reason}] names the taxonomy concepts no rule of this scanner
detects; each is in `concepts` with `rules: []` and `dimensions: []`, and a plant of it is scored an FN. A
mapping-level `summaryOfConcept` list [{rule, message, reason}] declares the rows that summarise their concept across
the repository without naming a site (see scoring.py).
Contract 1.5: a mapping-level `sitesFromMessage` list [{rule, message?, concepts?, within?, patterns, source?}] reads
the further sites a result names in its message (the other members of a clone group): each is an ADDITIONAL location
of the result (see scoring.py).
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


def _positive(text):
    return int(text) if text and text.isdigit() and int(text) >= 1 else None


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
        self.parents = {}    # concept -> umbrella concept (1.3)
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
            if spec.get("parent") is not None:
                if not isinstance(spec["parent"], str) or not spec["parent"]:
                    raise MappingError(f"mapping: {where}.parent must be a non-empty concept id")
                self.parents[c] = spec["parent"]
        for c, p in self.parents.items():
            if p not in self.concepts:
                raise MappingError(f"mapping: concepts.{c}.parent names '{p}', which is not a concept of the mapping")
            seen = {c}
            while p is not None:
                if p in seen:
                    raise MappingError(f"mapping: concepts.{c}.parent forms a cycle through '{p}'")
                seen.add(p)
                p = self.parents.get(p)
        self.unmapped = {}  # 1.4: concept -> why no rule of this scanner maps it
        for i, u in enumerate(doc.get("unmapped", []) or []):
            w = f"unmapped[{i}]"
            if not isinstance(u, dict) or not isinstance(u.get("concept"), str) or not (u.get("reason") or "").strip():
                raise MappingError(f"mapping: {w} needs a 'concept' and a one-line 'reason'")
            c = u["concept"]
            if c not in self.concepts:
                raise MappingError(f"mapping: {w} names '{c}', which is not a concept of the mapping")
            if self.concepts[c] or self.dims[c]:
                raise MappingError(f"mapping: {w}: '{c}' is listed as unmapped but has rules or dimensions")
            self.unmapped[c] = u["reason"]
        self.summaries = []  # 1.4: rows that summarise a concept across the repository, with no site
        for i, sm in enumerate(doc.get("summaryOfConcept", []) or []):
            w = f"summaryOfConcept[{i}]"
            if not isinstance(sm, dict) or not ("rule" in sm and "message" in sm) or not (sm.get("reason") or "").strip():
                raise MappingError(f"mapping: {w} needs a 'rule' regex, a 'message' regex and a 'reason'")
            self.summaries.append((_rx(sm["rule"], f"{w}.rule"), _rx(sm["message"], f"{w}.message", re.IGNORECASE),
                                   sm["reason"]))
        self.location_from_message = []
        for i, lm in enumerate(doc.get("locationFromMessage", []) or []):
            w = f"locationFromMessage[{i}]"
            if not isinstance(lm, dict) or "rule" not in lm or "pattern" not in lm:
                raise MappingError(f"mapping: {w} needs a 'rule' regex and a 'pattern' regex")
            pat = _rx(lm["pattern"], f"{w}.pattern")
            if "file" not in pat.groupindex:
                raise MappingError(f"mapping: {w}.pattern needs a named group 'file' (and optionally 'line')")
            self.location_from_message.append((_rx(lm["rule"], f"{w}.rule"),
                                               _rx(lm["message"], f"{w}.message", re.IGNORECASE)
                                               if "message" in lm else None, pat))
        self.sites_from_message = []  # 1.5: further sites of a result, named in its message
        for i, sm in enumerate(doc.get("sitesFromMessage", []) or []):
            w = f"sitesFromMessage[{i}]"
            if not isinstance(sm, dict) or "rule" not in sm:
                raise MappingError(f"mapping: {w} needs a 'rule' regex")
            pats = sm.get("patterns")
            if not isinstance(pats, list) or not pats:
                raise MappingError(f"mapping: {w}.patterns must be a non-empty array of regexes")
            compiled = []
            for j, p in enumerate(pats):
                rx = _rx(p, f"{w}.patterns[{j}]")
                if "file" not in rx.groupindex:
                    raise MappingError(f"mapping: {w}.patterns[{j}] needs a named group 'file' (and optionally 'line', "
                                       f"'endLine')")
                compiled.append(rx)
            within = None
            if "within" in sm:
                within = _rx(sm["within"], f"{w}.within")
                if "sites" not in within.groupindex:
                    raise MappingError(f"mapping: {w}.within needs a named group 'sites'")
            concepts = None
            if "concepts" in sm:
                concepts = sm["concepts"]
                if not (isinstance(concepts, list) and concepts and all(isinstance(c, str) and c for c in concepts)):
                    raise MappingError(f"mapping: {w}.concepts must be a non-empty array of concept ids")
                unknown = [c for c in concepts if c not in self.concepts]
                if unknown:
                    raise MappingError(f"mapping: {w}.concepts names {unknown}, not concepts of the mapping")
            self.sites_from_message.append((_rx(sm["rule"], f"{w}.rule"),
                                            _rx(sm["message"], f"{w}.message", re.IGNORECASE) if "message" in sm
                                            else None, set(concepts) if concepts else None, within, compiled))
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

    def summary_of(self, rule_id, message):
        """The reason of the first `summaryOfConcept` entry matching this result, or None (contract 1.4)."""
        for rule, msg, reason in self.summaries:
            if rule is not None and (rule_id is None or not rule.search(rule_id)):
                continue
            if msg is not None and not msg.search(message or ""):
                continue
            return reason
        return None

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

    def ancestors(self, concept):
        """The umbrella concepts above `concept` (contract 1.3 `parent`), nearest first."""
        out, p = [], self.parents.get(concept)
        while p is not None:
            out.append(p)
            p = self.parents.get(p)
        return out

    def location_in_message(self, rule_id, message):
        """(file, line or None) named by the message of a result, per the first `locationFromMessage` entry whose
        rule (and message) regexes match and whose pattern finds a site; None when none does."""
        if rule_id is None or not message:
            return None
        for rule, msg, pat in self.location_from_message:
            if not rule.search(rule_id) or (msg is not None and not msg.search(message)):
                continue
            m = pat.search(message)
            if m and m.group("file"):
                line = m.groupdict().get("line")
                return m.group("file"), (int(line) if line and line.isdigit() and int(line) >= 1 else None)
        return None

    def sites_in_message(self, rule_id, message, concepts):
        """[(file, line or None, endLine or None)] — every site the message names per the `sitesFromMessage` entries
        whose rule (and message) regexes match and whose `concepts` (if given) include one of the result's `concepts`,
        in message order, without repeats. With `within`, the patterns search only its first match's `sites` group."""
        if rule_id is None or not message:
            return []
        out = []
        for rule, msg, cs, within, pats in self.sites_from_message:
            if not rule.search(rule_id) or (msg is not None and not msg.search(message)):
                continue
            if cs is not None and not cs.intersection(concepts or ()):
                continue
            text = message
            if within is not None:
                m = within.search(message)
                if not m or m.group("sites") is None:
                    continue
                text = m.group("sites")
            for pat in pats:
                for m in pat.finditer(text):
                    if not m.group("file"):
                        continue
                    g = m.groupdict()
                    line, end = (_positive(g.get("line")), _positive(g.get("endLine")))
                    site = (m.group("file"), line, end if line is not None else None)
                    if site not in out:
                        out.append(site)
        return out

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
