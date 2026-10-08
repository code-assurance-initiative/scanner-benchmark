"""Matching a scanner's results against an answer key, and the metrics (docs/CONTRACT.md, "Matching" and "Metrics").

A result the mapping's `ignore` list matches is a scanner roll-up row: outcome `summary`, taken out before matching
and counted in no metric.

Concept families (contract 1.1): when the mapping gives concepts a common `family`, a result of a SIBLING concept may
match a `must-fire` or `must-not-fire` entry at the entry's site — but only after every exact-concept match has been
made, so a result of the entry's own concept always wins. The rule is symmetric on purpose: a sibling at a plant is a
hit, a sibling at a trap is caught in the trap, and a sibling result off every entry is noise (siblings of a covered
concept count as covered). `clean` and `not-applicable` entries match their listed concepts exactly.

An entry with a `commit` matches a result whose SARIF properties.commitSha starts with it (case-insensitive) in the
same file, at any line — the commit, not the line, is the site of a history finding.

Subjects (contract 1.2): an entry with a `subject` (a package id, a framework moniker, …) also matches a result of its
concept that has no location, or whose location is a dependency manifest (MANIFEST_NAMES), when the subject occurs in
the result's message as a whole token (subject_in). A located subject entry still matches on its site as before; a
repository-level one needs the subject. Matching goes in passes — exact concept on the site, exact concept by subject,
family sibling on the site, family sibling by subject — so a stronger match is always preferred, and consumption and
redundancy are one-to-one as for any other match. A location-less result that names the subject of an entry is never
taken by a repository-level entry without a subject: the subject entry, not the repository, is its site.

Umbrella concepts (contract 1.3): a mapping concept may name a `parent`. A result keeps the ONE concept its scanner
row denotes, but for matching it also counts as each of that concept's ancestors (`matchConcepts`), in the same pass
as an exact match: an entry naming the umbrella (written before the precise concepts existed) matches what it matched
before, while an entry naming a precise concept is matched only by results of that concept — never by the umbrella's
other children nor by a residue result of the umbrella itself.

Location from the message (contract 1.3): a result with no SARIF location whose message names its site, per the
mapping's `locationFromMessage`, is given that file (and line) before matching (`locationSource`: sarif | message |
none). A SARIF location is never replaced.

File-level recall (contract 1.3) is a SECONDARY diagnostic and changes no outcome: a must-fire entry is file-level
found when it is a TP, or when any result of its concept (exactly, as an umbrella's child, or as a family sibling) is
located anywhere in the entry's file. A repository-level entry is file-level found only when it is a TP.

Precedence when one result could match several entries — the first that applies decides it:
  1. a `must-fire` entry it can be consumed by (one-to-one, key order, located entries before repository-level ones)
                                                                                                   -> tp
  2. a `must-fire` entry already consumed (another result on the same planted site)                -> redundant
  3. a `must-not-fire` trap                                                                        -> trap-fp
  4. a `clean` region                                                                              -> clean-fp
  5. a `not-applicable` concept                                                                    -> na-fp
  6. a result the mapping declares a summary row (`summaryOfConcept`), with no location (none in SARIF, none
     from the message), of a concept the key plants at located sites (contract 1.4)                -> summary-of-concept
  7. any other result of a concept the key covers                                                  -> unmatched-fp
  8. a result of a concept the key does not cover at all                                           -> uncovered
Outcomes 3–5 and 7 are noise. `redundant` and `summary-of-concept` are neither hits nor noise (`summary-of-concept`
is outside the result count). `uncovered` is reported, never counted as noise.

Paths (contract 1.4): a result path made repository-relative (paths.repo_relative; the SARIF uriBaseId chain, the
configured prefixes, a built-in checkout root, or the checkout directory named after the key's repo) is compared with
an entry's path EXACTLY; one that cannot be, and every site read out of a message, falls back to the suffix rule
(`pathMatch`: exact | suffix).

Location equivalence (contract 1.5). File-scope concepts: a concept whose taxonomy `matchScope` is "file" (its defect
IS a whole class, file or module) matches an entry that names it anywhere in the entry's file — plants, traps and
clean regions that list it alike, never through a "*" region; consumption and redundancy stay one-to-one. Clone-group
sites: the mapping's `sitesFromMessage` gives a result the further sites its message names (the other members of a
clone group) as ADDITIONAL locations, and the result is on an entry's site when ANY of its locations is. Matching
prefers the stronger location in every pass: the result's own location on the entry's lines, then (file-scope) its
own location anywhere in the file, then a message site. Each result row says which location decided
(`locationSource`: sarif | message | sitesFromMessage | none, and `site`) and whether the file scope did
(`matchScope: "file"`). `score(..., contract="1.4")` scores without either rule (a frozen 1.4 measurement re-scores
exactly).

Location equivalence (contract 1.6). Resource-scope concepts: an IaC concept whose taxonomy `matchScope` is "resource"
(its defect is a property, usually an ABSENCE, of a whole resource: no limits, no probes, no securityContext, no USER,
no HEALTHCHECK) matches an entry that names it anywhere in the entry's RESOURCE — one YAML document, one Dockerfile
build stage (the lines before the first FROM are in every stage), one top-level HCL block (resources.py) — plants,
traps and clean regions that list it alike, never through a "*" region; consumption and redundancy stay one-to-one, and
a result on the entry's lines is preferred. The boundaries are read from the unit's files (`source`: a callable
path -> text, resources.dir_source / git_source); a file the source cannot read keeps the line rule and its entry row
says `matchScope: "resource-unavailable"` (an unsupported file type: "resource-unsupported"). `score(...,
contract="1.5")` scores without the resource rule.

Contract 1.7. (1) Assignment: which plant a result is consumed by no longer depends on key or result order. Among all
one-to-one assignments of results to plants the scorer takes one that finds the MOST plants; among those, the one with
the most matches of the strongest kind, then of the next (the passes and location levels above, the result's own
location on the entry's lines counting before one within the line tolerance); remaining ties go to key order, then
result order. Traps, clean regions and redundancy are unchanged (a trap or clean region is not consumed). (2) Subjects:
a mapping may say where a message STATES its subject (`subjectFromMessage`); the subjects of entries are then searched
in that part only (`subjectText` in the result row), so an advisory about one package that names its parent as the
path it arrived by is about the package. (3) Group scope: a concept whose taxonomy `matchScope` is "group" (a relation
among several files, each equally its site: a dependency cycle) matches an entry that names it at a result located in,
or listing, the entry's file. (4) Element scope: a concept whose taxonomy `matchScope` is "element" (a markup element's
property that can be an absence) matches an entry that names it at a result anywhere in the START TAG the entry's lines
lie in (resources.markup_start_tags); boundaries as for the resource scope ("element-unavailable",
"element-unsupported"). `score(..., contract="1.6")` scores without all four.
"""
import re

from . import CONTRACT_VERSION
from .keyfile import entry_concepts, line_tolerance
from .mapping import UNMAPPED
from .paths import norm, path_match, repo_relative, same_file
from .resources import ELEMENT, RESOURCE, UNAVAILABLE, UNSUPPORTED, ResourceIndex
from .taxonomy import element_scope_concepts, file_scope_concepts, group_scope_concepts, resource_scope_concepts

NOISE = ("trap-fp", "clean-fp", "na-fp", "unmatched-fp")
NO_RULE = "(no scanner rule)"  # by_dimension row: entries whose concept no dimension of the scanner maps
STAR = "*"


# --- matching -------------------------------------------------------------------------------------------------------

def _applies(entry, concept):
    cs = entry_concepts(entry)
    return cs == STAR or concept in cs


def _covers(entry, result, tol, whole_file=False):
    """The result's location (or one site of it: any dict with file, line, pathExact, commitSha) lies on the entry's
    (located) site. `clean` regions are exact; plants/traps take ±tol; an entry pinned to a commit takes any line of its
    file in that commit; with `whole_file` (contract 1.5, a file-scope concept) any line of the entry's file."""
    if result["file"] is None:
        return False
    if not same_file(result, entry["_file"]):
        return False
    if "commit" in entry:
        sha = result.get("commitSha")
        return bool(sha) and sha.lower().startswith(entry["commit"].lower())
    if "lines" not in entry or whole_file:
        return True
    if result["line"] is None:
        return False
    lo, hi = entry["lines"]
    t = 0 if entry["label"] == "clean" else tol
    if result.get("endLine"):  # contract 1.5: a message site stating its span covers the entry when the two overlap
        return result["line"] <= hi + t and max(result["endLine"], result["line"]) >= lo - t
    return lo - t <= result["line"] <= hi + t


FAMILY_LABELS = ("must-fire", "must-not-fire")

# Dependency manifests and lock files (lower-case basenames). A dependency/licence/EOL result located in one of them
# names its package in the message; the line is often 1 or the first reference, not the planted declaration.
MANIFEST_NAMES = frozenset("""
directory.packages.props directory.build.props directory.build.targets packages.config packages.lock.json global.json
nuget.config paket.dependencies paket.lock package.json package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml
bun.lockb deno.json deno.lock requirements.txt pipfile pipfile.lock pyproject.toml poetry.lock uv.lock setup.py setup.cfg
go.mod go.sum cargo.toml cargo.lock pom.xml build.gradle build.gradle.kts settings.gradle settings.gradle.kts
gradle.lockfile gemfile gemfile.lock composer.json composer.lock mix.exs mix.lock pubspec.yaml pubspec.lock
package.swift package.resolved
""".split())
MANIFEST_SUFFIXES = (".csproj", ".fsproj", ".vbproj", ".sqlproj")
_REQUIREMENTS = re.compile(r"^requirements[\w.-]*\.(?:txt|in)$")


def is_manifest(path):
    """True when the (normalised) path names a dependency manifest or lock file."""
    if not path:
        return False
    name = path.rsplit("/", 1)[-1].lower()
    return name in MANIFEST_NAMES or name.endswith(MANIFEST_SUFFIXES) or bool(_REQUIREMENTS.match(name))


_SUBJECT_RX = {}


def subject_in(subject, text):
    """True when `subject` occurs in `text` as a whole token, case-insensitively. A token is bounded by anything but
    a word character, and a `.`, `-` or `/` counts as part of the token when a word character is on its far side:
    "GPL-2.0" is not in "LGPL-2.0" nor in "GPL-2.0-only", "Newtonsoft.Json" is not in "Newtonsoft.Json.Bson", but
    "Newtonsoft.Json" is in "Newtonsoft.Json 12.0.3", "Newtonsoft.Json@12.0.3", "(Newtonsoft.Json)" and at the end
    of a sentence ("… Newtonsoft.Json.")."""
    if not text or not subject:
        return False
    rx = _SUBJECT_RX.get(subject)
    if rx is None:
        rx = _SUBJECT_RX[subject] = re.compile(
            r"(?<!\w)(?<!\w[.\-/])" + re.escape(subject.strip()) + r"(?!\w)(?![.\-/]\w)", re.IGNORECASE)
    return rx.search(text) is not None


def _stext(result):
    """The text a result's subjects are searched in: the part of the message that states its subject (contract 1.7,
    mapping `subjectFromMessage`), else the whole message."""
    return result.get("subjectText") or result.get("message")


def _subject_hit(entry, result):
    """The entry's subject is named by a result that has no location or sits in a manifest (concepts not checked)."""
    subject = entry.get("subject")
    if not subject:
        return False
    if result["file"] is not None and not is_manifest(result["file"]):
        return False
    return subject_in(subject, _stext(result))


# The passes of matching, strongest first: (family sibling?, by subject?).
PASSES = ((False, False), (False, True), (True, False), (True, True))


def _mc(result):
    """The concepts a result counts as for matching: its own, then their umbrella ancestors (contract 1.3)."""
    return result.get("matchConcepts", result["concepts"])


def _result_concepts_for(entry, result, family_of=None):
    """The result's concepts this entry speaks about (for "*": all of them, or (unmapped) when it has none). With
    `family_of`, the result's concepts that are siblings of a plant's/trap's concept instead."""
    cs = entry_concepts(entry)
    if cs == STAR:
        return list(_mc(result)) or [UNMAPPED]
    if family_of is None:
        return [c for c in _mc(result) if c in cs]
    if entry["label"] not in FAMILY_LABELS:
        return []
    fam = family_of(entry["concept"])
    return [c for c in _mc(result) if fam is not None and family_of(c) == fam] if fam else []


# Location levels of matching (contract 1.5), strongest first: the result's own location on the entry's lines; then
# also anywhere in the entry's file for a file-scope concept, or (1.6) in the entry's resource for a resource-scope
# concept, or (1.7) in the entry's start tag for an element-scope concept, or in the entry's file for a group-scope
# concept; then also every further site its message names.
SITE, FILE_SCOPE, MESSAGE_SITES = 0, 1, 2
WHOLE_FILE_SCOPES = ("file", "group")  # scopes in which an entry's site is its whole file
SCOPES = WHOLE_FILE_SCOPES + (RESOURCE, ELEMENT)


class Matcher:
    def __init__(self, entries, results, tol, mapping=None, file_scope=frozenset(), resource_scope=frozenset(),
                 resources=None, element_scope=frozenset(), group_scope=frozenset(), optimal=False):
        self.entries = [dict(e, _file=norm(e["file"])) if "file" in e else dict(e, _file=None)
                        for e in entries if e["label"] != "score-band"]
        self.results = results
        self.tol = tol
        self.file_scope = frozenset(file_scope)
        self.resource_scope = frozenset(resource_scope)
        self.element_scope = frozenset(element_scope)
        self.group_scope = frozenset(group_scope)
        self.bounded = {RESOURCE: self.resource_scope, ELEMENT: self.element_scope}
        self.optimal = optimal
        self.resources = resources if resources is not None else ResourceIndex(None)
        self._entry_resources = {}
        self.levels = ([SITE] + ([FILE_SCOPE] if self.file_scope or self.resource_scope or self.element_scope
                                 or self.group_scope else [])
                       + ([MESSAGE_SITES] if any(r.get("sites") for r in results) else []))
        self.widest = self.levels[-1]
        self.family_of = mapping.family_of if mapping is not None else (lambda c: None)
        self.located = [e for e in self.entries if e["_file"] is not None]
        self.subjected = [e for e in self.entries if e.get("subject")]
        covered = set()
        for e in self.entries:
            cs = entry_concepts(e)
            if cs != STAR:
                covered.update(cs)
        fams = {self.family_of(c) for c in covered} - {None}
        if mapping is not None and fams:
            covered.update(c for c, f in mapping.families.items() if f in fams)
        self.covered = covered

    @staticmethod
    def _scoped(entry, concepts, scope):
        """The entry NAMES a concept of `scope` (a plant's or trap's own concept, a clean region's listed one; never a
        "*" region) that the result counts as, or (family pass) the plant's or trap's own concept is in `scope`."""
        if not scope or entry_concepts(entry) == STAR:
            return False
        if entry["label"] in FAMILY_LABELS and entry["concept"] in scope:
            return True
        return any(c in scope for c in concepts)

    def _file_scoped(self, entry, concepts):
        """Contract 1.5 (file scope) and 1.7 (group scope): the entry's site is its whole file for these result
        concepts — "file", "group", or None."""
        if self._scoped(entry, concepts, self.file_scope):
            return "file"
        if self._scoped(entry, concepts, self.group_scope):
            return "group"
        return None

    def scope_status(self, entry, scope=RESOURCE):
        """Contract 1.6 (scope "resource") and 1.7 ("element"), for a located entry with lines that names a concept of
        the scope: (status, boundaries, ids of the boundaries the entry's lines lie in) — status "<scope>",
        "<scope>-unavailable" or "<scope>-unsupported"; None for any other entry."""
        k = (entry["id"], scope)
        if k in self._entry_resources:
            return self._entry_resources[k]
        got = None
        cs = entry_concepts(entry)
        concepts = self.bounded[scope]
        if (concepts and entry["_file"] is not None and "lines" in entry and "commit" not in entry
                and cs != STAR and any(c in concepts for c in cs)):
            b = self.resources.get(entry["_file"], scope)
            if b == UNAVAILABLE:
                got = (f"{scope}-unavailable", None, None)
            elif b == UNSUPPORTED:
                got = (f"{scope}-unsupported", None, None)
            else:
                got = (scope, b, b.ids_over(*entry["lines"]))
        self._entry_resources[k] = got
        return got

    def resource_status(self, entry):
        """Contract 1.6: scope_status for the resource scope."""
        return self.scope_status(entry, RESOURCE)

    def _in_bounds(self, entry, concepts, loc, scope):
        """Contract 1.6 / 1.7: the location lies in the entry's resource / start tag (same file, a line in a boundary
        the entry's lines are in) and the entry names a concept of that scope the result counts as."""
        if not self._scoped(entry, concepts, self.bounded[scope]):
            return False
        st = self.scope_status(entry, scope)
        if st is None or st[0] != scope or not _covers(entry, loc, self.tol, whole_file=True):
            return False
        return bool(st[1].ids_at(loc.get("line")) & st[2])

    def covering(self, entry, result, concepts, level=None):
        """(location, scope) by which the result lies on the located entry's site at `level` (default: the widest):
        location is the result itself or one of its message sites, scope "site", "file", "group", "resource" or
        "element"; None when it does not."""
        level = self.widest if level is None else level
        scoped = level >= FILE_SCOPE
        whole = self._file_scoped(entry, concepts) if scoped else None
        for loc in [result] + (result.get("sites") or [] if level >= MESSAGE_SITES else []):
            if _covers(entry, loc, self.tol):
                return loc, "site"
            if whole and _covers(entry, loc, self.tol, whole_file=True):
                return loc, whole
            if scoped:
                for sc in (RESOURCE, ELEMENT):
                    if self._in_bounds(entry, concepts, loc, sc):
                        return loc, sc
        return None

    def _on_located(self, result, c):
        return any(self.covering(L, result, [c]) for L in self.located if _applies(L, c))

    def _outside_located(self, result, concepts):
        """The result lies outside every located entry of (one of) its concepts (at the widest level)."""
        return any(not self._on_located(result, c) for c in concepts)

    def matches(self, entry, result, family=False, subject=False, level=None):
        """Falsy when the result does not match the entry; else (location, scope) for a located site match (see
        `covering`), True for any other."""
        concepts = _result_concepts_for(entry, result, self.family_of if family else None)
        if not concepts:
            return False
        if subject:
            if not _subject_hit(entry, result) and not (
                    entry["_file"] is None and entry.get("subject")
                    and subject_in(entry["subject"], _stext(result))
                    and self._outside_located(result, concepts)):
                return False
            return True
        if entry["_file"] is not None:
            return self.covering(entry, result, concepts, level)
        if entry.get("subject"):
            return False  # a repository-level entry with a subject matches only by its subject
        # repository-level: the result is outside every located entry of (one of) its concepts, and names the subject
        # of no subject entry of that concept (that entry, not the repository, is its site)
        return any(not self._on_located(result, c)
                   and not any(_subject_hit(S, result) for S in self.subjected if _applies(S, c))
                   for c in concepts)

    def _passes(self):
        """(family, subject, level) in the order matching tries them: the PASSES, each located one at every location
        level, strongest first (a subject pass does not depend on the location level)."""
        for family, subject in PASSES:
            for level in ([self.widest] if subject else self.levels):
                yield family, subject, level

    @staticmethod
    def _exact(entry, result, how):
        """A match by the result's own location on the entry's own lines (no tolerance needed), or one that is not a
        line match at all; False only for an own-location match that needed the line tolerance."""
        if not isinstance(how, tuple):
            return True
        loc, scope = how
        if scope != "site" or loc is not result or "lines" not in entry or "commit" in entry:
            return True
        lo, hi = entry["lines"]
        return result["line"] is not None and lo <= result["line"] <= hi

    def assign(self, mf, res_out):
        """Contract 1.7: [(plant position in `mf`, result index, how)] — a maximum one-to-one assignment of the free
        results to the plants. Each admissible (plant, result) pair has a TIER: the strongest pass and location level
        at which it matches, a level's own-location matches split into exact-line before within-tolerance. Among the
        assignments that find the most plants it takes the one with the most pairs of the strongest tier, then of
        the next, …; remaining ties go to key order, then result order. Solved exactly per connected component of
        the candidate pairs (Hungarian method on integer weights that encode that order)."""
        passes = list(self._passes())
        free = [i for i, o in enumerate(res_out) if o is None]
        pairs = {}
        for p, e in enumerate(mf):
            for i in free:
                r = self.results[i]
                if not (_result_concepts_for(e, r) or _result_concepts_for(e, r, self.family_of)):
                    continue
                for k, (family, subject, level) in enumerate(passes):
                    how = self.matches(e, r, family, subject, level)
                    if how:
                        pairs[(p, i)] = (2 * k + (0 if self._exact(e, r, how) else 1), how)
                        break
        if not pairs:
            return []
        tiers = 2 * len(passes)
        parent = {}

        def find(x):
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for p, i in pairs:
            parent[find(("e", p))] = find(("r", i))
        comps = {}
        for p, i in pairs:
            comps.setdefault(find(("e", p)), []).append((p, i))
        out = []
        for edges in comps.values():
            ps = sorted({p for p, _ in edges})
            rs = sorted({i for _, i in edges})
            n_e, n_r = len(ps), len(rs)
            n = min(n_e, n_r)
            base = n + 2
            c = (n_r + 1) ** n_e
            big = base ** (tiers + 1) * c
            pos_p = {p: k for k, p in enumerate(ps)}
            pos_r = {i: k for k, i in enumerate(rs)}
            weight = {}
            for p, i in edges:
                t = pairs[(p, i)][0]
                weight[(p, i)] = (big + base ** (tiers - 1 - t) * c
                                  + (n_r + 1) ** (n_e - 1 - pos_p[p]) * (n_r - pos_r[i]))
            if n_e == 1 or n_r == 1:
                best = max(edges, key=lambda pi: weight[pi])
                chosen = [best]
            else:
                chosen = _max_weight_matching(ps, rs, weight)
            out += [(p, i, pairs[(p, i)][1]) for p, i in chosen]
        return sorted(out)

    def run(self):
        """{"entries": {id: outcome}, "results": [outcome]} — see the module docstring for the outcome names."""
        res_out = [None] * len(self.results)
        for i, r in enumerate(self.results):
            if r.get("ignoreReason"):
                res_out[i] = {"outcome": "summary", "entryId": None, "concept": None}
        ent_out = {}

        def claim(i, outcome, entry, concept, how=None):
            res_out[i] = {"outcome": outcome, "entryId": entry["id"] if entry else None, "concept": concept}
            if isinstance(how, tuple):  # contract 1.5: which location of the result decided, and at what scope
                loc, scope = how
                if loc is not self.results[i]:
                    res_out[i]["site"] = {k: loc[k] for k in ("file", "line", "endLine")}
                if scope in SCOPES:
                    res_out[i]["scope"] = scope

        def concept_for(entry, r):
            if entry["label"] in FAMILY_LABELS:
                return entry["concept"]
            return _result_concepts_for(entry, r)[0]

        def first(group, r):
            """(entry, how): the first entry of `group` matching r in the strongest pass that matches any."""
            for family, subject, level in self._passes():
                for e in group:
                    how = self.matches(e, r, family, subject, level)
                    if how:
                        return e, how
            return None, None

        mf = [e for e in self.entries if e["label"] == "must-fire"]
        mf = [e for e in mf if e["_file"]] + [e for e in mf if not e["_file"]]
        for e in mf:
            ent_out[e["id"]] = {"outcome": "FN", "results": [], "redundant": [], "fileLevel": False}
        if self.optimal:  # contract 1.7: the best one-to-one assignment, not the first come
            for p, i, how in self.assign(mf, res_out):
                e = mf[p]
                claim(i, "tp", e, e["concept"], how)
                ent_out[e["id"]] = {"outcome": "TP", "results": [i], "redundant": [], "fileLevel": True}
        else:
            for family, subject, level in self._passes():
                for e in mf:
                    if ent_out[e["id"]]["outcome"] == "TP":
                        continue
                    for i, r in enumerate(self.results):
                        if res_out[i] is not None:
                            continue
                        how = self.matches(e, r, family, subject, level)
                        if how:
                            claim(i, "tp", e, e["concept"], how)
                            ent_out[e["id"]] = {"outcome": "TP", "results": [i], "redundant": [], "fileLevel": True}
                            break
        for e in mf:
            if ent_out[e["id"]]["outcome"] != "TP" and e["_file"] is not None:
                ent_out[e["id"]]["fileLevel"] = any(
                    res_out[i] is None or res_out[i]["outcome"] != "summary"
                    for i, r in enumerate(self.results)
                    if any(loc["file"] is not None and same_file(loc, e["_file"])
                           for loc in [r] + (r.get("sites") or []))
                    and (_result_concepts_for(e, r) or _result_concepts_for(e, r, self.family_of)))
        hit_mf = [e for e in mf if ent_out[e["id"]]["outcome"] == "TP"]
        for i, r in enumerate(self.results):
            if res_out[i] is None:
                e, how = first(hit_mf, r)
                if e:
                    claim(i, "redundant", e, e["concept"], how)
                    ent_out[e["id"]]["redundant"].append(i)

        for label, outcome in (("must-not-fire", "trap-fp"), ("clean", "clean-fp"), ("not-applicable", "na-fp")):
            group = [e for e in self.entries if e["label"] == label]
            group = [e for e in group if e["_file"]] + [e for e in group if not e["_file"]]
            for e in group:
                ent_out[e["id"]] = {"outcome": "TN", "results": [], "redundant": []}
            for i, r in enumerate(self.results):
                if res_out[i] is None:
                    e, how = first(group, r)
                    if e:
                        claim(i, outcome, e, concept_for(e, r), how)
                        ent_out[e["id"]]["outcome"] = "FP"
                        ent_out[e["id"]]["results"].append(i)

        located_mf = [e for e in mf if e["_file"] is not None]
        for i, r in enumerate(self.results):
            if res_out[i] is None and r["file"] is None and r.get("summaryOf"):
                # contract 1.4: a location-less row of a concept the key plants only at located sites summarises
                # that concept ("not all async methods take a token"): it tells the reader the scanner knew, but not
                # where, so it finds no plant — and it is not noise either
                plants = [e for e in located_mf if _result_concepts_for(e, r)]
                if plants:
                    claim(i, "summary-of-concept", None, plants[0]["concept"])
                    res_out[i]["plants"] = [e["id"] for e in plants]
                    for e in plants:
                        ent_out[e["id"]].setdefault("summarisedBy", []).append(i)
        for i, r in enumerate(self.results):
            if res_out[i] is None:
                cov = [c for c in _mc(r) if c in self.covered]
                if cov:
                    claim(i, "unmatched-fp", None, cov[0])
                else:
                    claim(i, "uncovered", None, r["concepts"][0] if r["concepts"] else UNMAPPED)
        return {"entries": ent_out, "results": res_out}


def _max_weight_matching(rows, cols, weight):
    """[(row, col)] of a maximum-weight matching of a bipartite graph (Hungarian method, integer weights >= 0; a pair
    absent from `weight` has none). Exact on arbitrary-precision integers."""
    transpose = len(rows) > len(cols)
    if transpose:
        rows, cols = cols, rows
        weight = {(b, a): w for (a, b), w in weight.items()}
    n, m = len(rows), len(cols)
    w = [[0] * (m + 1)] + [[0] + [weight.get((rows[a], cols[b]), 0) for b in range(m)] for a in range(n)]
    inf = (max(max(r) for r in w) + 1) * (n + 1) * 4
    u, v, p, way = [0] * (n + 1), [0] * (m + 1), [0] * (m + 1), [0] * (m + 1)
    for a in range(1, n + 1):
        p[0], j0 = a, 0
        minv, used = [inf] * (m + 1), [False] * (m + 1)
        while True:
            used[j0] = True
            a0, delta, j1 = p[j0], inf, 0
            for j in range(1, m + 1):
                if not used[j]:
                    cur = -w[a0][j] - u[a0] - v[j]
                    if cur < minv[j]:
                        minv[j], way[j] = cur, j0
                    if minv[j] < delta:
                        delta, j1 = minv[j], j
            for j in range(m + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break
    out = []
    for j in range(1, m + 1):
        if p[j] and w[p[j]][j] > 0:
            a, b = rows[p[j] - 1], cols[j - 1]
            out.append((b, a) if transpose else (a, b))
    return out


# --- metrics --------------------------------------------------------------------------------------------------------

def _ratio(n, d):
    return n / d if d else None


def empty_counts():
    return {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "trapFp": 0, "trapTn": 0,
            "results": 0, "noise": 0, "redundant": 0, "uncovered": 0, "summaryRows": 0, "summaryOfConcept": 0,
            "fileLevelTp": 0}


def finish(c):
    c["recall"] = _ratio(c["tp"], c["tp"] + c["fn"])
    c["trapResistance"] = _ratio(c["trapTn"], c["trapTn"] + c["trapFp"])
    c["noiseRate"] = _ratio(c["noise"], c["results"])
    # SECONDARY diagnostic (contract 1.3): plants with a result of the concept anywhere in their file / plants
    c["fileLevelRecall"] = _ratio(c["fileLevelTp"], c["tp"] + c["fn"])
    return c


def add_entry(c, label, outcome, file_level=False):
    if label == "must-fire":
        c["tp" if outcome == "TP" else "fn"] += 1
        c["fileLevelTp"] += 1 if file_level else 0
    else:
        c["fp" if outcome == "FP" else "tn"] += 1
        if label == "must-not-fire":
            c["trapFp" if outcome == "FP" else "trapTn"] += 1


def add_result(c, outcome):
    if outcome == "summary":
        c["summaryRows"] += 1
        return
    if outcome == "uncovered":
        c["uncovered"] += 1
        return
    if outcome == "summary-of-concept":  # contract 1.4: neither a hit nor noise, outside the result count
        c["summaryOfConcept"] += 1
        return
    c["results"] += 1
    if outcome in NOISE:
        c["noise"] += 1
    elif outcome == "redundant":
        c["redundant"] += 1


def totals(matcher, out):
    c = empty_counts()
    for e in matcher.entries:
        o = out["entries"][e["id"]]
        add_entry(c, e["label"], o["outcome"], o.get("fileLevel", False))
    for r in out["results"]:
        add_result(c, r["outcome"])
    return finish(c)


def by_concept(matcher, out):
    """Per concept. A `clean` entry listing concepts contributes one FP/TN per listed concept (FP when a result of
    that concept landed in it); a `"*"` clean entry is counted in the "*" row. Results count under the concept they
    were attributed to; uncovered ones under their own concept or (unmapped)."""
    rows = {}

    def row(k):
        return rows.setdefault(k, empty_counts())

    for e in matcher.entries:
        o = out["entries"][e["id"]]
        cs = entry_concepts(e)
        if e["label"] == "clean" and cs != STAR:
            fired = {out["results"][i]["concept"] for i in o["results"]}
            for c in cs:
                add_entry(row(c), "clean", "FP" if c in fired else "TN")
        elif cs == STAR:
            add_entry(row(STAR), "clean", o["outcome"])
        else:
            add_entry(row(e["concept"]), e["label"], o["outcome"], o.get("fileLevel", False))
    for r in out["results"]:
        if r["outcome"] != "summary":
            add_result(row(r["concept"]), r["outcome"])
    return {k: finish(v) for k, v in sorted(rows.items(), key=lambda kv: (kv[0] in (STAR, UNMAPPED), kv[0]))}


def by_dimension(entries, results, mapping, tol, file_scope=frozenset(), resource_scope=frozenset(), resources=None,
                 **scopes):
    """Per scanner dimension, matching re-run within the dimension: only its own results against the entries whose
    concept maps to it (and every `"*"` clean region), so a hit by one dimension is never credited to another."""
    dims = []
    for e in entries:
        cs = entry_concepts(e) if e["label"] != "score-band" else []
        for c in (cs if cs != STAR else []):
            for d in mapping.dimensions_of_concept(c):
                if d not in dims:
                    dims.append(d)
    results = [r for r in results if not r.get("ignoreReason")]
    for r in results:
        if r["dimension"] not in dims:
            dims.append(r["dimension"])
    rows = {}
    for d in dims:
        ents = []
        for e in entries:
            if e["label"] == "score-band":
                continue
            cs = entry_concepts(e)
            if cs == STAR or any(d in mapping.dimensions_of_concept(c) for c in cs):
                ents.append(e)
        rs = [r for r in results if r["dimension"] == d]
        m = Matcher(ents, rs, tol, mapping, file_scope, resource_scope, resources, **scopes)
        rows[d] = totals(m, m.run())
    # contract 1.4: plants and traps of a concept no dimension of the scanner maps (a must-fire there is an FN)
    ruleless = [e for e in entries if e["label"] in ("must-fire", "must-not-fire")
                and not mapping.dimensions_of_concept(e["concept"])]
    if ruleless:
        m = Matcher(ruleless, [], tol, mapping)
        rows[NO_RULE] = totals(m, m.run())
    return {k: rows[k] for k in sorted(rows, key=lambda k: (k in (UNMAPPED, NO_RULE), k == NO_RULE, _natural(k)))}


def _natural(s):
    import re
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def score_bands(entries, scores, mapping):
    """Each score-band entry: the score found for its concept (else for the dimensions whose score measures the concept:
    the mapping's `scoreDimensions`, defaulting to `dimensions`) and in/out."""
    out = []
    for e in entries:
        if e["label"] != "score-band":
            continue
        lo, hi = e["band"]
        found = []
        if e["concept"] in scores:
            found.append((e["concept"], scores[e["concept"]]))
        else:
            found += [(d, scores[d]) for d in mapping.score_dimensions_of_concept(e["concept"]) if d in scores]
        if not found:
            outcome = "unscored"
        else:
            outcome = "in" if all(isinstance(s, (int, float)) and lo <= s <= hi for _, s in found) else "out"
        out.append({"id": e["id"], "concept": e["concept"], "band": [lo, hi],
                    "scores": [{"source": k, "score": s} for k, s in found], "outcome": outcome})
    return out


# --- the whole run --------------------------------------------------------------------------------------------------

CONTRACTS = ("1.4", "1.5", "1.6", "1.7")


def score(key, results, mapping, scores=None, contract=None, taxonomy=None, source=None):
    """Score `results` (from sarif.read_results) against `key` under `mapping`. Returns the full report dict.

    `contract` (default: the current one) "1.4" scores without the 1.5 location-equivalence rules, so a measurement
    frozen under 1.4 re-scores exactly; "1.5" without the 1.6 resource scope; "1.6" without the 1.7 rules (optimal
    assignment, `subjectFromMessage`, element and group scope). `taxonomy` (a parsed taxonomy.json)
    overrides the harness's own for the file- and resource-scope concepts. `source` (contract 1.6; a callable
    repository-relative path -> text or None, see resources.dir_source / git_source) reads the unit's files for
    resource boundaries; without it every resource-scope entry keeps the line rule (`resource-unavailable`)."""
    contract = contract or CONTRACT_VERSION
    if contract not in CONTRACTS:
        raise ValueError(f"score: contract {contract!r} is not one of {CONTRACTS}")
    equivalence = contract != "1.4"
    file_scope = file_scope_concepts(taxonomy) if equivalence else frozenset()
    resource_rule = contract not in ("1.4", "1.5")
    resource_scope = resource_scope_concepts(taxonomy) if resource_rule else frozenset()
    rules_1_7 = contract not in ("1.4", "1.5", "1.6")
    scopes = {"element_scope": element_scope_concepts(taxonomy) if rules_1_7 else frozenset(),
              "group_scope": group_scope_concepts(taxonomy) if rules_1_7 else frozenset(),
              "optimal": rules_1_7}
    resources = ResourceIndex(source)
    tol = line_tolerance(key)
    entries = key["entries"]
    repo_name = (key.get("repo") or "").rsplit("/", 1)[-1] or None
    for r in results:
        r["ignoreReason"] = mapping.ignored(r["ruleId"], r.get("message"))
        r["summaryOf"] = None if r["ignoreReason"] else mapping.summary_of(r["ruleId"], r.get("message"))
        r["concepts"] = [] if r["ignoreReason"] else mapping.concepts_of(r["ruleId"], r.get("message"),
                                                                         r.get("properties"))
        mc = list(r["concepts"])
        for c in r["concepts"]:
            mc += [a for a in mapping.ancestors(c) if a not in mc]
        r["matchConcepts"] = mc
        r["dimension"] = mapping.dimension_of(r["ruleId"], r["concepts"])
        r["locationSource"] = "sarif" if r["file"] is not None else "none"
        if r["file"] is None and not r["ignoreReason"]:
            loc = mapping.location_in_message(r["ruleId"], r.get("message"))
            if loc is not None:
                r["file"], r["line"], r["locationSource"] = norm(loc[0]), loc[1], "message"
                r["pathExact"] = False  # a site named in prose (often a basename): the suffix rule
        elif r["file"] is not None and not r.get("pathExact"):
            f, exact = repo_relative(r["file"], (), repo_name)  # contract 1.4: under the checkout directory
            if exact:
                r["file"], r["pathExact"] = f, True
        r["pathMatch"] = None if r["file"] is None else ("exact" if r.get("pathExact") else "suffix")
        r.pop("subjectText", None)
        if rules_1_7 and not r["ignoreReason"]:  # contract 1.7: the part of the message that states the subject
            st = mapping.subject_text(r["ruleId"], r.get("message"))
            if st is not None:
                r["subjectText"] = st
        r.pop("sites", None)
        if equivalence and not r["ignoreReason"] and r["concepts"]:
            sites = []  # contract 1.5: further sites named in the message, matched like message locations (suffix)
            for f, line, end in mapping.sites_in_message(r["ruleId"], r.get("message"), r["concepts"]):
                f = norm(f)
                if f is None or (r["file"] is not None and line == r["line"] and path_match(f, r["file"])
                                 and end is None):
                    continue  # the result's own location, restated (kept when the message adds its span)
                sites.append({"file": f, "line": line, "endLine": end, "pathExact": False,
                              "commitSha": r.get("commitSha")})
            if sites:
                r["sites"] = sites
    m = Matcher(entries, results, tol, mapping, file_scope, resource_scope, resources, **scopes)
    out = m.run()
    for r, o in zip(results, out["results"]):
        r.pop("site", None), r.pop("matchScope", None)
        if o.get("site"):
            r["locationSource"], r["site"] = "sitesFromMessage", o["site"]
        if o.get("scope"):
            r["matchScope"] = o["scope"]

    entry_rows = []
    for e in m.entries:
        o = out["entries"][e["id"]]
        row = {"id": e["id"], "label": e["label"], "outcome": o["outcome"]}
        if e["label"] == "must-fire":
            row["fileLevel"] = o["fileLevel"]
        cs = entry_concepts(e)
        row["concept" if e["label"] != "clean" else "concepts"] = e["concept"] if e["label"] != "clean" else cs
        for k in ("file", "lines", "commit", "subject"):
            if k in e:
                row[k] = e[k]
        row["results"] = [_brief(results[i]) for i in o["results"]]
        row["redundant"] = [_brief(results[i]) for i in o["redundant"]]
        if o.get("summarisedBy"):
            row["summarisedBy"] = list(o["summarisedBy"])
        st = m.resource_status(e)
        if st is None and rules_1_7:
            st = m.scope_status(e, ELEMENT)
        if st is not None:  # contract 1.6 / 1.7: how the resource (else the element) scope applied to this entry
            row["matchScope"] = st[0]
            if st[1] is not None:
                row["resourceKind"] = st[1].kind
        entry_rows.append(row)

    result_rows = []
    for r, o in zip(results, out["results"]):
        row = {**_brief(r), "message": r["message"], "concepts": r["concepts"],
               "dimension": r["dimension"], "outcome": o["outcome"], "entryId": o["entryId"],
               "attributedConcept": o["concept"], "ignoreReason": r.get("ignoreReason")}
        if r.get("sites"):
            row["sites"] = [{k: x[k] for k in ("file", "line", "endLine")} for x in r["sites"]]
        if r.get("subjectText") is not None:
            row["subjectText"] = r["subjectText"]
        result_rows.append(row)

    soc = [{"index": r["index"], "ruleId": r["ruleId"], "concept": o["concept"], "message": r["message"],
            "plants": o["plants"], "reason": r["summaryOf"]} for r, o in zip(results, out["results"]) if o["outcome"] == "summary-of-concept"]
    bands = score_bands(entries, scores or {}, mapping)
    summary = totals(m, out)
    summary["locationSources"] = {k: sum(r["locationSource"] == k for r in results)
                                  for k in ("sarif", "message") + (("sitesFromMessage",) if equivalence else ()) + ("none",)}
    if equivalence:
        summary["fileScopeMatches"] = sum(r.get("matchScope") == "file" for r in results)
        summary["resultsWithMessageSites"] = sum(bool(r.get("sites")) for r in results)
    if resource_rule:
        statuses = [st[0] if st else None for st in (m.resource_status(e) for e in m.entries)]
        summary["resourceScopeMatches"] = sum(r.get("matchScope") == "resource" for r in results)
        summary["resourceScope"] = {
            "source": getattr(source, "description", None) if source is not None else None,
            "entries": sum(x is not None for x in statuses), "applied": statuses.count("resource"),
            "unavailable": statuses.count("resource-unavailable"), "unsupported": statuses.count("resource-unsupported")}
    if rules_1_7:
        estat = [x[0] if x else None for x in (m.scope_status(e, ELEMENT) for e in m.entries)]
        summary["assignment"] = "optimal"
        summary["groupScopeMatches"] = sum(r.get("matchScope") == "group" for r in results)
        summary["elementScopeMatches"] = sum(r.get("matchScope") == "element" for r in results)
        summary["elementScope"] = {
            "source": getattr(source, "description", None) if source is not None else None,
            "entries": sum(x is not None for x in estat), "applied": estat.count("element"),
            "unavailable": estat.count("element-unavailable"), "unsupported": estat.count("element-unsupported")}
    summary["pathMatches"] = {k: sum(r.get("pathMatch") == k for r in results) for k in ("exact", "suffix")}
    return {
        "lineTolerance": tol,
        "summary": summary,
        "concepts": by_concept(m, out),
        "dimensions": by_dimension(entries, results, mapping, tol, file_scope, resource_scope, resources, **scopes),
        "contract": contract,
        "scoreBands": bands,
        "unmappedConcepts": unmapped_concepts(entries, mapping),
        "summaryOfConcept": soc,
        "entries": entry_rows,
        "results": result_rows,
    }


def unmapped_concepts(entries, mapping):
    """The concepts of the key's plants and traps that no rule of the scanner maps (contract 1.4: a concept beyond
    the scanner — absent from its mapping, listed as `unmapped`, or mapped with no rule): its plants are FNs."""
    out = set()
    for e in entries:
        if e["label"] in ("must-fire", "must-not-fire") and not mapping.concepts.get(e["concept"]):
            out.add(e["concept"])
    return sorted(out)


def _brief(r):
    b = {"index": r["index"], "run": r["run"], "resultIndex": r["resultIndex"], "ruleId": r["ruleId"],
         "file": r["file"], "line": r["line"], "locationSource": r.get("locationSource"),
         "pathMatch": r.get("pathMatch"),
         "commitSha": r.get("commitSha")}
    if r.get("site"):  # contract 1.5: the message site that decided the outcome
        b["site"] = r["site"]
    if r.get("matchScope"):
        b["matchScope"] = r["matchScope"]
    return b


# --- text rendering -------------------------------------------------------------------------------------------------

def _pct(v):
    return "   n/a" if v is None else f"{100 * v:5.1f}%"


def render_table(title, rows):
    head = (f"{title:<28} {'recall':>7} {'trapRes':>7} {'noise':>7}  {'TP':>3} {'FN':>3} {'FP':>3} {'TN':>3}"
            f"  {'res':>4} {'redund':>6} {'uncov':>5}  {'fileRec*':>8}")
    lines = [head, "-" * len(head)]
    for k, c in rows.items():
        lines.append(f"{k[:28]:<28} {_pct(c['recall']):>7} {_pct(c['trapResistance']):>7} {_pct(c['noiseRate']):>7}"
                     f"  {c['tp']:>3} {c['fn']:>3} {c['fp']:>3} {c['tn']:>3}"
                     f"  {c['results']:>4} {c['redundant']:>6} {c['uncovered']:>5}  {_pct(c['fileLevelRecall']):>8}")
    return "\n".join(lines)


FILE_LEVEL_NOTE = ("* fileRec = file-level recall, a SECONDARY diagnostic: must-fire entries with a result of the concept "
                   "anywhere in the same file / must-fire. It changes no TP or FN — a result on the wrong line stays "
                   "an FN; the gap to recall is the scanner's location imprecision.")


def render(report):
    parts = [render_table("concept", report["concepts"]), "",
             render_table("scanner dimension", report["dimensions"]), "",
             render_table("TOTAL", {"all": report["summary"]}), FILE_LEVEL_NOTE]
    ls = report["summary"].get("locationSources") or {}
    if ls.get("message"):
        parts += [f"{ls['message']} result(s) located from the message (mapping `locationFromMessage`): the scanner "
                  f"named the site only in prose and is given the benefit of that location."]
    if ls.get("sitesFromMessage"):
        parts += [f"{ls['sitesFromMessage']} result(s) matched at a further site their message names (mapping "
                  f"`sitesFromMessage`, contract 1.5): a clone group reported at one member, found at another."]
    if report["summary"].get("fileScopeMatches"):
        parts += [f"{report['summary']['fileScopeMatches']} result(s) matched by file-scope (contract 1.5): a "
                  f"class-, file- or module-level concept reported elsewhere in the entry's file."]
    if report["summary"].get("resourceScopeMatches"):
        parts += [f"{report['summary']['resourceScopeMatches']} result(s) matched by resource-scope (contract 1.6): an "
                  f"IaC concept whose defect is a property of a whole resource, reported elsewhere in the entry's "
                  f"resource (YAML document, Dockerfile stage, HCL block)."]
    if report["summary"].get("groupScopeMatches"):
        parts += [f"{report['summary']['groupScopeMatches']} result(s) matched by group-scope (contract 1.7): a "
                  f"relation among several files (a dependency cycle) reported at, or listing, another member."]
    if report["summary"].get("elementScopeMatches"):
        parts += [f"{report['summary']['elementScopeMatches']} result(s) matched by element-scope (contract 1.7): a "
                  f"markup element's property reported elsewhere in the element's start tag."]
    es = report["summary"].get("elementScope") or {}
    if es.get("unavailable") or es.get("unsupported"):
        lost = [e["id"] for e in report["entries"] if e.get("matchScope") in ("element-unavailable",
                                                                           "element-unsupported")]
        parts += [f"{len(lost)} element-scope entr(y/ies) kept the line rule — element-unavailable (the unit's files "
                  f"were not readable: pass --repo-dir) or element-unsupported (not a markup file): "
                  f"{', '.join(lost)}"]
    rs = report["summary"].get("resourceScope") or {}
    if rs.get("unavailable") or rs.get("unsupported"):
        lost = [e["id"] for e in report["entries"] if e.get("matchScope") in ("resource-unavailable",
                                                                           "resource-unsupported")]
        parts += [f"{len(lost)} resource-scope entr(y/ies) kept the line rule — resource-unavailable (the unit's files "
                  f"were not readable: pass --repo-dir) or resource-unsupported (no resource boundaries for the file "
                  f"type): {', '.join(lost)}"]
    if report["scoreBands"]:
        parts += ["", "score bands:"]
        for b in report["scoreBands"]:
            got = ", ".join(f"{s['source']}={s['score']}" for s in b["scores"]) or "-"
            parts.append(f"  {b['id']:<12} {b['concept']:<32} band {b['band'][0]}-{b['band'][1]}  "
                         f"score {got}  -> {b['outcome']}")
    if report.get("unmappedConcepts"):
        parts += ["", "concepts no rule of this scanner maps (each plant of them is an FN: a real defect the scanner "
                      "cannot see): " + ", ".join(report["unmappedConcepts"])]
    misses = [e for e in report["entries"] if e["outcome"] in ("FN", "FP")]
    if misses:
        parts += ["", "entries that went wrong (FN = planted defect missed, FP = fired on a trap/clean/n-a):"]
        for e in misses:
            where = e.get("file", "(repository)") + (f":{e['lines'][0]}-{e['lines'][1]}" if "lines" in e else "")
            on = "; ".join(f"#{r['index']} {r['ruleId']} {r['file']}:{r['line']}" for r in e["results"])
            parts.append(f"  {e['outcome']} {e['id']:<12} {e['label']:<15} {where}" + (f"  <- {on}" if on else ""))
    summ = [r for r in report["results"] if r["outcome"] == "summary"]
    if summ:
        parts += ["", "summary rows (mapping `ignore`; in no metric):"]
        parts += [f"  #{r['index']} {r['ruleId']} {r['file'] or '(repository)'}  — {r['ignoreReason']}" for r in summ]
    if report.get("summaryOfConcept"):
        parts += ["", "summaryOfConcept (location-less rows summarising a concept planted at located sites; the "
                      "scanner knew, but said not where — no hit, no noise):"]
        parts += [f"  #{x['index']} {x['ruleId']} [{x['concept']}] plants {', '.join(x['plants'])}: "
                  f"{(x['message'] or '')[:100]}" for x in report["summaryOfConcept"]]
    stray = [r for r in report["results"] if r["outcome"] == "unmatched-fp"]
    if stray:
        parts += ["", "results on covered concepts that match no entry (noise):"]
        parts += [f"  #{r['index']} {r['ruleId']} {r['file']}:{r['line']} [{r['attributedConcept']}]" for r in stray]
    return "\n".join(parts)
