"""Contract 1.7: optimal one-to-one assignment, the subject a result states, group scope and element scope.

- Assignment. Which plant a result is consumed by no longer depends on key order: among all one-to-one assignments of
  results to plants the scorer takes one with the MOST plants found, then the most found by the strongest match
  (exact concept before subject before family; the result's own location on the entry's lines before one within the
  line tolerance, before the file/resource/element scope, before a listed site), then — only to make it
  deterministic — key order and result order.
- Subjects. A mapping may declare where a result's message STATES its subject (`subjectFromMessage`): subjects are
  then searched there only, so an advisory about one package that names its parent as the path it arrived by is
  about the package, not the parent.
- Group scope (taxonomy `matchScope: "group"`): a defect that is a relation among several files with no member more
  its site than another (a dependency cycle); a result of the concept located in, or listing, the entry's file is on
  the entry's site.
- Element scope (taxonomy `matchScope: "element"`): a markup element's property that can be an ABSENCE (no accessible
  name, no label, missing required ARIA state, …); a result anywhere in the element's start tag is on the site of an
  entry whose lines lie in that start tag."""
import copy
import json
import os
import unittest

from cai_bench import CONTRACT_VERSION
from cai_bench.keyfile import load_json
from cai_bench.mapping import Mapping, MappingError
from cai_bench.resources import ResourceIndex, markup_start_tags
from cai_bench.sarif import read_results
from cai_bench.scoring import render, score as score_report
from cai_bench.taxonomy import (element_scope_concepts, file_scope_concepts, group_scope_concepts,
                                resource_scope_concepts)
from tests.helpers import MAPPING_DOC, clean, entry, key, mf, mnf, outcomes, res, sarif

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def score(k, *results, mapping=MAPPING_DOC, contract=None, src=None):
    return score_report(json.loads(json.dumps(k)), read_results(sarif(*results)), Mapping(mapping), None,
                        contract=contract, source=src)


class Version(unittest.TestCase):
    def test_contract_is_1_7(self):
        self.assertEqual(CONTRACT_VERSION, "1.7")

    def test_the_report_names_its_contract(self):
        self.assertEqual(score(key(mf("A", "sql-injection", "a.cs", [5, 5])))["contract"], "1.7")


# --- optimal one-to-one assignment ------------------------------------------------------------------------------------

class Assignment(unittest.TestCase):
    def test_a_tolerance_match_no_longer_steals_a_plant_another_plant_needs(self):
        # A (line 5) comes first in the key; the line-2 row is within tolerance of both A and B, the line-5 row of A only.
        # Greedy: A takes the line-2 row, the exact line-5 row is redundant on A, B is an FN.
        k = key(mf("A", "sql-injection", "a.cs", [5, 5]), mf("B", "sql-injection", "a.cs", [1, 1]))
        rs = (res("D14", "a.cs", 2), res("D14", "a.cs", 5))
        r = score(k, *rs)
        self.assertEqual(outcomes(r), [(0, "tp", "B"), (1, "tp", "A")])
        self.assertEqual((r["summary"]["tp"], r["summary"]["fn"]), (2, 0))
        self.assertEqual(r["summary"]["assignment"], "optimal")
        g = score(k, *rs, contract="1.6")  # a frozen 1.6 measurement re-scores exactly
        self.assertEqual(outcomes(g), [(0, "tp", "A"), (1, "redundant", "A")])
        self.assertNotIn("assignment", g["summary"])

    def test_the_exact_line_row_is_the_tp_and_the_tolerance_row_redundant(self):
        k = key(mf("A", "sql-injection", "a.cs", [5, 5]))
        r = score(k, res("D14", "a.cs", 7), res("D14", "a.cs", 5))
        self.assertEqual(outcomes(r), [(0, "redundant", "A"), (1, "tp", "A")])
        self.assertEqual(outcomes(score(k, res("D14", "a.cs", 7), res("D14", "a.cs", 5), contract="1.6")),
                         [(0, "tp", "A"), (1, "redundant", "A")])

    def test_more_plants_found_beats_an_exact_line(self):
        # The line-5 row is exact on A and within tolerance of B; the line-2 row reaches A only. Two TPs, not one.
        k = key(mf("A", "sql-injection", "a.cs", [5, 5]), mf("B", "sql-injection", "a.cs", [8, 8]))
        r = score(k, res("D14", "a.cs", 5), res("D14", "a.cs", 2))
        self.assertEqual(outcomes(r), [(0, "tp", "B"), (1, "tp", "A")])

    def test_independent_of_key_and_result_order(self):
        a, b = mf("A", "sql-injection", "a.cs", [5, 5]), mf("B", "sql-injection", "a.cs", [1, 1])
        x, y = res("D14", "a.cs", 2), res("D14", "a.cs", 5)
        for k in (key(a, b), key(b, a)):
            for rs in ((x, y), (y, x)):
                s = score(k, *rs)["summary"]
                self.assertEqual((s["tp"], s["fn"], s["redundant"]), (2, 0, 0))

    def test_a_clone_row_listing_a_second_plant_frees_the_nearby_row(self):
        # The clone row sits on A's lines and lists B; the second row sits within tolerance of A only. Both are found.
        m = copy.deepcopy(MAPPING_DOC)
        m["sitesFromMessage"] = [{"rule": "^D14$", "patterns": [r"also (?P<file>\S+):(?P<line>\d+)"]}]
        k = key(mf("A", "sql-injection", "a.cs", [10, 10]), mf("B", "sql-injection", "b.cs", [40, 40]))
        r = score(k, res("D14", "a.cs", 10, "clone; also b.cs:40"), res("D14", "a.cs", 12, "clone"), mapping=m)
        self.assertEqual(outcomes(r), [(0, "tp", "B"), (1, "tp", "A")])
        self.assertEqual(outcomes(score(k, res("D14", "a.cs", 10, "clone; also b.cs:40"), res("D14", "a.cs", 12, "clone"),
                                        mapping=m, contract="1.6")),
                         [(0, "tp", "A"), (1, "redundant", "A")])

    def test_a_trap_is_still_caught_by_every_result_on_it(self):
        k = key(mf("A", "sql-injection", "a.cs", [5, 5]), mnf("T", "sql-injection", "a.cs", [20, 20]))
        r = score(k, res("D14", "a.cs", 5), res("D14", "a.cs", 20), res("D14", "a.cs", 21))
        self.assertEqual(outcomes(r), [(0, "tp", "A"), (1, "trap-fp", "T"), (2, "trap-fp", "T")])

    def test_dimension_rows_use_the_same_assignment(self):
        k = key(mf("A", "sql-injection", "a.cs", [5, 5]), mf("B", "sql-injection", "a.cs", [1, 1]))
        r = score(k, res("D14", "a.cs", 2), res("D14", "a.cs", 5))
        self.assertEqual((r["dimensions"]["D14"]["tp"], r["dimensions"]["D14"]["fn"]), (2, 0))

    def test_a_large_component_stays_one_to_one(self):
        # 30 plants a line apart, 30 rows each within tolerance of up to seven plants: all 30 found, no row twice.
        k = key(*[mf(f"P{i:02}", "sql-injection", "a.cs", [10 + i, 10 + i]) for i in range(30)])
        rs = [res("D14", "a.cs", 10 + (i * 7) % 30) for i in range(30)]
        r = score(k, *rs)
        self.assertEqual(r["summary"]["tp"], 30)
        self.assertEqual(sorted(o[2] for o in outcomes(r)), sorted(f"P{i:02}" for i in range(30)))


# --- the subject a result states ----------------------------------------------------------------------------------------

DEP = copy.deepcopy(MAPPING_DOC)
DEP["concepts"]["vulnerable-dependency"] = {"rules": ["^D30$"], "dimensions": ["D30"]}
DEP["concepts"]["flaky-test"] = {"rules": ["^D11$"], "dimensions": ["D11"]}
DEP["subjectFromMessage"] = [
    {"rule": "^D30$", "within": r"^\w+ CVE: (?:GHSA-[\w-]+: )?(?P<subject>\S+) ", "source": "test"},
    {"rule": "^D11$", "message": r"^Flaky test: [\w.-]+::",
     "within": r"^Flaky test: [\w.-]+::(?:(?P<c>[\w.]+)\.(?=(?P=c)\.))?(?P<subject>.+?): Passed \d+×", "source": "test"},
]
CVE = ("Critical CVE: GHSA-fjxv-7rqg-78g4: form-data 2.3.3: GHSA-fjxv-7rqg-78g4 — form-data is not declared in this "
       "repo's manifests: it is pulled in transitively by request 2.88.2, so upgrade the dependency that requires it")


class Subjects(unittest.TestCase):
    def test_an_advisory_is_about_the_package_it_states_not_the_parent_it_names(self):
        k = key(mf("REQ", "vulnerable-dependency", subject="request"),
                mf("FD", "vulnerable-dependency", subject="form-data"))
        r = score(k, res("D30", message=CVE), mapping=DEP)
        self.assertEqual(outcomes(r), [(0, "tp", "FD")])
        self.assertEqual(r["results"][0]["subjectText"], "form-data")
        # 1.6: the whole message, key order: the parent took it
        self.assertEqual(outcomes(score(k, res("D30", message=CVE), mapping=DEP, contract="1.6")), [(0, "tp", "REQ")])

    def test_symmetric_a_trap_named_only_as_the_parent_does_not_catch(self):
        k = key(mnf("T", "vulnerable-dependency", subject="request"))
        r = score(k, res("D30", message=CVE), mapping=DEP)
        self.assertEqual(entry(r, "T")["outcome"], "TN")
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])
        self.assertEqual(entry(score(k, res("D30", message=CVE), mapping=DEP, contract="1.6"), "T")["outcome"], "FP")

    def test_a_located_manifest_row_states_its_subject_too(self):
        k = key(mf("REQ", "vulnerable-dependency", subject="request"),
                mf("FD", "vulnerable-dependency", subject="form-data"))
        r = score(k, res("D30", "package-lock.json", 1, CVE), mapping=DEP)
        self.assertEqual(outcomes(r), [(0, "tp", "FD")])

    def test_an_undeclared_format_keeps_the_whole_message(self):
        k = key(mf("REQ", "vulnerable-dependency", subject="request"))
        r = score(k, res("D30", message="request 2.88.2 is vulnerable via form-data"), mapping=DEP)
        self.assertEqual(outcomes(r), [(0, "tp", "REQ")])
        self.assertNotIn("subjectText", r["results"][0])

    def test_a_test_identity_printed_with_its_class_twice_is_the_test(self):
        msg = ("Flaky test: Lantern.Tests::Lantern.Tests.RolloverTests.Lantern.Tests.RolloverTests.Closes_the_season: "
               "Passed 2×, failed 1× across repeated runs.")
        k = key(mf("F", "flaky-test", "tests/RolloverTests.cs", [10, 20],
                   subject="Lantern.Tests.RolloverTests.Closes_the_season"))
        r = score(k, res("D11", message=msg), mapping=DEP)
        self.assertEqual(outcomes(r), [(0, "tp", "F")])
        self.assertEqual(r["results"][0]["subjectText"], "Lantern.Tests.RolloverTests.Closes_the_season")
        self.assertEqual(entry(score(k, res("D11", message=msg), mapping=DEP, contract="1.6"), "F")["outcome"], "FN")

    def test_the_declaration_needs_a_subject_group(self):
        m = copy.deepcopy(DEP)
        m["subjectFromMessage"] = [{"rule": "^D30$", "within": r"CVE: (\S+)"}]
        with self.assertRaises(MappingError):
            Mapping(m)
        m["subjectFromMessage"] = [{"within": r"CVE: (?P<subject>\S+)"}]
        with self.assertRaises(MappingError):
            Mapping(m)


# --- group scope -------------------------------------------------------------------------------------------------------

CYC = copy.deepcopy(MAPPING_DOC)
CYC["concepts"]["module-dependency-cycle"] = {"rules": ["^R9$"], "dimensions": ["R9"]}
CYC["sitesFromMessage"] = [{"rule": "^R9$", "concepts": ["module-dependency-cycle"],
                            "within": r"^Import cycle \(\d+ files\): (?P<sites>.*?)(?: \(|$)",
                            "patterns": [r"(?:^|\s→\s)(?P<file>[^\s→]+)"]}]
CYCLE = "Import cycle (3 files): src/a.ts → src/b.ts → src/c.ts → src/a.ts"


class GroupScope(unittest.TestCase):
    def test_the_group_scope_concepts(self):
        self.assertEqual(group_scope_concepts(), frozenset({"module-dependency-cycle"}))
        self.assertFalse(group_scope_concepts() & (file_scope_concepts() | resource_scope_concepts()
                                                  | element_scope_concepts()))

    def test_a_cycle_reported_at_one_member_finds_the_plant_at_another(self):
        k = key(mf("C", "module-dependency-cycle", "src/b.ts", [7, 7]))
        r = score(k, res("R9", "src/a.ts", 1, CYCLE), mapping=CYC)
        self.assertEqual(outcomes(r), [(0, "tp", "C")])
        self.assertEqual(r["results"][0]["matchScope"], "group")
        self.assertEqual(r["summary"]["groupScopeMatches"], 1)
        self.assertEqual(entry(score(k, res("R9", "src/a.ts", 1, CYCLE), mapping=CYC, contract="1.6"), "C")["outcome"],
                         "FN")

    def test_the_member_it_is_located_at_too(self):
        k = key(mf("C", "module-dependency-cycle", "src/a.ts", [9, 9]))
        r = score(k, res("R9", "src/a.ts", 1, CYCLE), mapping=CYC)
        self.assertEqual(outcomes(r), [(0, "tp", "C")])

    def test_a_file_outside_the_cycle_is_not_its_site(self):
        k = key(mf("C", "module-dependency-cycle", "src/d.ts", [1, 1]))
        self.assertEqual(entry(score(k, res("R9", "src/a.ts", 1, CYCLE), mapping=CYC), "C")["outcome"], "FN")

    def test_symmetric_a_trap_in_a_member_file_is_caught(self):
        k = key(mnf("T", "module-dependency-cycle", "src/c.ts", [3, 3]))
        r = score(k, res("R9", "src/a.ts", 1, CYCLE), mapping=CYC)
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])

    def test_one_row_finds_one_plant(self):
        k = key(mf("C1", "module-dependency-cycle", "src/b.ts", [7, 7]),
                mf("C2", "module-dependency-cycle", "src/c.ts", [2, 2]))
        s = score(k, res("R9", "src/a.ts", 1, CYCLE), mapping=CYC)["summary"]
        self.assertEqual((s["tp"], s["fn"]), (1, 1))


# --- element scope -----------------------------------------------------------------------------------------------------

QUICK = "\n".join([
    '<form class="quick-search" method="get" action="/Search" role="search">',   # 1
    '  <input type="search"',                                                  # 2  start tag 2-11
    '         name="Surname"',                                                 # 3
    '         aria-label="Search by surname"',                                 # 4
    '         title="a > b is not the end"',                                   # 5  quoted '>'
    '         role="combobox"',                                                # 6
    '         aria-autocomplete="list"',                                       # 7
    '         autocomplete="off"',                                             # 8
    '         minlength="2"',                                                  # 9
    '         maxlength="60"',                                                 # 10
    '         style="outline: none" />',                                       # 11
    '  <ul id="s" role="listbox" hidden></ul>',                                # 12
    '  <button type="submit">Search</button>',                                 # 13
    '</form>',                                                                 # 14
    ""])

CARD = "\n".join([
    "export function Card({ items }: Props) {",       # 1
    "  const ok = items.length < limit && x > 0;",    # 2  comparisons: no tag
    "  const m = await fetchJson<Payload>(url);",    # 3  a generic call: no tag
    "  return (",                                     # 4
    "    <div",                                       # 5  start tag 5-9
    "      className=\"card\"",                       # 6
    "      onClick={() => { if (a > b) go(); }}",     # 7  a '>' inside a JSX expression
    "      role=\"button\"",                          # 8
    "    >",                                          # 9
    "      <img",                                     # 10 start tag 10-12
    "        src={url}",                              # 11
    "      />",                                       # 12
    "    </div>",                                     # 13
    "  );",                                           # 14
    "}",                                              # 15
    ""])

PAGE = "\n".join([
    "<!-- a <comment\n spanning > lines -->",          # 1-2
    "<script>",                                        # 3
    "  if (a <b) { x = \"<p class='x'>\" + y; }",       # 4  script content: no tag
    "</script>",                                       # 5
    "<svg role=\"img\"",                               # 6  start tag 6-7
    "     viewBox=\"0 0 4 3\">",                       # 7
    "</svg>",                                          # 8
    ""])

FILES = {"Pages/Shared/_QuickSearch.cshtml": QUICK, "web/src/Card.tsx": CARD, "site/index.html": PAGE,
         "src/Api/Handler.cs": "class Handler\n{\n  void Run() { }\n}\n"}


def source(path):
    return FILES.get(path)


A11Y = copy.deepcopy(MAPPING_DOC)
A11Y["concepts"].update({
    "invalid-aria-usage": {"rules": ["^AC5$"], "dimensions": ["AC5"]},
    "missing-text-alternative": {"rules": ["^AC1$"], "dimensions": ["AC1"]},
    "non-keyboard-accessible-interaction": {"rules": ["^AC4$"], "dimensions": ["AC4"]},
    "focus-outline-removed": {"rules": ["^AC6$"], "dimensions": ["AC6"]},
})
Q = "Pages/Shared/_QuickSearch.cshtml"

ELEMENT_SCOPE = {"missing-text-alternative", "form-control-without-label", "non-keyboard-accessible-interaction",
                 "invalid-aria-usage", "page-structure-violation", "form-error-not-associated",
                 "autoplay-media-without-control"}


class MarkupStartTags(unittest.TestCase):
    def test_html_and_razor(self):
        self.assertIn((2, 11), markup_start_tags(QUICK, "x.cshtml"))
        self.assertIn((1, 1), markup_start_tags(QUICK, "x.cshtml"))

    def test_jsx_expressions_comparisons_and_generics(self):
        tags = markup_start_tags(CARD, "Card.tsx")
        self.assertIn((5, 9), tags)
        self.assertIn((10, 12), tags)
        self.assertFalse([t for t in tags if t[0] <= 3], tags)

    def test_comments_and_script_content_are_skipped(self):
        tags = markup_start_tags(PAGE, "index.html")
        self.assertIn((6, 7), tags)
        self.assertFalse([t for t in tags if t[0] in (1, 2, 4)], tags)

    def test_which_files_have_elements(self):
        idx = ResourceIndex(source)
        self.assertEqual(idx.get(Q, "element").kind, "markup-start-tag")
        self.assertEqual(idx.get("src/Api/Handler.cs", "element"), "unsupported")
        self.assertEqual(idx.get("deploy/x.yaml", "element"), "unsupported")
        self.assertEqual(ResourceIndex(None).get(Q, "element"), "unavailable")


class ElementScope(unittest.TestCase):
    def test_the_element_scope_concepts(self):
        self.assertEqual(element_scope_concepts(), frozenset(ELEMENT_SCOPE))
        self.assertFalse(element_scope_concepts() & (file_scope_concepts() | resource_scope_concepts()))
        # a removed outline is a PRESENT value with a line of its own; the umbrella keeps the line rule
        for c in ("focus-outline-removed", "visual-and-motion-safety", "motion-without-reduced-motion",
                  "modal-focus-not-managed"):
            self.assertNotIn(c, element_scope_concepts(), c)

    def test_a_row_at_the_start_tag_finds_an_absence_keyed_on_an_attribute_line(self):
        k = key(mf("ARIA", "invalid-aria-usage", Q, [6, 6]))
        r = score(k, res("AC5", Q, 2, "role=combobox missing aria-expanded"), mapping=A11Y, src=source)
        self.assertEqual(outcomes(r), [(0, "tp", "ARIA")])
        self.assertEqual(r["results"][0]["matchScope"], "element")
        self.assertEqual((entry(r, "ARIA")["matchScope"], entry(r, "ARIA")["resourceKind"]),
                         ("element", "markup-start-tag"))
        self.assertEqual(r["summary"]["elementScopeMatches"], 1)
        self.assertEqual(r["summary"]["elementScope"]["applied"], 1)
        self.assertIn("element-scope", render(r))
        self.assertEqual(entry(score(k, res("AC5", Q, 2), mapping=A11Y, src=source, contract="1.6"), "ARIA")["outcome"],
                         "FN")

    def test_a_present_value_keeps_the_line_rule(self):
        k = key(mf("FOC", "focus-outline-removed", Q, [11, 11]))
        r = score(k, res("AC6", Q, 2, "outline removed inline"), mapping=A11Y, src=source)
        self.assertEqual(entry(r, "FOC")["outcome"], "FN")
        self.assertNotIn("matchScope", entry(r, "FOC"))

    def test_the_next_element_is_not_the_site(self):
        k = key(mf("ARIA", "invalid-aria-usage", Q, [12, 12]))
        self.assertEqual(entry(score(k, res("AC5", Q, 2), mapping=A11Y, src=source), "ARIA")["outcome"], "FN")

    def test_the_parent_element_is_not_the_site(self):
        k = key(mf("ALT", "missing-text-alternative", "web/src/Card.tsx", [11, 11]))
        r = score(k, res("AC1", "web/src/Card.tsx", 5), mapping=A11Y, src=source)
        self.assertEqual(entry(r, "ALT")["outcome"], "FN")
        r = score(k, res("AC1", "web/src/Card.tsx", 10), mapping=A11Y, src=source)
        self.assertEqual(entry(r, "ALT")["outcome"], "TP")

    def test_symmetric_traps_and_clean_regions(self):
        k = key(mnf("T", "non-keyboard-accessible-interaction", "web/src/Card.tsx", [9, 9]))
        r = score(k, res("AC4", "web/src/Card.tsx", 5), mapping=A11Y, src=source)
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])
        k = key(clean("C", ["invalid-aria-usage"], Q, [5, 7]))
        self.assertEqual(outcomes(score(k, res("AC5", Q, 2), mapping=A11Y, src=source)), [(0, "clean-fp", "C")])
        k = key(clean("C", "*", Q, [5, 7]))
        self.assertEqual(outcomes(score(k, res("AC5", Q, 2), mapping=A11Y, src=source)), [(0, "uncovered", None)])

    def test_without_the_files_the_line_rule_and_the_report_says_so(self):
        k = key(mf("ARIA", "invalid-aria-usage", Q, [6, 6]), mf("X", "invalid-aria-usage", "src/Api/Handler.cs", [3, 3]))
        r = score(k, res("AC5", Q, 2), mapping=A11Y)
        self.assertEqual(entry(r, "ARIA")["matchScope"], "element-unavailable")
        self.assertEqual(entry(r, "ARIA")["outcome"], "FN")
        r = score(k, res("AC5", Q, 2), mapping=A11Y, src=source)
        self.assertEqual(entry(r, "X")["matchScope"], "element-unsupported")
        self.assertEqual(r["summary"]["elementScope"], {"source": None, "entries": 2, "applied": 1, "unavailable": 0,
                                                        "unsupported": 1})
        self.assertEqual(r["summary"]["resourceScope"]["entries"], 0)  # element entries are not resource entries

    def test_the_lines_of_the_entry_win_over_the_start_tag(self):
        k = key(mf("ARIA", "invalid-aria-usage", Q, [6, 6]))
        r = score(k, res("AC5", Q, 2), res("AC5", Q, 6), mapping=A11Y, src=source)
        self.assertEqual(outcomes(r), [(0, "redundant", "ARIA"), (1, "tp", "ARIA")])


# --- the shipped taxonomy and mapping ----------------------------------------------------------------------------------

class Shipped(unittest.TestCase):
    TAX = load_json(os.path.join(ROOT, "taxonomy.json"))
    MAP = load_json(os.path.join(ROOT, "mappings", "watchdog.json"))

    def test_taxonomy_scopes(self):
        got = {c["id"]: c.get("matchScope") for c in self.TAX["concepts"]}
        self.assertEqual({c for c, s in got.items() if s == "element"}, ELEMENT_SCOPE)
        self.assertEqual({c for c, s in got.items() if s == "group"}, {"module-dependency-cycle"})

    def test_mapping_declares_subjects_and_loads(self):
        m = Mapping(self.MAP)
        self.assertEqual(m.subject_text("D30", CVE), "form-data")
        self.assertEqual(m.subject_text("D12", "Vulnerable: Npgsql: Npgsql 8.0.2 — High severity. https://x"),
                         "Npgsql")
        self.assertEqual(m.subject_text("D11", "Flaky test: P.Tests::P.Tests.C.P.Tests.C.M: Passed 2×, failed 1× "
                                               "across repeated runs."), "P.Tests.C.M")
        self.assertEqual(m.subject_text("D11", "Flaky test: the repository roottests/x.test.ts::reads a pack: Passed "
                                               "2×, failed 1× across repeated runs."), "tests/x.test.ts::reads a pack")
        self.assertIsNone(m.subject_text("D13", "Leaked secret: jwt: jwt detected"))


if __name__ == "__main__":
    unittest.main()
