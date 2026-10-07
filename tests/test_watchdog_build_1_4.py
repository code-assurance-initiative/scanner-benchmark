"""Contract 1.4 in the generated Watchdog files: concepts beyond the reference scanner (`unmapped`), the AC6 split, the
untrusted-data-executed family, summary rows, and matrix coverage read from the frozen keys."""
import json
import os
import unittest

from cai_bench.keyfile import load_json
from cai_bench.mapping import Mapping
from tests.helpers import entry, key, mf, mnf, outcomes, res, run

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = load_json(os.path.join(ROOT, "mappings", "watchdog.json"))
M = Mapping(DOC)
TAX = {c["id"]: c for c in load_json(os.path.join(ROOT, "taxonomy.json"))["concepts"]}
MATRIX = load_json(os.path.join(ROOT, "coverage", "matrix.json"))

NEW_UNMAPPED = ["business-logic-in-controller", "value-object-mutability", "domain-event-never-handled",
                "event-schema-change-without-upcaster", "react-index-as-key", "react-hook-missing-dependency",
                "react-state-mutation", "form-error-not-associated", "modal-focus-not-managed",
                "autoplay-media-without-control", "consent-not-checked"]


def wd(k, *results):
    return run(k, *results, mapping=DOC)


class Unmapped(unittest.TestCase):
    def test_every_new_concept_is_in_the_taxonomy_and_unmapped_with_the_reason(self):
        self.assertEqual(sorted(M.unmapped), sorted(NEW_UNMAPPED))
        for c in NEW_UNMAPPED:
            self.assertIn(c, TAX)
            self.assertEqual(DOC["concepts"][c], {"rules": [], "dimensions": []})
            self.assertEqual(M.unmapped[c], "no Watchdog rule detects this")
            self.assertIsNone(TAX[c]["cwe"])  # none of them has a genuine CWE

    def test_a_plant_of_an_unmapped_concept_is_a_watchdog_fn(self):
        # the closest real Watchdog row on the planted site does not stand in for it
        r = wd(key(mf("BLC", "business-logic-in-controller", "src/Api/WorkOrdersController.cs", [47, 74])),
               res("AX10", "src/Api/WorkOrdersController.cs", 50, "Business logic share: 31% of production lines"))
        self.assertEqual(entry(r, "BLC")["outcome"], "FN")
        self.assertIn("business-logic-in-controller", r["unmappedConcepts"])
        self.assertEqual(r["dimensions"]["(no scanner rule)"]["fn"], 1)

    def test_existing_rule_less_concepts_are_still_mapped_to_their_dimension(self):
        # excessive-mocking (= mock-dominated test) and pointless-catch-rethrow existed already: their dimension covers
        # them, no title evidences them (`unevidenced`), so they are not `unmapped`
        for c, d in (("excessive-mocking", "D10"), ("pointless-catch-rethrow", "X3")):
            self.assertEqual(DOC["concepts"][c]["rules"], [])
            self.assertEqual(DOC["concepts"][c]["dimensions"], [d])
            self.assertNotIn(c, M.unmapped)
            self.assertTrue(any(u["concept"] == c and u["dimension"] == d for u in DOC["unevidenced"]))


class Ac6Split(unittest.TestCase):
    CASES = [
        ("Focus outline removed inline: outline:none/0 in an inline style removes the keyboard focus ring", "focus-outline-removed"),
        ("Focus outline removed in CSS without a :focus replacement: outline:none/0 with no :focus rule", "focus-outline-removed"),
        ("Animation without a prefers-reduced-motion guard: This stylesheet animates but never checks", "motion-without-reduced-motion"),
        ("Low contrast Tailwind colour pair (2.9:1): This element's Tailwind text/background", "visual-and-motion-safety"),
        ("Low contrast colour pair in CSS (3.1:1): `.btn-primary` sets color: white", "visual-and-motion-safety"),
        ("Low contrast colour pair in CSS-in-JS (2.2:1): A styled-components/emotion style", "visual-and-motion-safety"),
        ("Low contrast colour pair (4.1:1): The inline foreground/background colours", "visual-and-motion-safety"),
    ]

    def test_each_ac6_title_lands_on_one_concept(self):
        for msg, c in self.CASES:
            self.assertEqual(M.concepts_of("AC6", msg), [c], msg)

    def test_children_have_the_umbrella_as_parent(self):
        for c in ("focus-outline-removed", "motion-without-reduced-motion"):
            self.assertEqual(TAX[c]["parent"], "visual-and-motion-safety")
            self.assertEqual(M.parents[c], "visual-and-motion-safety")

    def test_a_key_naming_the_umbrella_still_matches_a_child_row(self):
        r = wd(key(mf("A", "visual-and-motion-safety", "src/app.css", [3, 3])),
               res("AC6", "src/app.css", 3, self.CASES[0][0]))
        self.assertEqual(entry(r, "A")["outcome"], "TP")

    def test_a_precise_plant_is_not_found_by_a_sibling(self):
        r = wd(key(mf("A", "motion-without-reduced-motion", "src/app.css", [3, 3])),
               res("AC6", "src/app.css", 3, self.CASES[0][0]))
        self.assertEqual(entry(r, "A")["outcome"], "FN")


class DeserialisationFamily(unittest.TestCase):
    CODE = "High: watchdog-assembled-code-string-evaluated-ts: a string assembled from input is evaluated"

    def test_family_declared(self):
        self.assertEqual(M.family_of("insecure-deserialization"), "untrusted-data-executed")
        self.assertEqual(M.family_of("code-injection"), "untrusted-data-executed")
        self.assertEqual(M.concepts_of("D29", self.CODE), ["code-injection"])

    def test_deserialization_plant_reported_as_code_injection_is_found(self):
        r = wd(key(mf("DESER", "insecure-deserialization", "src/import.ts", [20, 20])),
               res("D29", "src/import.ts", 20, self.CODE))
        self.assertEqual(entry(r, "DESER")["outcome"], "TP")

    def test_and_charged_at_a_deserialization_trap(self):
        r = wd(key(mnf("T", "insecure-deserialization", "src/import.ts", [20, 20])),
               res("D29", "src/import.ts", 20, self.CODE))
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])


class SummaryRows(unittest.TestCase):
    X2 = ("Not all async methods take a CancellationToken: Only 24/27 async methods accept a CancellationToken, so "
          "in-flight work can't be stopped early")

    def test_x2_ratio_row_is_a_summary_of_its_located_plant(self):
        r = wd(key(mf("CH-026", "missing-cancellation-propagation", "src/RateCardCache.cs", [63, 63])),
               res("X2", None, None, self.X2))
        self.assertEqual(entry(r, "CH-026")["outcome"], "FN")
        self.assertEqual(outcomes(r), [(0, "summary-of-concept", None)])
        self.assertEqual(r["summaryOfConcept"][0]["plants"], ["CH-026"])
        self.assertEqual(r["summary"]["noise"], 0)


class MatrixFromKeys(unittest.TestCase):
    def row(self, did):
        return next(r for r in MATRIX["rows"] if r["id"] == did)

    def test_frozen_repos_report_key_labels(self):
        cov = {c["repo"]: c for c in self.row("X2")["coverage"]}
        rd = cov["bench-csharp-readiness"]  # readiness was planned with score-bands only; its key plants X2 rows
        self.assertTrue(rd["source"].startswith("key v"))
        self.assertIn("must-fire", rd["labels"])
        reg = load_json(os.path.join(ROOT, "registry.json"))
        frozen = {x["repo"].split("/")[1] for x in reg["repos"]}
        planned = [c for repo, c in cov.items() if repo not in frozen]
        self.assertTrue(all(c["source"] == "plan" for c in planned))  # not frozen: planned labels stay
        self.assertTrue(all(c["source"].startswith("key v") for repo, c in cov.items() if repo in frozen))

    def test_every_registered_repo_is_listed_with_its_key(self):
        reg = load_json(os.path.join(ROOT, "registry.json"))
        latest = {}
        for x in reg["repos"]:
            latest[x["repo"].split("/")[1]] = x
        self.assertEqual({r: v["keySha256"] for r, v in MATRIX["frozenRepos"].items()},
                         {r: x["keySha256"] for r, x in latest.items()})

    def test_no_frozen_entry_claims_a_planned_label(self):
        for r in MATRIX["rows"]:
            for c in r.get("coverage", []):
                if c.get("source", "").startswith("key"):
                    self.assertEqual(c["labels"], [l for l in MATRIX["labelKinds"] if c["entries"].get(l)], (r["id"], c))

    def test_beyond_reference_lists_every_unmapped_concept(self):
        self.assertEqual(sorted(b["concept"] for b in MATRIX["beyondReference"]), sorted(NEW_UNMAPPED))
        for b in MATRIX["beyondReference"]:
            self.assertTrue(b["repos"], b["concept"])


if __name__ == "__main__":
    unittest.main()
