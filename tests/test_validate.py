import json
import os
import unittest

from cai_bench.keyfile import validate_key
from tests.helpers import FIXTURES, TAXONOMY, band, clean, key, mf, mnf, na

PC = "src/Billing/PaymentClient.cs"


def problems(k, taxonomy=TAXONOMY):
    return validate_key(json.loads(json.dumps(k)), taxonomy)


class Valid(unittest.TestCase):
    def test_fixture_key_is_valid(self):
        with open(os.path.join(FIXTURES, "answer-key.json")) as f:
            self.assertEqual(problems(json.load(f)), [])

    def test_every_label_shape_is_accepted(self):
        k = key(mf("A", "hardcoded-credential", PC, [1, 2], cwe="CWE-798", scannerHints={"any-scanner": ["D13"]}),
                mnf("T", "hardcoded-credential", PC, [40, 40]),
                clean("C1", "*", "src/Invoice.cs"), clean("C2", ["weak-hash"], "src/Hash.cs", [1, 9]),
                na("N", "sql-injection"), band("B", "security-policy-present", 0, 100), lineTolerance=0)
        self.assertEqual(problems(k), [])


class Invalid(unittest.TestCase):
    def assertProblem(self, k, *fragments, taxonomy=TAXONOMY):
        ps = problems(k, taxonomy)
        self.assertTrue(ps, "expected the key to be rejected")
        for frag in fragments:
            self.assertTrue(any(frag in p for p in ps), f"no problem mentions {frag!r}: {ps}")

    def test_duplicate_ids(self):
        self.assertProblem(key(mf("A", "hardcoded-credential", PC), mf("A", "weak-hash", PC)), "duplicate id 'A'")

    def test_unknown_concept(self):
        self.assertProblem(key(mf("A", "no-such-thing", PC)), "concept 'no-such-thing' is not in the taxonomy")
        self.assertProblem(key(clean("C", ["hardcoded-credential", "nope"], PC)), "concept 'nope'")

    def test_unknown_concept_not_checked_without_taxonomy(self):
        self.assertEqual(problems(key(mf("A", "no-such-thing", PC)), taxonomy=None), [])

    def test_cwe_mismatch(self):
        self.assertProblem(key(mf("A", "hardcoded-credential", PC, cwe="CWE-89")),
                           "cwe CWE-89 disagrees with the taxonomy's CWE-798")

    def test_cwe_allowed_where_taxonomy_has_none(self):
        self.assertEqual(problems(key(mf("A", "long-method", PC, cwe="CWE-1121"))), [])

    def test_bad_band(self):
        self.assertProblem(key(band("B", "security-policy-present", 90, 80)), "min 90 is above max 80")
        self.assertProblem(key(band("B", "security-policy-present", -1, 80)), "0..100")
        self.assertProblem(key(band("B", "security-policy-present", 0, 101)), "0..100")
        bad = band("B", "security-policy-present", 0, 1)
        bad["band"] = [5]
        self.assertProblem(key(bad), "[min, max]")
        nob = band("B", "security-policy-present", 0, 1)
        del nob["band"]
        self.assertProblem(key(nob), "requires 'band'")

    def test_bad_lines(self):
        self.assertProblem(key(mf("A", "hardcoded-credential", PC, [9, 3])), "start 9 is after end 3")
        self.assertProblem(key(mf("A", "hardcoded-credential", PC, [0, 3])), ">= 1")
        self.assertProblem(key(mf("A", "hardcoded-credential", None, [1, 3])), "'lines' requires 'file'")

    def test_conditional_requirements(self):
        self.assertProblem(key({"id": "A", "label": "must-fire", "rationale": "x", "file": PC}), "requires 'concept'")
        self.assertProblem(key({"id": "C", "label": "clean", "rationale": "x", "concept": "weak-hash"}),
                           "requires 'concepts'", "does not take 'concept'")
        self.assertProblem(key(mf("A", "hardcoded-credential", PC, concepts="*")), "does not take 'concepts'")
        self.assertProblem(key(band("B", "security-policy-present", 0, 1, file=PC)), "does not take 'file'")

    def test_rationale_required_everywhere(self):
        for e in (mf("A", "weak-hash", PC), mnf("A", "weak-hash", PC), clean("A", "*", PC), na("A", "weak-hash"),
                  band("A", "security-policy-present", 0, 1)):
            del e["rationale"]
            self.assertProblem(key(e), "'rationale' is required")

    def test_bad_label_and_unknown_property(self):
        self.assertProblem(key({"id": "A", "label": "should-fire", "rationale": "x"}), "'label' must be one of")
        self.assertProblem(key(mf("A", "weak-hash", PC, severity="high")), "unknown property 'severity'")

    def test_top_level(self):
        k = key()
        del k["repo"]
        k["keyVersion"] = "1.0"
        self.assertProblem(k, "'repo' is required", "MAJOR.MINOR.PATCH")

    def test_must_fire_and_must_not_fire_overlap(self):
        self.assertProblem(key(mf("A", "hardcoded-credential", PC, [14, 14]),
                               mnf("T", "hardcoded-credential", PC, [17, 17])), "A (must-fire) and T (must-not-fire)")
        self.assertProblem(key(mf("A", "hardcoded-credential", PC), mnf("T", "hardcoded-credential", PC, [5, 5])),
                           "overlap")
        self.assertProblem(key(mf("A", "missing-security-policy"), mnf("T", "missing-security-policy")), "overlap")

    def test_no_overlap_when_apart_or_other_concept(self):
        self.assertEqual(problems(key(mf("A", "hardcoded-credential", PC, [14, 14]),
                                      mnf("T", "hardcoded-credential", PC, [18, 18]))), [])
        self.assertEqual(problems(key(mf("A", "hardcoded-credential", PC, [14, 14]),
                                      mnf("T", "weak-hash", PC, [14, 14]))), [])

    def test_must_fire_inside_clean_region(self):
        self.assertProblem(key(mf("A", "weak-hash", PC, [5, 5]), clean("C", "*", PC)), "lies inside C")
        self.assertProblem(key(mf("A", "weak-hash", PC, [5, 5]), clean("C", ["weak-hash"], PC, [1, 9])), "inside")
        self.assertEqual(problems(key(mf("A", "weak-hash", PC, [5, 5]), clean("C", ["sql-injection"], PC))), [])
        self.assertEqual(problems(key(mf("A", "weak-hash", PC, [5, 5]), clean("C", "*", PC, [6, 9]))), [])

    def test_sites_compared_by_exact_repo_relative_path(self):
        # Contract 1.4: entry paths are repository-relative, and the scorer compares them EXACTLY. A root
        # CHANGELOG.md and packages/x/CHANGELOG.md are different files: a plant in one and a clean certificate (or a
        # trap) on the other do not contradict each other.
        root, nested = "CHANGELOG.md", "packages/x/CHANGELOG.md"
        self.assertEqual(problems(key(mf("A", "weak-hash", root, [5, 5]), clean("C", "*", nested))), [])
        self.assertEqual(problems(key(mf("A", "weak-hash", nested, [5, 5]), clean("C", "*", root))), [])
        self.assertEqual(problems(key(mf("A", "weak-hash", root, [5, 5]), mnf("T", "weak-hash", nested, [5, 5]))), [])
        self.assertEqual(problems(key(mf("A", "weak-hash", nested), mnf("T", "weak-hash", root))), [])
        # the same file still collides, also when spelled with a leading "./"
        self.assertProblem(key(mf("A", "weak-hash", root, [5, 5]), clean("C", "*", "./" + root)), "lies inside C")
        self.assertProblem(key(mf("A", "weak-hash", nested, [5, 5]), mnf("T", "weak-hash", "./" + nested, [6, 6])),
                           "overlap")

    def test_not_applicable_contradicted(self):
        self.assertProblem(key(na("N", "weak-hash"), mf("A", "weak-hash", PC)), "N marks concept 'weak-hash'")

    def test_scanner_hints_must_map_names_to_rule_lists(self):
        self.assertProblem(key(mf("A", "hardcoded-credential", PC, [1, 2], scannerHints=["D13"])), "scannerHints")


if __name__ == "__main__":
    unittest.main()
