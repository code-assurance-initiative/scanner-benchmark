"""Contract 1.9: CAI dimensions come from the taxonomy's own assignment, never from the engine's mapping."""
import json
import unittest

from cai_bench import CONTRACT_VERSION
from cai_bench.engine_report import _rows
from cai_bench.mapping import Mapping
from cai_bench.sarif import read_results
from cai_bench.scoring import NO_CAI_DIMENSION, score
from cai_bench.taxonomy import concept_dimensions
from tests.helpers import key, mf, mnf, res, sarif

TAXONOMY = {"version": "test", "concepts": [
    {"id": "sql-injection", "title": "SQL injection", "family": "security", "kind": "finding", "description": "d",
     "dimensions": ["D29"]},
    {"id": "security-response-headers", "title": "headers", "family": "security", "kind": "finding", "description": "d",
     "dimensions": ["S1", "AXH1"]},
    {"id": "tabs", "title": "tabs", "family": "codehealth", "kind": "finding", "description": "d"},
]}

# The engine groups its rules its own way: both concepts under its "SEC" dimension, and tabs under D29.
MAP = {"scanner": "example-scanner", "concepts": {
    "sql-injection": {"rules": [{"rule": "^SQLI$"}], "dimensions": ["SEC"]},
    "security-response-headers": {"rules": [{"rule": "^HDR$"}], "dimensions": ["SEC"]},
    "tabs": {"rules": [{"rule": "^TAB$"}], "dimensions": ["D29"]}}}


def run(k, *results, contract=None):
    return score(json.loads(json.dumps(k)), read_results(sarif(*results), ()), Mapping(MAP), contract=contract,
                 taxonomy=TAXONOMY)


class CaiDimensions(unittest.TestCase):
    def setUp(self):
        self.k = key(mf("SQL", "sql-injection", "src/a.cs", [10, 10]),
                     mf("HDR", "security-response-headers", "src/b.cs", [5, 5]),
                     mnf("TRAP", "sql-injection", "src/c.cs", [7, 7]))

    def test_the_contract_is_1_9(self):
        self.assertEqual(CONTRACT_VERSION, "1.9")

    def test_rows_follow_the_taxonomy_not_the_mapping(self):
        r = run(self.k, res("SQLI", "src/a.cs", 10), res("HDR", "src/b.cs", 5))
        self.assertEqual(sorted(r["caiDimensions"]), ["AXH1", "D29", "S1"])
        self.assertEqual(sorted(r["dimensions"]), ["SEC"])  # the engine's own grouping is still reported apart

    def test_one_finding_counts_in_every_dimension_its_concept_evidences(self):
        r = run(self.k, res("HDR", "src/b.cs", 5))
        for d in ("S1", "AXH1"):
            self.assertEqual(r["caiDimensions"][d]["tp"], 1, d)
        self.assertEqual(r["caiDimensions"]["D29"]["fn"], 1)

    def test_a_finding_on_a_trap_is_noise_of_the_trap_dimension_only(self):
        r = run(self.k, res("SQLI", "src/c.cs", 7))
        self.assertEqual(r["caiDimensions"]["D29"]["trapFp"], 1)
        self.assertEqual(r["caiDimensions"]["S1"]["trapFp"], 0)
        self.assertEqual(r["caiDimensions"]["S1"]["noise"], 0)

    def test_a_finding_of_a_concept_without_a_cai_dimension_is_its_own_row(self):
        r = run(self.k, res("TAB", "src/d.cs", 1))
        self.assertIn(NO_CAI_DIMENSION, r["caiDimensions"])
        self.assertNotIn("D29", [d for d in r["caiDimensions"] if r["caiDimensions"][d]["results"]])

    def test_before_1_9_there_are_no_cai_dimensions(self):
        r = run(self.k, res("SQLI", "src/a.cs", 10), contract="1.8")
        self.assertNotIn("caiDimensions", r)

    def test_the_engine_report_reads_cai_dimensions_first(self):
        r = run(self.k, res("SQLI", "src/a.cs", 10))
        self.assertIs(_rows(r), r["caiDimensions"])

    def test_a_malformed_assignment_is_refused(self):
        with self.assertRaises(ValueError):
            concept_dimensions({"concepts": [{"id": "x", "dimensions": "D1"}]})


class TheHarnessTaxonomy(unittest.TestCase):
    def test_every_concept_states_its_cai_dimensions(self):
        from cai_bench.taxonomy import load_taxonomy
        t = load_taxonomy()
        dims = concept_dimensions(t)
        self.assertEqual(len(dims), len(t["concepts"]))
        self.assertTrue(any(dims.values()))


if __name__ == "__main__":
    unittest.main()
