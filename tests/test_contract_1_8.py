"""Contract 1.8 (decision 0012): the harness names no producer, and a run reports the rules its mapping cannot place."""
import os
import unittest

from cai_bench import CONTRACT_VERSION
from cai_bench.mapping import Mapping
from tests.helpers import key, mf, res, run

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MAP = {
    "scanner": "example-scanner",
    "concepts": {"sql-injection": {"rules": [{"rule": "^D29$", "messages": ["^\\w+: sqli-rule:"]}], "dimensions": ["D29"]}},
    "offConcept": [{"rule": "^D29$", "message": "^\\w+: style-rule:", "source": "a style row, deliberately off-concept"}],
    "ignore": [{"rule": "^X1$", "reason": "progress row"}],
}


class UnplacedRules(unittest.TestCase):
    def _report(self, *results):
        return run(key(mf("SQL", "sql-injection", "src/a.cs", [10, 10])), *results, mapping=MAP)

    def test_a_rule_the_mapping_cannot_place_is_reported(self):
        r = self._report(res("D29", "src/a.cs", 10, "High: sqli-rule: built from input"),
                         res("D29", "src/b.cs", 3, "Medium: new-rule: something"))
        self.assertEqual(r["unplacedRules"], [{"ruleId": "D29", "title": "Medium"}])

    def test_placed_ignored_and_off_concept_rows_are_not_unplaced(self):
        r = self._report(res("D29", "src/a.cs", 10, "High: sqli-rule: built from input"),
                         res("D29", "src/c.cs", 4, "Low: style-rule: tabs"),
                         res("X1", "src/d.cs", 1, "progress"))
        self.assertEqual(r["unplacedRules"], [])

    def test_the_contract_is_1_8(self):
        self.assertEqual(CONTRACT_VERSION, "1.8")


class NoProducerInTheHarness(unittest.TestCase):
    def test_no_producer_mapping_ships_with_the_harness(self):
        names = os.listdir(os.path.join(ROOT, "mappings"))
        self.assertFalse([n for n in names if "watchdog" in n.lower() or "cca" in n.lower()], names)

    def test_harness_code_names_no_producer(self):
        for d in ("cai_bench",):
            for f in os.listdir(os.path.join(ROOT, d)):
                if f.endswith(".py"):
                    text = open(os.path.join(ROOT, d, f), encoding="utf-8").read().lower()
                    for word in ("watchdog", "canine", "kennel"):
                        self.assertNotIn(word, text, f"{d}/{f} names {word}")


if __name__ == "__main__":
    unittest.main()
