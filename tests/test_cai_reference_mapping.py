"""Pins mappings/cai-reference.json — the CAI reference implementation's generated mapping plus the taxonomy's
`parent` links (mappings/cai-reference-build/build.py) — against the taxonomy and against the rule ids the engine
really emitted on the training set (tests/fixtures/cai-reference-rule-ids.json). Also the comparison helpers of
results/cai-reference/ (canonical dimension, key-mismatch refusal, FN mechanism)."""
import importlib.util
import json
import os
import re
import tempfile
import unittest

from cai_bench.keyfile import load_json
from cai_bench.mapping import UNMAPPED, Mapping

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = load_json(os.path.join(ROOT, "mappings", "cai-reference.json"))
GENERATED = load_json(os.path.join(ROOT, "mappings", "cai-reference-build", "cai-reference.generated.json"))
TAX = load_json(os.path.join(ROOT, "taxonomy.json"))
CONCEPTS = {c["id"]: c for c in TAX["concepts"]}
RULE_IDS = load_json(os.path.join(ROOT, "tests", "fixtures", "cai-reference-rule-ids.json"))["ruleIds"]
M = Mapping(DOC)


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, *path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUILD = _load(("mappings", "cai-reference-build", "build.py"), "cai_reference_build")
COMPARE = _load(("results", "cai-reference", "compare.py"), "cai_reference_compare")
UNIT_FILES = _load(("results", "cai-reference", "unit_files.py"), "cai_reference_unit_files")


class MappingFile(unittest.TestCase):
    def test_loads_and_names_the_scanner(self):
        self.assertEqual(M.scanner, "cai-reference")
        self.assertTrue(M.version)

    def test_every_taxonomy_concept_is_in_the_mapping_and_nothing_else(self):
        self.assertEqual(set(DOC["concepts"]), set(CONCEPTS))

    def test_every_rule_is_one_exact_concept_id(self):
        for c, spec in DOC["concepts"].items():
            for r in spec["rules"]:
                self.assertIsInstance(r, str, c)
                m = re.fullmatch(r"\^([a-z0-9-]+)\$", r)
                self.assertIsNotNone(m, f"{c}: rule {r!r} is not an exact ruleId")
                self.assertEqual(m.group(1), c, f"{c}: its rule names another concept")

    def test_every_emitted_rule_id_maps_to_exactly_one_existing_concept_and_its_dimension(self):
        self.assertGreater(len(RULE_IDS), 100)
        for rid in RULE_IDS:
            concepts = M.concepts_of(rid, "any message", {})
            self.assertEqual(concepts, [rid], f"ruleId {rid}")
            self.assertIn(rid, CONCEPTS, f"ruleId {rid} is not a taxonomy concept")
            dim = M.dimension_of(rid, concepts)
            self.assertNotEqual(dim, UNMAPPED, rid)
            self.assertEqual([dim], M.dimensions_of_concept(rid), rid)

    def test_an_unknown_rule_id_maps_to_nothing(self):
        self.assertEqual(M.concepts_of("hardcoded-credential-x", "", {}), [])
        self.assertEqual(M.concepts_of("not-a-concept", "", {}), [])

    def test_unmapped_concepts_have_no_rule_and_a_reason(self):
        self.assertTrue(M.unmapped)
        for c, why in M.unmapped.items():
            self.assertEqual(DOC["concepts"][c]["rules"], [], c)
            self.assertTrue(why.strip(), c)

    def test_parents_mirror_the_taxonomy_exactly(self):
        want = {c: v["parent"] for c, v in CONCEPTS.items() if v.get("parent")}
        self.assertEqual(M.parents, want)
        for child, umbrella in want.items():
            self.assertEqual(M.ancestors(child), [umbrella])

    def test_committed_mapping_is_the_build_of_the_generated_file(self):
        built = BUILD.build(GENERATED, TAX)
        self.assertEqual(built, DOC)
        # the build adds parents and the note, nothing else
        for c, spec in GENERATED["concepts"].items():
            self.assertEqual({k: v for k, v in DOC["concepts"][c].items() if k != "parent"}, spec)
        self.assertEqual(DOC["unmapped"], GENERATED["unmapped"])
        self.assertEqual(DOC["ruleDimension"], GENERATED["ruleDimension"])
        self.assertNotIn("parent", json.dumps(GENERATED))


class ComparisonHelpers(unittest.TestCase):
    WD = Mapping(load_json(os.path.join(ROOT, "mappings", "watchdog.json")))

    def test_canonical_dimension_prefers_side_a_then_side_b_and_umbrellas_follow_children(self):
        self.assertEqual(COMPARE.canonical_dimension("hardcoded-credential", M, self.WD), "D13")
        self.assertEqual(COMPARE.canonical_dimension("container-excessive-privilege", M, self.WD), "D31")
        self.assertEqual(COMPARE.canonical_dimension("iac-misconfiguration", M, self.WD), "D31")
        # a concept the RI does not detect falls back to Watchdog's dimension
        self.assertEqual(COMPARE.canonical_dimension("deprecated-dependency", M, self.WD),
                         self.WD.dims["deprecated-dependency"][0])

    def test_wilson_interval(self):
        lo, hi = COMPARE.wilson(213, 225)
        self.assertAlmostEqual(lo, 0.9092, places=3)
        self.assertAlmostEqual(hi, 0.9693, places=3)
        self.assertIsNone(COMPARE.wilson(0, 0))

    def _final(self, tag, sha):
        return {"instrument": "x", "repos": [{"name": "u", "tag": tag, "keySha256": sha, "languages": ["csharp"],
                                              "family": "f", "summary": {}, "concepts": [], "dimensions": [],
                                              "scoreBands": []}]}

    def test_compare_refuses_different_keys(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "a.json"), os.path.join(d, "b.json")
            for path, tag, sha in ((a, "v1.2.0", "aa"), (b, "v1.1.0", "bb")):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self._final(tag, sha), f)
            mp = os.path.join(ROOT, "mappings", "cai-reference.json")
            with self.assertRaises(SystemExit) as cm:
                COMPARE.main(["--a", a, "--a-mapping", mp, "--b", b, "--b-mapping", mp, "--units", "u"])
            self.assertIn("refusing", str(cm.exception))

    def test_fn_mechanism(self):
        report = {"results": [{"concepts": ["sql-injection"], "attributedConcept": "sql-injection"}]}
        self.assertEqual(UNIT_FILES.fn_mechanism({"concept": "primitive-obsession"}, M, report)[0], "no-rule")
        self.assertEqual(UNIT_FILES.fn_mechanism({"concept": "sql-injection", "fileLevel": True}, M, report)[0],
                         "off-site")
        self.assertEqual(UNIT_FILES.fn_mechanism({"concept": "sql-injection"}, M, report)[0], "elsewhere")
        self.assertEqual(UNIT_FILES.fn_mechanism({"concept": "path-traversal"}, M, report)[0], "silent")

    def test_verdict_disambiguation_by_commit_and_message(self):
        res = [{"run": 0, "resultIndex": 0, "ruleId": "r", "file": "f", "line": 3, "commitSha": None,
                "outcome": "trap-fp", "concepts": ["r"]},
               {"run": 0, "resultIndex": 1, "ruleId": "r", "file": "f", "line": 3, "commitSha": "abcdef12",
                "outcome": "trap-fp", "concepts": ["r"]}]
        report = {"results": res, "entries": []}
        row = {"name": "u", "repo": "o/u", "tag": "v1", "commit": "c", "keySha256": "k", "keyVersion": "1",
               "scan": {"sarifSha256": "s"}, "summary": {}}
        msgs = {(0, 0): "current copy", (0, 1): "history copy"}

        def one(v):
            doc = UNIT_FILES.build_unit(row, report, "/nonexistent", msgs, M,
                                        {"verdicts": [dict(v, ruleId="r", file="f", line=3, **{"class": "redundant",
                                                                                            "reason": "x"})]},
                                        "i", "2026-10-08")
            return doc["verdicts"][0]["message"]

        with self.assertRaises(SystemExit):
            one({})
        self.assertEqual(one({"commitSha": None}), "current copy")
        self.assertEqual(one({"commitSha": "abcdef"}), "history copy")
        self.assertEqual(one({"messageContains": "history"}), "history copy")


if __name__ == "__main__":
    unittest.main()
