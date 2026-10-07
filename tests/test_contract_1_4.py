"""Contract 1.4: repo-relative path matching (exact, suffix only as a fallback), concepts no scanner rule maps
(`unmapped`), location-less summaries of a located concept (`summaryOfConcept`), and the configuration stamp."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

from cai_bench.mapping import Mapping, MappingError
from cai_bench.paths import repo_relative
from cai_bench.sarif import read_results
from cai_bench.scoring import render, score as score_report
from tests.helpers import MAPPING_DOC, clean, entry, key, mf, mnf, na, outcomes, res, run, sarif

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

M = copy.deepcopy(MAPPING_DOC)
M["concepts"].update({
    "end-of-life-platform": {"rules": ["^D12$"], "dimensions": ["D12"]},
    "missing-cancellation-propagation": {"rules": ["^X2$"], "dimensions": ["X2"]},
    "insecure-deserialization": {"rules": [{"rule": "^D29$", "messages": ["^High: deser"]}], "dimensions": ["D29"],
                                 "family": "untrusted-data-executed"},
    "code-injection": {"rules": [{"rule": "^D29$", "messages": ["^High: eval"]}], "dimensions": ["D29"],
                       "family": "untrusted-data-executed"},
    "react-index-as-key": {"rules": [], "dimensions": []},
})
M["summaryOfConcept"] = [{"rule": "^X2$", "message": "^Not all async methods take a CancellationToken:",
                          "reason": "ratio row over every async method; the per-method rows never reach SARIF"}]
M["unmapped"] = [{"concept": "react-index-as-key", "reason": "no reference-scanner rule detects this"}]

REPO = "bench-ts-security-dependencies"


def score(k, *results, mapping=M, prefixes=()):
    return run(k, *results, mapping=mapping, prefixes=prefixes)


def kr(*entries):
    return key(*entries, repo=f"code-assurance-initiative/{REPO}")


class RepoRelative(unittest.TestCase):
    def test_relative_uri_is_repo_relative(self):
        self.assertEqual(repo_relative("tools/x/.nvmrc"), ("tools/x/.nvmrc", True))
        self.assertEqual(repo_relative("./.nvmrc"), (".nvmrc", True))

    def test_absolute_checkout_prefixes(self):
        self.assertEqual(repo_relative("/src/tools/x/.nvmrc"), ("tools/x/.nvmrc", True))
        self.assertEqual(repo_relative("file:///src/.nvmrc"), (".nvmrc", True))
        self.assertEqual(repo_relative("/tmp/a/b/" + REPO + "/.nvmrc", repo_name=REPO), (".nvmrc", True))
        self.assertEqual(repo_relative("/w/repo/src/a.cs", prefixes=["/w/repo"]), ("src/a.cs", True))

    def test_unknown_absolute_root_falls_back_to_suffix(self):
        self.assertEqual(repo_relative("/home/ci/work/repo/.nvmrc"), ("/home/ci/work/repo/.nvmrc", False))
        self.assertEqual(repo_relative("../elsewhere/.nvmrc"), ("../elsewhere/.nvmrc", False))


class ExactPaths(unittest.TestCase):
    def test_nvmrc_collision_root_entry_is_not_hit_by_a_nested_file(self):
        # the plant is the repository-root .nvmrc; a result on a nested tool's .nvmrc is a different file
        r = score(kr(mf("EOL", "end-of-life-platform", ".nvmrc")), res("D12", "tools/manifest-export/.nvmrc", 1))
        self.assertEqual(entry(r, "EOL")["outcome"], "FN")
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])
        self.assertEqual(r["results"][0]["pathMatch"], "exact")

    def test_nvmrc_root_result_hits_the_root_entry(self):
        r = score(kr(mf("EOL", "end-of-life-platform", ".nvmrc")), res("D12", ".nvmrc", 1))
        self.assertEqual(entry(r, "EOL")["outcome"], "TP")

    def test_two_lock_files_do_not_collide(self):
        k = kr(mf("ROOT", "end-of-life-platform", "package-lock.json"),
               mnf("TOOL", "end-of-life-platform", "tools/manifest-export/package-lock.json"))
        r = score(k, res("D12", "package-lock.json", 1))
        self.assertEqual(entry(r, "ROOT")["outcome"], "TP")
        self.assertEqual(entry(r, "TOOL")["outcome"], "TN")
        r = score(k, res("D12", "tools/manifest-export/package-lock.json", 1))
        self.assertEqual(entry(r, "ROOT")["outcome"], "FN")
        self.assertEqual(entry(r, "TOOL")["outcome"], "FP")

    def test_clean_region_is_exact_too(self):
        r = score(kr(clean("C", "*", ".nvmrc")), res("D12", "tools/manifest-export/.nvmrc", 1))
        self.assertEqual(entry(r, "C")["outcome"], "TN")

    def test_absolute_paths_under_the_checkout_are_exact(self):
        r = score(kr(mf("EOL", "end-of-life-platform", ".nvmrc")),
                  res("D12", f"/tmp/scan-1/{REPO}/tools/manifest-export/.nvmrc", 1))
        self.assertEqual(entry(r, "EOL")["outcome"], "FN")
        self.assertEqual(r["results"][0]["file"], "tools/manifest-export/.nvmrc")
        r = score(kr(mf("EOL", "end-of-life-platform", ".nvmrc")), res("D12", f"/src/.nvmrc", 1))
        self.assertEqual(entry(r, "EOL")["outcome"], "TP")

    def test_unresolvable_absolute_path_keeps_the_suffix_rule(self):
        r = score(kr(mf("EOL", "end-of-life-platform", ".nvmrc")), res("D12", "/home/ci/w/r/.nvmrc", 1))
        self.assertEqual(entry(r, "EOL")["outcome"], "TP")
        self.assertEqual(r["results"][0]["pathMatch"], "suffix")
        self.assertEqual(r["summary"]["pathMatches"], {"exact": 0, "suffix": 1})

    def test_uri_base_id_resolution(self):
        doc = sarif(res("D12", "tools/manifest-export/.nvmrc", 1))
        doc["runs"][0]["originalUriBaseIds"] = {"SRCROOT": {"uri": "file:///home/ci/somewhere/"}}
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "SRCROOT"
        rs = read_results(doc)
        self.assertEqual((rs[0]["file"], rs[0]["pathExact"]), ("tools/manifest-export/.nvmrc", True))
        # a base that is itself relative to the root contributes its path
        doc["runs"][0]["originalUriBaseIds"] = {"SRCROOT": {"uri": "file:///home/ci/somewhere/"},
                                                "TOOLS": {"uri": "tools/", "uriBaseId": "SRCROOT"}}
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].update(
            uri="manifest-export/.nvmrc", uriBaseId="TOOLS")
        rs = read_results(doc)
        self.assertEqual((rs[0]["file"], rs[0]["pathExact"]), ("tools/manifest-export/.nvmrc", True))

    def test_message_located_basename_keeps_the_suffix_rule(self):
        mp = copy.deepcopy(M)
        mp["locationFromMessage"] = [{"rule": "^D12$", "pattern": r"(?P<file>\.nvmrc):(?P<line>\d+)"}]
        r = score(kr(mf("EOL", "end-of-life-platform", "tools/manifest-export/.nvmrc", [1, 1])),
                  res("D12", None, None, "EOL runtime at .nvmrc:1"), mapping=mp)
        self.assertEqual(entry(r, "EOL")["outcome"], "TP")
        self.assertEqual(r["results"][0]["pathMatch"], "suffix")


class Unmapped(unittest.TestCase):
    def test_mapping_parses_unmapped_and_refuses_rules_on_them(self):
        self.assertEqual(Mapping(M).unmapped, {"react-index-as-key": "no reference-scanner rule detects this"})
        bad = copy.deepcopy(M)
        bad["concepts"]["react-index-as-key"]["rules"] = ["^R1$"]
        with self.assertRaises(MappingError):
            Mapping(bad)
        bad = copy.deepcopy(M)
        bad["unmapped"] = [{"concept": "nope", "reason": "x"}]
        with self.assertRaises(MappingError):
            Mapping(bad)

    def test_must_fire_on_an_unmapped_concept_is_a_false_negative(self):
        r = score(key(mf("K", "react-index-as-key", "src/List.tsx", [12, 12])), res("D13", "src/List.tsx", 12))
        self.assertEqual(entry(r, "K")["outcome"], "FN")
        self.assertEqual(r["summary"]["fn"], 1)
        self.assertEqual(r["summary"]["recall"], 0.0)
        self.assertEqual(r["concepts"]["react-index-as-key"]["fn"], 1)
        self.assertEqual(r["unmappedConcepts"], ["react-index-as-key"])
        self.assertEqual(r["dimensions"]["(no scanner rule)"]["fn"], 1)
        self.assertIn("no rule of this scanner maps", render(r))

    def test_concept_absent_from_the_mapping_is_also_a_false_negative(self):
        r = score(key(mf("K", "focus-outline-removed", "src/a.css", [3, 3])), res("D13", "src/a.css", 3))
        self.assertEqual(entry(r, "K")["outcome"], "FN")
        self.assertEqual(r["unmappedConcepts"], ["focus-outline-removed"])


class Family(unittest.TestCase):
    def test_deserialization_reported_as_code_injection_is_found(self):
        r = score(key(mf("DESER", "insecure-deserialization", "src/a.ts", [5, 5])),
                  res("D29", "src/a.ts", 5, "High: eval-of-untrusted: …"))
        self.assertEqual(entry(r, "DESER")["outcome"], "TP")

    def test_and_charged_at_a_trap(self):
        r = score(key(mnf("T", "insecure-deserialization", "src/a.ts", [5, 5])),
                  res("D29", "src/a.ts", 5, "High: eval-of-untrusted: …"))
        self.assertEqual(entry(r, "T")["outcome"], "FP")


SUMMARY = "Not all async methods take a CancellationToken: 4 of 9 public async methods accept no token"


class SummaryOfConcept(unittest.TestCase):
    K = key(mf("A", "missing-cancellation-propagation", "src/Svc.cs", [10, 10]),
            mf("B", "missing-cancellation-propagation", "src/Svc.cs", [20, 20]))

    def test_unlocated_summary_does_not_match_located_plants_and_is_not_noise(self):
        r = score(self.K, res("X2", None, None, SUMMARY))
        self.assertEqual([entry(r, x)["outcome"] for x in "AB"], ["FN", "FN"])
        self.assertEqual(outcomes(r), [(0, "summary-of-concept", None)])
        s = r["summary"]
        self.assertEqual((s["noise"], s["results"], s["summaryOfConcept"]), (0, 0, 1))
        self.assertEqual(r["summaryOfConcept"], [{"index": 0, "ruleId": "X2", "concept": "missing-cancellation-propagation",
                                                  "message": SUMMARY, "plants": ["A", "B"],
                                                  "reason": M["summaryOfConcept"][0]["reason"]}])
        self.assertEqual(entry(r, "A")["summarisedBy"], [0])
        self.assertIn("summaryOfConcept", render(r))

    def test_located_result_still_wins(self):
        r = score(self.K, res("X2", None, None, SUMMARY), res("X2", "src/Svc.cs", 10))
        self.assertEqual(entry(r, "A")["outcome"], "TP")
        self.assertEqual(outcomes(r)[0], (0, "summary-of-concept", None))

    def test_repository_level_plant_takes_the_summary(self):
        r = score(key(mf("R", "missing-cancellation-propagation")), res("X2", None, None, SUMMARY))
        self.assertEqual(entry(r, "R")["outcome"], "TP")

    def test_an_undeclared_location_less_row_of_the_concept_stays_noise(self):
        # only rows the mapping declares summaries are; a per-item row that lost its location is not one
        r = score(self.K, res("X2", None, None, "Async method lacks a token: DownloadAsync"))
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])

    def test_mapping_validates_summary_declarations(self):
        bad = copy.deepcopy(M)
        bad["summaryOfConcept"] = [{"rule": "^X2$", "reason": "x"}]
        with self.assertRaises(MappingError):
            Mapping(bad)

    def test_without_a_located_plant_it_is_noise_as_before(self):
        r = score(key(mnf("T", "missing-cancellation-propagation", "src/Svc.cs", [10, 10])),
                  res("X2", None, None, SUMMARY))
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])

    def test_a_repository_level_trap_still_catches_it(self):
        r = score(key(mf("A", "missing-cancellation-propagation", "src/Svc.cs", [10, 10]),
                      mnf("T", "missing-cancellation-propagation")), res("X2", None, None, SUMMARY))
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])


class Configuration(unittest.TestCase):
    def test_cli_stamps_configuration(self):
        fx = os.path.join(ROOT, "tests", "fixtures")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "s.json")
            args = [sys.executable, "-m", "cai_bench", "score", "--key", os.path.join(fx, "answer-key.json"),
                    "--sarif", os.path.join(fx, "report.sarif"), "--mapping", os.path.join(fx, "mapping.json"),
                    "--json", out]
            subprocess.run(args, cwd=ROOT, check=True, capture_output=True)
            self.assertEqual(json.load(open(out))["configuration"], {"label": "default", "headline": True})
            p = subprocess.run(args + ["--configuration-label", "wcag-2.2 framework on"], cwd=ROOT, check=True,
                               capture_output=True, text=True)
            self.assertEqual(json.load(open(out))["configuration"], {"label": "wcag-2.2 framework on", "headline": False})
            self.assertIn("NOT the default configuration", p.stdout)


if __name__ == "__main__":
    unittest.main()
