"""Contract 1.3: a location taken from the message (mapping `locationFromMessage`) for results without a SARIF
location, the secondary file-level recall diagnostic, and umbrella concepts (mapping `parent`)."""
import copy
import unittest

from cai_bench.mapping import Mapping, MappingError
from cai_bench.scoring import render
from tests.helpers import MAPPING_DOC, clean, entry, key, mf, mnf, outcomes, res, run

WF = ".github/workflows/release.yml"
DEPLOY = ".github/workflows/deploy.yml"
DS = "deploy/k8s/node-agent/daemonset.yaml"

# Shapes of real Watchdog D36 rows (bench-csharp-security-iac iter2): no SARIF location, the site in the message.
GRANT = ("Workflow token grant is wider than its jobs use: 1 `permissions:` grant(s) are wider than the jobs that hold "
         "them use (release.yml:7 (write-all; held by images)). `write-all` grants every scope GitHub defines")
ARGV = ("Secret passed as a command-line argument: 2 CI command(s) pass a credential in the command line: "
        ".github/workflows/deploy.yml: kubectl --server \"$KUBE_SERVER\" --token \"${{ secrets.KUBE_DEPLOY_TOKEN }}\" "
        "apply; .github/workflows/deploy.yml: kubectl rollout status. Pass the credential through the environment")
ENVS = ("Secret exported as workflow-level env: 2 workflow-level `env:` entries interpolate a secret "
        "(build.yml:31 (SCW_NAMESPACE); ci.yml:16 (TURBO_TOKEN)), which places the credential in every step")

LOC = copy.deepcopy(MAPPING_DOC)
LOC["concepts"].update({
    "ci-token-excessive-permissions": {"rules": [{"rule": "^D36$", "messages": ["^Workflow token grant "]}],
                                       "dimensions": ["D36"]},
    "secret-in-process-arguments": {"rules": [{"rule": "^D36$", "messages": ["^Secret passed as "]}],
                                    "dimensions": ["D36"]},
    "ci-secret-exposure": {"rules": [{"rule": "^D36$", "messages": ["^Secret exported as "]}], "dimensions": ["D36"]},
})
LOC["locationFromMessage"] = [
    {"rule": "^D36$", "message": "^Secret passed as a command-line argument:",
     "pattern": r": (?P<file>[\w./-]+\.ya?ml): ", "source": "argv sites name the file, no line"},
    {"rule": "^D36$", "pattern": r"(?<![\w./-])(?P<file>[\w.-]+\.ya?ml):(?P<line>\d+)\b",
     "source": "first basename:line the row names"},
]


def score(k, *results, mapping=LOC):
    return run(k, *results, mapping=mapping)


class LocationFromMessage(unittest.TestCase):
    def test_location_less_row_is_located_by_the_site_its_message_names(self):
        r = score(key(mf("TOK", "ci-token-excessive-permissions", WF, [7, 7])), res("D36", None, None, GRANT))
        self.assertEqual(outcomes(r), [(0, "tp", "TOK")])
        row = r["results"][0]
        self.assertEqual((row["file"], row["line"], row["locationSource"]), ("release.yml", 7, "message"))
        self.assertEqual(r["summary"]["locationSources"], {"sarif": 0, "message": 1, "none": 0})

    def test_without_the_mapping_entry_the_same_row_stays_location_less(self):
        doc = copy.deepcopy(LOC)
        del doc["locationFromMessage"]
        r = score(key(mf("TOK", "ci-token-excessive-permissions", WF, [7, 7])), res("D36", None, None, GRANT),
                  mapping=doc)
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])
        self.assertEqual(r["results"][0]["locationSource"], "none")
        self.assertEqual(r["summary"]["locationSources"], {"sarif": 0, "message": 0, "none": 1})

    def test_a_sarif_location_is_never_replaced(self):
        # a scanner that DID locate the row (here at line 1) keeps its location: the message is not a second chance
        r = score(key(mf("TOK", "ci-token-excessive-permissions", WF, [7, 7])), res("D36", WF, 1, GRANT))
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])
        self.assertEqual(r["results"][0]["locationSource"], "sarif")

    def test_the_wrong_line_in_the_message_is_still_wrong(self):
        r = score(key(mf("TOK", "ci-token-excessive-permissions", WF, [20, 20])), res("D36", None, None, GRANT))
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])

    def test_a_message_location_can_be_caught_in_a_trap(self):
        r = score(key(mnf("TRP", "ci-token-excessive-permissions", WF, [6, 8])), res("D36", None, None, GRANT))
        self.assertEqual(outcomes(r), [(0, "trap-fp", "TRP")])

    def test_first_site_named_is_the_location(self):
        r = score(key(mf("ENV", "ci-secret-exposure", ".github/workflows/ci.yml", [16, 16])),
                  res("D36", None, None, ENVS))
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])
        self.assertEqual((r["results"][0]["file"], r["results"][0]["line"]), ("build.yml", 31))

    def test_a_pattern_without_line_gives_a_file_level_location(self):
        lined = key(mf("ARGV", "secret-in-process-arguments", DEPLOY, [33, 34]))
        whole = key(mf("ARGV", "secret-in-process-arguments", DEPLOY))
        self.assertEqual(outcomes(score(lined, res("D36", None, None, ARGV))), [(0, "unmatched-fp", None)])
        r = score(whole, res("D36", None, None, ARGV))
        self.assertEqual(outcomes(r), [(0, "tp", "ARGV")])
        self.assertEqual((r["results"][0]["file"], r["results"][0]["line"]), (DEPLOY, None))

    def test_other_rules_are_not_relocated(self):
        r = score(key(mf("SQL", "sql-injection", "src/A.cs", [7, 7])), res("D14", None, None, "see release.yml:7"))
        self.assertEqual(r["results"][0]["locationSource"], "none")

    def test_mapping_validation(self):
        for bad in ({"rule": "^D36$"}, {"rule": "^D36$", "pattern": r"(?P<line>\d+)"},
                    {"pattern": r"(?P<file>\S+):(?P<line>\d+)"}, {"rule": "^D36$", "pattern": "(?P<file>"}):
            doc = copy.deepcopy(LOC)
            doc["locationFromMessage"] = [bad]
            with self.subTest(bad=bad):
                with self.assertRaises(MappingError):
                    Mapping(doc)

    def test_render_reports_message_locations(self):
        r = score(key(mf("TOK", "ci-token-excessive-permissions", WF, [7, 7])), res("D36", None, None, GRANT))
        self.assertIn("1 result(s) located from the message", render(r))


class FileLevelRecall(unittest.TestCase):
    K = key(mf("HOST", "sql-injection", DS, [71, 74]), mf("OTHER", "sql-injection", "src/B.cs", [5, 5]),
            mf("REPO", "weak-hash"))

    def test_a_result_elsewhere_in_the_file_is_file_level_but_still_fn(self):
        r = run(self.K, res("D14", DS, 1))
        self.assertEqual(entry(r, "HOST")["outcome"], "FN")
        self.assertTrue(entry(r, "HOST")["fileLevel"])
        self.assertFalse(entry(r, "OTHER")["fileLevel"])
        s = r["summary"]
        self.assertEqual((s["tp"], s["fn"], s["fileLevelTp"]), (0, 3, 1))
        self.assertEqual(s["recall"], 0.0)
        self.assertAlmostEqual(s["fileLevelRecall"], 1 / 3)
        self.assertAlmostEqual(r["concepts"]["sql-injection"]["fileLevelRecall"], 0.5)
        self.assertAlmostEqual(r["dimensions"]["D14"]["fileLevelRecall"], 0.5)

    def test_a_tp_is_file_level(self):
        r = run(self.K, res("D14", DS, 72))
        self.assertEqual(entry(r, "HOST")["outcome"], "TP")
        self.assertEqual(r["summary"]["fileLevelTp"], 1)

    def test_another_concept_in_the_file_does_not_count(self):
        r = run(self.K, res("D20", DS, 72))
        self.assertFalse(entry(r, "HOST")["fileLevel"])
        self.assertEqual(entry(r, "REPO")["outcome"], "TP")           # the weak-hash row is the repository-level hit
        self.assertEqual(r["summary"]["fileLevelTp"], 1)
        self.assertEqual(r["concepts"]["sql-injection"]["fileLevelTp"], 0)

    def test_repository_level_entry_is_file_level_only_when_found(self):
        self.assertFalse(entry(run(self.K), "REPO")["fileLevel"])
        self.assertTrue(entry(run(self.K, res("D20")), "REPO")["fileLevel"])

    def test_zero_denominator_is_none(self):
        r = run(key(mnf("T", "sql-injection", DS, [3, 3])))
        self.assertIsNone(r["summary"]["fileLevelRecall"])

    def test_rendered_as_a_labelled_secondary_column(self):
        text = render(run(self.K, res("D14", DS, 1)))
        self.assertIn("fileRec*", text)
        self.assertIn("file-level recall", text)
        self.assertIn("SECONDARY", text)


UMB = copy.deepcopy(MAPPING_DOC)
UMB["concepts"].update({
    "container-excessive-privilege": {"rules": [{"rule": "^D31$", "messages": ["^\\w+ IaC: KSV-0024:"]}],
                                      "dimensions": ["D31"]},
    "privileged-container": {"rules": [{"rule": "^D31$", "messages": ["^\\w+ IaC: KSV-0017:"]}],
                             "dimensions": ["D31"], "parent": "container-excessive-privilege"},
    "host-namespace-sharing": {"rules": [{"rule": "^D31$", "messages": ["^\\w+ IaC: KSV-0009:"]}],
                               "dimensions": ["D31"], "parent": "container-excessive-privilege"},
})
PRIV = "High IaC: KSV-0017: Privileged. Container 'fluent-bit' should set 'securityContext.privileged' to false."
HOSTNET = "High IaC: KSV-0009: Access to host network."
HOSTPORT = "Medium IaC: KSV-0024: Access to host ports."


class UmbrellaConcepts(unittest.TestCase):
    def test_an_umbrella_entry_matches_its_childrens_results_exactly(self):
        r = run(key(mf("P", "container-excessive-privilege", DS, [29, 33])), res("D31", DS, 29, PRIV), mapping=UMB)
        self.assertEqual(outcomes(r), [(0, "tp", "P")])
        self.assertEqual(r["results"][0]["concepts"], ["privileged-container"])   # the result keeps ONE concept

    def test_a_precise_entry_does_not_take_a_sibling_or_the_umbrella_residue(self):
        k = key(mf("P", "privileged-container", DS, [29, 33]))
        self.assertEqual(outcomes(run(k, res("D31", DS, 30, HOSTNET), mapping=UMB)), [(0, "uncovered", None)])
        self.assertEqual(outcomes(run(k, res("D31", DS, 30, HOSTPORT), mapping=UMB)), [(0, "uncovered", None)])
        self.assertEqual(outcomes(run(k, res("D31", DS, 30, PRIV), mapping=UMB)), [(0, "tp", "P")])

    def test_umbrella_trap_and_clean_catch_children(self):
        r = run(key(mnf("T", "container-excessive-privilege", DS, [9, 9]),
                    clean("C", ["container-excessive-privilege"], "deploy/k8s/api/deployment.yaml")),
                res("D31", DS, 9, HOSTNET), res("D31", "deploy/k8s/api/deployment.yaml", 3, PRIV), mapping=UMB)
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T"), (1, "clean-fp", "C")])

    def test_child_results_off_every_entry_are_noise_for_an_umbrella_key(self):
        r = run(key(mf("P", "container-excessive-privilege", DS, [29, 33])), res("D31", DS, 1, HOSTNET), mapping=UMB)
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])
        self.assertEqual(r["results"][0]["attributedConcept"], "container-excessive-privilege")

    def test_mapping_validation(self):
        for parent in ("no-such-concept", "privileged-container"):
            doc = copy.deepcopy(UMB)
            doc["concepts"]["privileged-container"]["parent"] = parent
            with self.subTest(parent=parent):
                with self.assertRaises(MappingError):
                    Mapping(doc)
        doc = copy.deepcopy(UMB)
        doc["concepts"]["container-excessive-privilege"]["parent"] = "host-namespace-sharing"
        doc["concepts"]["host-namespace-sharing"]["parent"] = "container-excessive-privilege"
        with self.assertRaises(MappingError):
            Mapping(doc)

    def test_ancestors(self):
        m = Mapping(UMB)
        self.assertEqual(m.ancestors("privileged-container"), ["container-excessive-privilege"])
        self.assertEqual(m.ancestors("container-excessive-privilege"), [])


if __name__ == "__main__":
    unittest.main()
