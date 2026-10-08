"""Pins the contract 1.7 mapping pass of mappings/watchdog.json against message shapes taken verbatim (truncated) from
the local Watchdog scans: every title lands on the concept it denotes or on none, rows that are about several files
list them, and the part of a message that states its subject is the one subjects are searched in."""
import os
import unittest

from cai_bench.keyfile import load_json
from cai_bench.mapping import Mapping

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = load_json(os.path.join(ROOT, "mappings", "watchdog.json"))
M = Mapping(DOC)

CONCEPTS = [
    # a dereference through a value whose presence nothing guarantees
    ("D29", "Medium: watchdog-unchecked-catch-binding-deref-ts: This `if`/`while`/ternary asks whether something is "
            "present on the caught error, and the question ITSELF dereferences two levels", ["null-dereference"]),
    ("D29", "Medium: unchecked-map-lookup-deref-go: This map is indexed with a name", ["null-dereference"]),
    ("D29", "Medium: watchdog-discarded-close-error-go: the close error is dropped", []),
    # release versioning
    ("D36", "Packaging script can name the release artifact with an empty version: 1 packaging script(s) name the "
            "artifact they produce after a value parsed out of another file", ["release-hygiene"]),
    ("D36", "Release publish has no approval gate: 1 workflow(s) publish a package to a registry", []),
    ("D36", "npm publish authenticates with a long-lived registry token: 1 publishing job(s) upload", []),
    # a floating declaration is not an unlocked build; a missing lockfile still is
    ("D12", "Floating npm dependency: @kestrelford/kernel: `@kestrelford/kernel` is declared as `*` in apps/api/package"
            ".json, which names no releasable version", []),
    ("D12", "No dependency lockfile committed (npm): the build resolves afresh", ["dependencies-not-locked"]),
    # measurement disclosures are no defect of the dimension's concept
    ("D11", "Test reliability not measured — JavaScript/TypeScript suite install refused the lockfile: Test reliability "
            "NOT MEASURED", []),
    ("D11", "Test suite cannot be installed from its own lockfile: the repository root: The vitest suite in the "
            "repository root was never exercised", []),
    ("D11", "Flaky test: the repository roottests/import/csv-round-trip.test.ts::CSV bank round trip imports a numeric "
            "question: Passed 2×, failed 1× across repeated runs.", ["flaky-test"]),
    ("D11", "Test declared unreliable: RetryingTests.Polls: marked [Retry(3)]", ["flaky-test"]),
    ("D8", "Coverage not measured — no coverage collector is wired up: Coverage NOT MEASURED", []),
    ("D8", "Coverage not measured — JavaScript/TypeScript suite: Coverage NOT MEASURED", []),
    ("D8", "Low coverage: src/Billing/Invoice.cs: 12% line coverage", ["test-coverage"]),
    ("D8", "No test project references Hollinsfield.Dispensing.Api: no test project references it", ["test-coverage"]),
    ("D30", "Scanner failed to run — not a clean result: osv-scanner exited 2", []),
    ("D30", "High CVE: Newtonsoft.Json 12.0.3: Newtonsoft.Json 12.0.3 (direct) has a High advisory.",
     ["vulnerable-dependency"]),
    ("D43", "Scanner failed to run — not a clean result: osv-scanner exited 2", []),
    # AC4's composite title is a missing ARIA state
    ("AC4", 'Composite <ul role="listbox"> never reports its active option: This role="listbox" is the tab stop',
     ["invalid-aria-usage"]),
    ("AC4", "Positive tabindex (3): A positive tabindex reorders keyboard focus", ["non-keyboard-accessible-interaction"]),
]


class Concepts(unittest.TestCase):
    def test_each_title_lands_on_its_concept_or_none(self):
        for rule, msg, want in CONCEPTS:
            with self.subTest(rule=rule, msg=msg[:50]):
                self.assertEqual(sorted(M.concepts_of(rule, msg, {})), want)

    def test_dimensions_added_for_findings_keep_their_score(self):
        self.assertEqual(M.score_dimensions_of_concept("invalid-aria-usage"), ["AC5"])
        self.assertEqual(M.score_dimensions_of_concept("null-dereference"), ["X5"])
        self.assertEqual(M.score_dimensions_of_concept("release-hygiene"), ["P6"])

    def test_one_defect_at_two_granularities_is_a_family(self):
        self.assertEqual(M.family_of("container-confinement-profile-unset"), "syscall-confinement")
        self.assertEqual(M.family_of("workload-syscall-confinement"), "syscall-confinement")
        self.assertIsNone(M.family_of("container-excessive-privilege"))
        self.assertEqual(M.concepts_of("D31", 'Medium IaC: KSV-0104: Seccomp policies disabled. container "api"', {}),
                         ["container-confinement-profile-unset"])

    def test_summaries_of_the_other_languages(self):
        self.assertTrue(M.summary_of("X2", "Not all async functions that make a request accept an AbortSignal: 3 of 9"))
        self.assertTrue(M.summary_of("X5", "Strict null checking is not enabled everywhere the repository type-checks: 2"))
        self.assertTrue(M.summary_of("X5", "Null assertions (`!`) reduce the strict null checking score: 14 `!`"))
        self.assertIsNone(M.summary_of("X5", "Symbol treated as nullable, then dereferenced unguarded: x"))


class Sites(unittest.TestCase):
    def test_an_import_cycle_lists_its_members(self):
        msg = ("Import cycle (3 files): apps/web/src/app/api-client.ts → apps/web/src/app/session.ts → "
               "apps/web/src/app/store.ts → apps/web/src/app/api-client.ts (one verified cycle inside a "
               "mutually-dependent group of 5 files)")
        self.assertEqual([f for f, _, _ in M.sites_in_message("R9", msg, ["module-dependency-cycle"])],
                         ["apps/web/src/app/api-client.ts", "apps/web/src/app/session.ts", "apps/web/src/app/store.ts"])

    def test_the_files_an_off_boarding_row_names(self):
        msg = ("Off-boarding risk: anonymized user #1: If anonymized user #1 becomes unavailable, 2 significant file(s) "
               "lose their only recent owner: src/A/Policy.cs, src/A/Rules.cs (+3 more). Pair on, review, or document "
               "these before any departure.")
        self.assertEqual(M.sites_in_message("D16", msg, ["knowledge-concentration"]),
                         [("src/A/Policy.cs", None, None), ("src/A/Rules.cs", None, None)])
        self.assertEqual(M.sites_in_message("D16", "Further sole-owners (lower concentration): 1 other contributor(s) "
                                                   "are each the sole owner", ["knowledge-concentration"]), [])

    def test_the_files_an_orphan_fold_names(self):
        msg = ("Orphaned files with no living knowledge: 2 of 12 analysed file(s) have no living knowledge left … rather "
               "than raising one each — most significant first: src/D/RecurrenceRule.cs, src/D/Expander.cs. Attach the "
               "read to the next change")
        self.assertEqual([f for f, _, _ in M.sites_in_message("D34", msg, ["knowledge-freshness"])],
                         ["src/D/RecurrenceRule.cs", "src/D/Expander.cs"])

    def test_both_files_of_a_coupled_pair(self):
        msg = ("Boundary-crossing change coupling: WithholdingRules.cs ↔ SprayRecordExport.cs: "
               "`src/V.Domain/Spray/WithholdingRules.cs` (context V) and `src/V.Worker/Export/SprayRecordExport.cs` "
               "(context V.Worker) sit in DIFFERENT parts of the tree")
        self.assertEqual([f for f, _, _ in M.sites_in_message("D35", msg, ["change-coupling"])],
                         ["src/V.Domain/Spray/WithholdingRules.cs", "src/V.Worker/Export/SprayRecordExport.cs"])

    def test_the_post_merge_row_is_located_at_its_workflow(self):
        msg = ("Test suite runs only after the merge: `ci.yml` run(s) the test suite, but no workflow that runs tests is "
               "triggered by a pull request")
        self.assertEqual(M.location_in_message("P12", msg), ("ci.yml", None))
        self.assertIsNone(M.location_in_message("P12", "Coverage collected but not gated: CI collects a coverage report"))


class Subjects(unittest.TestCase):
    def test_the_subject_each_format_states(self):
        cases = [
            ("D30", "Medium CVE: GHSA-hp3w-g68c-fv3c: sprintf-js 1.0.3: GHSA-hp3w-g68c-fv3c — no fixed version has "
                    "been published yet. Track the advisory; sprintf-js is not declared in this repo's manifests: it is "
                    "pulled in transitively by argparse 1.0.10", "sprintf-js"),
            ("D30", "High CVE: SixLabors.ImageSharp 1.0.4: SixLabors.ImageSharp 1.0.4 (transitive) has a High advisory",
             "SixLabors.ImageSharp"),
            ("D12", "Deprecated: Microsoft.Azure.ServiceBus: Microsoft.Azure.ServiceBus 5.2.0 — Legacy — the "
                    "publisher's replacement is `Azure.Messaging.ServiceBus`", "Microsoft.Azure.ServiceBus"),
            ("D12", "Prerelease dependency: StyleCop.Analyzers: StyleCop.Analyzers resolves to 1.2.0-beta.556",
             "StyleCop.Analyzers"),
            ("D11", "Flaky test: FleetOps.Application.Tests::FleetOps.Application.Tests.Infrastructure.ReadSideTests."
                    "FleetOps.Application.Tests.Infrastructure.ReadSideTests.FleetAndInspectionReports: Passed 2×, "
                    "failed 1× across repeated runs.",
             "FleetOps.Application.Tests.Infrastructure.ReadSideTests.FleetAndInspectionReports"),
            ("D11", "Flaky test: the repository roottests/import/opentdb-reader.test.ts::readOpenTdbPack parses a live "
                    "five-question pack: Passed 2×, failed 1× across repeated runs.",
             "tests/import/opentdb-reader.test.ts::readOpenTdbPack parses a live five-question pack"),
        ]
        for rule, msg, want in cases:
            with self.subTest(rule=rule, want=want):
                self.assertEqual(M.subject_text(rule, msg), want)

    def test_every_declaration_has_a_source(self):
        self.assertTrue(DOC["subjectFromMessage"])
        self.assertTrue(all(x.get("source") for x in DOC["subjectFromMessage"]))


if __name__ == "__main__":
    unittest.main()
