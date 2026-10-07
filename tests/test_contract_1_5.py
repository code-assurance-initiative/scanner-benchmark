"""Contract 1.5: location equivalence — file-scope concepts (taxonomy `matchScope: "file"`) and clone-group sites read
out of a result's message (mapping `sitesFromMessage`)."""
import copy
import json
import os
import unittest

from cai_bench.keyfile import load_json
from cai_bench.mapping import Mapping, MappingError
from cai_bench.sarif import read_results
from cai_bench.scoring import render, score as score_report
from cai_bench.taxonomy import file_scope_concepts
from tests.helpers import MAPPING_DOC, clean, entry, key, mf, mnf, outcomes, res, sarif

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

M = copy.deepcopy(MAPPING_DOC)
M["concepts"].update({
    "god-class": {"rules": [{"rule": "^D3$", "messages": ["^ClassTooLong:"]}], "dimensions": ["D3"]},
    "duplicated-code": {"rules": ["^(?:D4|R10)$"], "dimensions": ["D4", "R10"]},
})
M["sitesFromMessage"] = [
    {"rule": "^D4$", "concepts": ["duplicated-code"], "within": r"^[^:]*\): (?P<sites>.*?)(?: — |$)",
     "patterns": [r"(?:^|\s\|\s)(?P<file>[^\s|]+):(?P<line>\d+)(?:-(?P<endLine>\d+))?(?=\s|$)"], "source": "test"},
    {"rule": "^R10$", "within": r"^[^:]*\): (?P<sites>.*?)(?: — |$)",
     "patterns": [r"(?:^|\s·\s)(?P<file>[^\s·]+):(?P<line>\d+)(?=\s|$)"], "source": "test"},
]

A, B, C = "src/Carriers/AlderAdapter.cs", "src/Carriers/CorvidAdapter.cs", "src/Carriers/Shared.cs"


def d4(first, first_lines, *others):
    sites = " | ".join([f"{first}:{first_lines[0]}-{first_lines[1]}"] + [f"{f}:{a}-{b}" for f, a, b in others])
    return (f"Duplicated block (16 lines × {1 + len(others)}): {sites} — extract the block; read the range at "
            f"`{first}:{first_lines[0]}` as the matched window.")


def score(k, *results, mapping=M, contract=None):
    return score_report(json.loads(json.dumps(k)), read_results(sarif(*results)), Mapping(mapping), None,
                        contract=contract)


GOD = "ClassTooLong: LabelService: ClassTooLong — 493 significant lines"


class Taxonomy(unittest.TestCase):
    def test_the_file_scope_concepts(self):
        self.assertEqual(file_scope_concepts(), frozenset({
            "god-class", "oversized-source-file", "low-class-cohesion", "fat-interface", "anemic-domain-model",
            "churn-complexity-hotspot", "knowledge-concentration", "knowledge-freshness", "change-coupling",
            "oversized-module", "unstable-dependency", "module-off-main-sequence"}))

    def test_taxonomy_json_carries_match_scope_only_as_file(self):
        tax = load_json(os.path.join(ROOT, "taxonomy.json"))
        scopes = {c.get("matchScope") for c in tax["concepts"]}
        self.assertEqual(scopes, {None, "file"})

    def test_a_bad_match_scope_is_refused(self):
        with self.assertRaises(ValueError):
            file_scope_concepts({"concepts": [{"id": "x", "matchScope": "line"}]})

    def test_an_explicit_taxonomy_decides(self):
        self.assertEqual(file_scope_concepts({"concepts": [{"id": "x", "matchScope": "file"}, {"id": "y"}]}),
                         frozenset({"x"}))


class FileScope(unittest.TestCase):
    K = key(mf("GOD", "god-class", "src/Labels/LabelService.cs", [40, 482]))

    def test_class_level_result_anywhere_in_the_file_is_a_hit(self):
        # the class header is at 40; a scanner reporting the file (line 1) or the class end is equally precise
        for line in (1, 12, 600):
            r = score(self.K, res("D3", "src/Labels/LabelService.cs", line, GOD))
            self.assertEqual(entry(r, "GOD")["outcome"], "TP", line)

    def test_under_contract_1_4_the_line_still_decides(self):
        r = score(self.K, res("D3", "src/Labels/LabelService.cs", 1, GOD), contract="1.4")
        self.assertEqual(entry(r, "GOD")["outcome"], "FN")
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])

    def test_a_second_result_in_the_file_is_redundant(self):
        r = score(self.K, res("D3", "src/Labels/LabelService.cs", 1, GOD), res("D3", "src/Labels/LabelService.cs", 600, GOD))
        self.assertEqual(outcomes(r), [(0, "tp", "GOD"), (1, "redundant", "GOD")])
        # a result ON the entry's lines is the stronger match: it takes the plant, the file-level one is redundant
        r = score(self.K, res("D3", "src/Labels/LabelService.cs", 1, GOD), res("D3", "src/Labels/LabelService.cs", 90, GOD))
        self.assertEqual(outcomes(r), [(0, "redundant", "GOD"), (1, "tp", "GOD")])

    def test_another_file_is_not_the_same_site(self):
        r = score(self.K, res("D3", "src/Labels/LabelPrinter.cs", 40, GOD))
        self.assertEqual(entry(r, "GOD")["outcome"], "FN")
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])

    def test_a_site_scoped_concept_keeps_the_line_rule(self):
        r = score(key(mf("LM", "long-method", "src/Labels/LabelService.cs", [40, 60])),
                  res("D1", "src/Labels/LabelService.cs", 1))
        self.assertEqual(entry(r, "LM")["outcome"], "FN")

    def test_symmetric_at_a_trap(self):
        r = score(key(mnf("T", "god-class", "src/Gen/Zones.g.cs", [5, 5])), res("D3", "src/Gen/Zones.g.cs", 300, GOD))
        self.assertEqual(entry(r, "T")["outcome"], "FP")
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])

    def test_a_clean_region_naming_the_concept_covers_its_file(self):
        r = score(key(clean("C", ["god-class"], "src/A.cs", [10, 20])), res("D3", "src/A.cs", 1, GOD))
        self.assertEqual(entry(r, "C")["outcome"], "FP")

    def test_a_wildcard_clean_region_keeps_its_lines(self):
        # "*" does not name the concept: a region certified clean of everything is still a region
        r = score(key(clean("C", "*", "src/A.cs", [10, 20]), mf("X", "sql-injection", "src/Z.cs", [1, 1])),
                  res("D3", "src/A.cs", 1, GOD))
        self.assertEqual(entry(r, "C")["outcome"], "TN")

    def test_located_entry_in_the_file_shields_it_from_a_repository_level_entry(self):
        k = key(mf("GOD", "god-class", "src/A.cs", [40, 400]), mnf("REPO", "god-class"))
        r = score(k, res("D3", "src/A.cs", 1, GOD), res("D3", "src/A.cs", 2, GOD))
        self.assertEqual(outcomes(r), [(0, "tp", "GOD"), (1, "redundant", "GOD")])
        self.assertEqual(entry(r, "REPO")["outcome"], "TN")

    def test_line_precise_match_is_preferred(self):
        # two classes of one file, both god classes: results in either order find both
        k = key(mf("G1", "god-class", "src/A.cs", [1, 100]), mf("G2", "god-class", "src/A.cs", [150, 300]))
        r = score(k, res("D3", "src/A.cs", 150, GOD), res("D3", "src/A.cs", 1, GOD))
        self.assertEqual(outcomes(r), [(0, "tp", "G2"), (1, "tp", "G1")])

    def test_per_dimension_rows_use_the_rule_too(self):
        r = score(self.K, res("D3", "src/Labels/LabelService.cs", 1, GOD))
        self.assertEqual(r["dimensions"]["D3"]["tp"], 1)
        r = score(self.K, res("D3", "src/Labels/LabelService.cs", 1, GOD), contract="1.4")
        self.assertEqual(r["dimensions"]["D3"]["tp"], 0)

    def test_report_states_the_rule(self):
        r = score(self.K, res("D3", "src/Labels/LabelService.cs", 1, GOD))
        self.assertEqual(r["summary"]["fileScopeMatches"], 1)
        self.assertEqual(r["results"][0]["matchScope"], "file")
        self.assertIn("file-scope", render(r))


class SitesFromMessage(unittest.TestCase):
    def test_mapping_parses_and_validates(self):
        m = Mapping(M)
        self.assertEqual(m.sites_in_message("D4", d4(A, (44, 51), (B, 53, 60)), ["duplicated-code"]),
                         [(A, 44, 51), (B, 53, 60)])
        self.assertEqual(m.sites_in_message("D4", d4(A, (44, 51), (B, 53, 60)), ["sql-injection"]), [])
        for bad in ({"rule": "^D4$"}, {"rule": "^D4$", "patterns": []}, {"rule": "^D4$", "patterns": [r"(?P<line>\d+)"]},
                    {"rule": "^D4$", "patterns": ["("]}, {"patterns": [r"(?P<file>\S+)"]},
                    {"rule": "^D4$", "patterns": [r"(?P<file>\S+)"], "within": r"x"},
                    {"rule": "^D4$", "patterns": [r"(?P<file>\S+)"], "concepts": []}):
            doc = copy.deepcopy(M)
            doc["sitesFromMessage"] = [bad]
            with self.assertRaises(MappingError, msg=bad):
                Mapping(doc)

    def test_the_backticked_detail_is_not_a_site(self):
        m = Mapping(M)
        self.assertEqual(m.sites_in_message("D4", d4(A, (44, 51), (B, 53, 60)) + f" `{C}:9`", ["duplicated-code"]),
                         [(A, 44, 51), (B, 53, 60)])

    def test_a_listed_member_finds_the_plant(self):
        r = score(key(mf("DUP", "duplicated-code", B, [53, 60])), res("D4", A, 44, d4(A, (44, 51), (B, 53, 60))))
        self.assertEqual(entry(r, "DUP")["outcome"], "TP")
        row = r["results"][0]
        self.assertEqual(row["locationSource"], "sitesFromMessage")
        self.assertEqual(row["site"], {"file": B, "line": 53, "endLine": 60})
        # its own location restated with the span the message states is a site too (the span is information)
        self.assertEqual(row["sites"], [{"file": A, "line": 44, "endLine": 51}, {"file": B, "line": 53, "endLine": 60}])
        self.assertEqual(r["summary"]["resultsWithMessageSites"], 1)
        self.assertEqual(r["summary"]["locationSources"]["sitesFromMessage"], 1)
        self.assertIn("sitesFromMessage", render(r))

    def test_a_stated_span_overlapping_the_plant_finds_it(self):
        # the row is located at the copy's first line (43), the key plants the copied lines 48-63: the SARIF line is
        # outside the tolerance, the span the message states (43-65) contains the plant
        k = key(mf("DUP", "duplicated-code", A, [48, 63]))
        r = score(k, res("D4", A, 43, d4(A, (43, 65), (B, 23, 45))))
        self.assertEqual(entry(r, "DUP")["outcome"], "TP")
        self.assertEqual(r["results"][0]["site"], {"file": A, "line": 43, "endLine": 65})
        self.assertEqual(entry(score(k, res("D4", A, 43, d4(A, (43, 65), (B, 23, 45))), contract="1.4"), "DUP")["outcome"],
                         "FN")
        r = score(key(mf("DUP", "duplicated-code", A, [70, 80])), res("D4", A, 43, d4(A, (43, 65), (B, 23, 45))))
        self.assertEqual(entry(r, "DUP")["outcome"], "FN")  # 65 + 3 < 70: no overlap
        r = score(key(clean("C", ["duplicated-code"], A, [66, 90])), res("D4", A, 43, d4(A, (43, 65), (B, 23, 45))))
        self.assertEqual(entry(r, "C")["outcome"], "TN")  # a clean region takes no tolerance
        r = score(key(clean("C", ["duplicated-code"], A, [65, 90])), res("D4", A, 43, d4(A, (43, 65), (B, 23, 45))))
        self.assertEqual(entry(r, "C")["outcome"], "FP")

    def test_a_restated_location_without_a_span_is_not_a_site(self):
        msg = f"Duplicated block (8 lines × 2 locations): {A}:24 · {B}:10 — x"
        r = score(key(mf("DUP", "duplicated-code", C, [1, 1])), res("R10", A, 24, msg))
        self.assertEqual(r["results"][0]["sites"], [{"file": B, "line": 10, "endLine": None}])

    def test_under_contract_1_4_it_does_not(self):
        r = score(key(mf("DUP", "duplicated-code", B, [53, 60])), res("D4", A, 44, d4(A, (44, 51), (B, 53, 60))),
                  contract="1.4")
        self.assertEqual(entry(r, "DUP")["outcome"], "FN")
        self.assertEqual(r["results"][0]["locationSource"], "sarif")

    def test_one_result_is_still_consumed_once(self):
        k = key(mf("DA", "duplicated-code", A, [44, 51]), mf("DB", "duplicated-code", B, [53, 60]))
        r = score(k, res("D4", A, 44, d4(A, (44, 51), (B, 53, 60))))
        self.assertEqual([entry(r, x)["outcome"] for x in ("DA", "DB")], ["TP", "FN"])
        self.assertEqual(r["results"][0]["locationSource"], "sarif")

    def test_the_reported_site_is_preferred_over_a_listed_one(self):
        k = key(mf("DA", "duplicated-code", A, [44, 51]), mf("DB", "duplicated-code", B, [53, 60]))
        r = score(k, res("D4", B, 53, d4(B, (53, 60), (A, 44, 51))), res("D4", A, 44, "Duplicated block (8 lines × 1): x"))
        self.assertEqual(outcomes(r), [(0, "tp", "DB"), (1, "tp", "DA")])

    def test_a_listed_member_on_a_trap_is_caught(self):
        r = score(key(mnf("T", "duplicated-code", C)), res("D4", A, 44, d4(A, (44, 51), (C, 1, 8))))
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])

    def test_a_listed_member_of_an_already_found_plant_is_redundant(self):
        k = key(mf("DB", "duplicated-code", B, [53, 60]))
        r = score(k, res("D4", B, 53, "Duplicated block (8 lines × 1): x"), res("D4", A, 44, d4(A, (44, 51), (B, 53, 60))))
        self.assertEqual(outcomes(r), [(0, "tp", "DB"), (1, "redundant", "DB")])

    def test_file_level_recall_sees_listed_members(self):
        r = score(key(mf("DUP", "duplicated-code", B, [200, 210])), res("D4", A, 44, d4(A, (44, 51), (B, 53, 60))))
        self.assertEqual(entry(r, "DUP")["outcome"], "FN")
        self.assertTrue(entry(r, "DUP")["fileLevel"])

    def test_r10_dot_separated_sites_and_the_unlisted_tail(self):
        msg = (f"Duplicated block (8 lines × 5 locations): {A}:24 · {A}:45 · {B}:10 · {C}:28 · +1 more site(s) not "
               f"listed — the 3 copies sit in sibling files")
        self.assertEqual(Mapping(M).sites_in_message("R10", msg, ["duplicated-code"]),
                         [(A, 24, None), (A, 45, None), (B, 10, None), (C, 28, None)])
        r = score(key(mf("DUP", "duplicated-code", C, [27, 30])), res("R10", A, 24, msg))
        self.assertEqual(entry(r, "DUP")["outcome"], "TP")

    def test_a_result_without_a_listed_site_is_unchanged(self):
        r = score(key(mf("DUP", "duplicated-code", B, [53, 60])), res("D4", A, 44, "Duplicated block (8 lines × 2): odd"))
        self.assertEqual(entry(r, "DUP")["outcome"], "FN")
        self.assertNotIn("sites", r["results"][0])


class WatchdogMapping(unittest.TestCase):
    """The real mapping on message shapes verbatim from local Watchdog scans (_scans/**/report.sarif)."""
    W = Mapping(load_json(os.path.join(ROOT, "mappings", "watchdog.json")))

    def test_d4(self):
        msg = ("Duplicated block (24–25 lines × 2): src/Shipping.Rates.Core/Carriers/AlderParcelAdapter.cs:45-68 | "
               "src/Shipping.Rates.Core/Carriers/CorvidCourierAdapter.cs:41-65 — the copies sit in sibling files of one "
               "directory, so a shared home is within easy reach: … at `src/Shipping.Rates.Core/Carriers/"
               "AlderParcelAdapter.cs:45` it does not close everything it opens")
        self.assertEqual(self.W.sites_in_message("D4", msg, ["duplicated-code"]),
                         [("src/Shipping.Rates.Core/Carriers/AlderParcelAdapter.cs", 45, 68),
                          ("src/Shipping.Rates.Core/Carriers/CorvidCourierAdapter.cs", 41, 65)])
        msg = ("Edited copy of a member (13 corresponding lines): src/ReportDesk.Api/Feeds/FeedAddressPolicy.cs:13-39 | "
               "src/ReportDesk.Api/Webhooks/CallbackAddressPolicy.cs:13-39 — These two members are one piece of code")
        self.assertEqual(len(self.W.sites_in_message("D4", msg, ["duplicated-code"])), 2)

    def test_r10(self):
        msg = ("Duplicated block (11 lines × 4 locations): src/billing/features/record-payment/record-payment.ts:26 · "
               "src/membership/features/cancel-membership/cancel-membership.ts:35 · src/membership/features/erase-member/"
               "erase-member.ts:29 · src/membership/features/export-member-data/export-member-data.ts:53 — the 4 copies")
        self.assertEqual([s[1] for s in self.W.sites_in_message("R10", msg, ["duplicated-code"])], [26, 35, 29, 53])
        msg = ("Duplicated block with local edits (5 matched lines × 2 locations): src/reports/report-routes.ts:51 · "
               "src/subscriptions/subscription-routes.ts:63 — the two spans are one implementation")
        self.assertEqual(self.W.sites_in_message("R10", msg, ["duplicated-code"]),
                         [("src/reports/report-routes.ts", 51, None), ("src/subscriptions/subscription-routes.ts", 63, None)])
        # the concentration row names directories, not sites
        msg = ("Duplication concentrated across 8 sibling directories (5 clone groups): 5 duplicated blocks under src/ "
               "have copies in at least two of the sibling directories conversion, feeds, imports (+2 more sibling(s) "
               "not listed) — 2 of them are reported below")
        self.assertEqual(self.W.sites_in_message("R10", msg, ["duplicated-code"]), [])

    def test_x10_lists_files(self):
        msg = ("Duplicated predicate: `member.status !== 'active' || member.membershipEndsOn.getTime() < today.getTime()` "
               "appears character-identically in 2 files — src/membership/features/book-class/book-class.ts, "
               "src/membership/features/send-class-reminders/send-class-reminders.ts. It is one line, so the duplication "
               "detector's token window never sees it")
        self.assertEqual(self.W.sites_in_message("X10", msg, ["duplicated-code"]),
                         [("src/membership/features/book-class/book-class.ts", None, None),
                          ("src/membership/features/send-class-reminders/send-class-reminders.ts", None, None)])

    def test_only_duplication(self):
        self.assertEqual(self.W.sites_in_message("D3", "ClassTooLong: a.cs:1 | b.cs:2 — x", ["god-class"]), [])


if __name__ == "__main__":
    unittest.main()
