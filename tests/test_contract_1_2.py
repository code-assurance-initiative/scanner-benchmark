"""Contract 1.2: entries with a `subject` (package id / framework moniker) that match location-less dependency results
by a whole-token occurrence in the message, and the mapping's per-concept `scoreDimensions` for score-band lookup."""
import copy
import json
import unittest

from cai_bench.keyfile import validate_key
from cai_bench.mapping import Mapping, MappingError
from cai_bench.scoring import is_manifest, subject_in
from tests.helpers import MAPPING_DOC, TAXONOMY, band, clean, entry, key, mf, mnf, outcomes, res, run

PROPS = "Directory.Packages.props"

# Shapes of real Watchdog dependency rows (bench-csharp-security-dependencies iter2): no location, package in message.
DEPS = copy.deepcopy(MAPPING_DOC)
DEPS["concepts"].update({
    "vulnerable-dependency": {"rules": ["^D12$", "^D30$"], "messages": ["^Vulnerable: ", "^\\w+ CVE: "],
                              "dimensions": ["D12", "D30"]},
    "deprecated-dependency": {"rules": ["^D12$"], "messages": ["^Deprecated: "], "dimensions": ["D12"]},
    "license-policy-violation": {"rules": ["^D44$"], "dimensions": ["D44"]},
    "end-of-life-platform": {"rules": ["^D45$"], "dimensions": ["D45"]},
})
NJ12 = "Vulnerable: Newtonsoft.Json: Newtonsoft.Json 12.0.3 — High severity. https://github.com/advisories/GHSA-5crp"
NJ12_D30 = "High CVE: Newtonsoft.Json 12.0.3: Newtonsoft.Json 12.0.3 (direct) has a High advisory"
ZIP = "Vulnerable: SharpZipLib: SharpZipLib 1.3.2 — High severity."
BSON = "Vulnerable: Newtonsoft.Json.Bson: Newtonsoft.Json.Bson 1.0.1 — Moderate severity."
GPL = "Banned license: MySql.Data: `MySql.Data` 26.7.0 resolves to SPDX id GPL-2.0-only WITH Universal-FOSS-exception"
LGPL = "Banned license: iTextSharp.LGPLv2.Core: `iTextSharp.LGPLv2.Core` 3.8.6 resolves to SPDX id LGPL-2.0-only"


def score(k, *results, mapping=DEPS, scores=None):
    return run(k, *results, mapping=mapping, scores=scores)


class Tokens(unittest.TestCase):
    def test_whole_token_case_insensitive(self):
        self.assertTrue(subject_in("Newtonsoft.Json", NJ12))
        self.assertTrue(subject_in("newtonsoft.json", NJ12))
        self.assertTrue(subject_in("Newtonsoft.Json", "pinned at Newtonsoft.Json@12.0.3"))
        self.assertTrue(subject_in("Newtonsoft.Json", "(Newtonsoft.Json)"))
        self.assertTrue(subject_in("Newtonsoft.Json", "upgrade Newtonsoft.Json."))
        self.assertTrue(subject_in("net6.0", "End-of-life runtime: .NET net6.0: tools/X.csproj declares"))

    def test_a_longer_package_id_is_another_package(self):
        self.assertFalse(subject_in("Newtonsoft.Json", BSON))
        self.assertFalse(subject_in("Json", NJ12))          # a segment of a dotted id is not the id
        self.assertFalse(subject_in("core", "@angular/core 17.0.0"))

    def test_spdx_ids_do_not_match_inside_each_other(self):
        self.assertFalse(subject_in("GPL-2.0", "resolves to SPDX id LGPL-2.0"))
        self.assertFalse(subject_in("GPL-2.0", "resolves to SPDX id GPL-2.0-only"))
        self.assertTrue(subject_in("GPL-2.0", "resolves to SPDX id GPL-2.0, which is banned"))
        self.assertTrue(subject_in("LGPL-2.0", "resolves to SPDX id LGPL-2.0"))

    def test_manifests(self):
        for p in (PROPS, "src/A/A.csproj", "src/A/packages.lock.json", "web/package-lock.json", "requirements-dev.txt",
                  "global.json"):
            self.assertTrue(is_manifest(p), p)
        for p in ("src/A/Program.cs", "Dockerfile", ".editorconfig", None):
            self.assertFalse(is_manifest(p), p)


class SubjectMatching(unittest.TestCase):
    K = key(mf("NJ", "vulnerable-dependency", PROPS, [16, 16], subject="Newtonsoft.Json"),
            mf("ZIP", "vulnerable-dependency", PROPS, [28, 28], subject="SharpZipLib"), schemaVersion="1.2")

    def test_location_less_result_naming_the_subject_is_a_hit(self):
        r = score(self.K, res("D12", None, None, NJ12), res("D12", None, None, ZIP))
        self.assertEqual(outcomes(r), [(0, "tp", "NJ"), (1, "tp", "ZIP")])
        self.assertEqual(r["summary"]["recall"], 1.0)

    def test_without_subject_the_same_result_is_noise_as_in_1_1(self):
        k = key(mf("NJ", "vulnerable-dependency", PROPS, [16, 16]))
        self.assertEqual(outcomes(score(k, res("D12", None, None, NJ12))), [(0, "unmatched-fp", None)])

    def test_one_to_one_then_redundant(self):
        r = score(self.K, res("D12", None, None, NJ12), res("D30", None, None, NJ12_D30))
        self.assertEqual(outcomes(r), [(0, "tp", "NJ"), (1, "redundant", "NJ")])
        self.assertEqual((r["summary"]["noise"], r["summary"]["redundant"]), (0, 1))

    def test_token_boundary_in_matching(self):
        r = score(self.K, res("D12", None, None, BSON))
        self.assertEqual(entry(r, "NJ")["outcome"], "FN")
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])

    def test_concept_must_still_match(self):
        dep = "Deprecated: Newtonsoft.Json: Newtonsoft.Json 12.0.3 — Legacy"
        r = score(self.K, res("D12", None, None, dep))
        self.assertEqual(entry(r, "NJ")["outcome"], "FN")

    def test_manifest_location_matches_by_subject_at_any_line(self):
        r = score(self.K, res("D12", "src/Api/Api.csproj", 1, NJ12))
        self.assertEqual(outcomes(r), [(0, "tp", "NJ")])

    def test_source_file_location_does_not_match_by_subject(self):
        r = score(self.K, res("D12", "src/Api/WebhookController.cs", 40, NJ12))
        self.assertEqual(entry(r, "NJ")["outcome"], "FN")

    def test_site_match_still_works_and_is_preferred(self):
        # the located row on ZIP's line belongs to ZIP even though it also names Newtonsoft.Json
        r = score(self.K, res("D12", PROPS, 28, "Vulnerable: SharpZipLib (pulled next to Newtonsoft.Json)"),
                  res("D12", None, None, NJ12))
        self.assertEqual(outcomes(r), [(0, "tp", "ZIP"), (1, "tp", "NJ")])

    def test_subject_on_a_trap_catches_the_scanner(self):
        k = key(mnf("T", "license-policy-violation", PROPS, [27, 27], subject="iTextSharp.LGPLv2.Core"),
                mf("P", "license-policy-violation", PROPS, [23, 23], subject="MySql.Data"))
        r = score(k, res("D44", None, None, GPL), res("D44", None, None, LGPL))
        self.assertEqual(outcomes(r), [(0, "tp", "P"), (1, "trap-fp", "T")])
        self.assertEqual(r["summary"]["trapResistance"], 0.0)

    def test_subject_on_a_clean_entry(self):
        k = key(clean("C", ["vulnerable-dependency"], "src/Api/packages.lock.json", subject="Serilog"))
        r = score(k, res("D12", None, None, "Vulnerable: Serilog: Serilog 2.0.0 — Low severity."))
        self.assertEqual(outcomes(r), [(0, "clean-fp", "C")])

    def test_repository_level_entry_does_not_steal_a_subject_result(self):
        k = key(mf("NJ", "vulnerable-dependency", PROPS, [16, 16], subject="Newtonsoft.Json"),
                mf("ANY", "vulnerable-dependency"))
        r = score(k, res("D12", None, None, NJ12), res("D12", None, None, ZIP))
        self.assertEqual(outcomes(r), [(0, "tp", "NJ"), (1, "tp", "ANY")])

    def test_repository_level_entry_with_a_subject_needs_the_subject(self):
        k = key(mf("NJ", "vulnerable-dependency", subject="Newtonsoft.Json"))
        self.assertEqual(outcomes(score(k, res("D12", None, None, ZIP))), [(0, "unmatched-fp", None)])
        self.assertEqual(outcomes(score(k, res("D12", None, None, NJ12))), [(0, "tp", "NJ")])

    def test_per_dimension_rows_credit_each_dimension(self):
        r = score(self.K, res("D12", None, None, NJ12), res("D30", None, None, NJ12_D30))
        self.assertEqual((r["dimensions"]["D12"]["tp"], r["dimensions"]["D30"]["tp"]), (1, 1))

    def test_entry_row_reports_the_subject(self):
        self.assertEqual(entry(score(self.K), "NJ")["subject"], "Newtonsoft.Json")


class SubjectValidation(unittest.TestCase):
    def p(self, k):
        return validate_key(json.loads(json.dumps(k)), TAXONOMY)

    def test_schema_version_1_2_accepted(self):
        self.assertEqual(self.p(key(schemaVersion="1.2")), [])

    def test_subject_allowed_on_plants_traps_and_clean(self):
        k = key(mf("A", "weak-hash", "a.props", [1, 1], subject="Foo"),
                mnf("B", "weak-hash", "a.props", [9, 9], subject="Bar"),
                clean("C", ["weak-hash"], "b.props", subject="Baz"), schemaVersion="1.2")
        self.assertEqual(self.p(k), [])

    def test_subject_must_be_a_non_empty_string(self):
        for bad in ("", "   ", 3, None, ["Foo"]):
            probs = self.p(key(dict(mf("A", "weak-hash"), subject=bad)))
            self.assertTrue(any("'subject' must be a non-empty string" in x for x in probs), (bad, probs))

    def test_subject_not_allowed_on_na_or_score_band(self):
        for e in ({"id": "N", "label": "not-applicable", "concept": "weak-hash", "rationale": "x", "subject": "Foo"},
                  band("S", "security-policy-present", 0, 100, subject="Foo")):
            self.assertTrue(any("does not take 'subject'" in x for x in self.p(key(e))), e)

    def test_plant_and_trap_naming_the_same_subject_collide(self):
        k = key(mf("A", "weak-hash", "a.props", [1, 1], subject="Foo"),
                mnf("B", "weak-hash", "a.props", [40, 40], subject="foo"))
        self.assertTrue(any("name the same subject" in x for x in self.p(k)))


class ScoreDimensions(unittest.TestCase):
    M = copy.deepcopy(MAPPING_DOC)
    M["concepts"]["dependencies-not-locked"] = {"rules": [], "dimensions": ["D12", "D36", "SC1"],
                                                "scoreDimensions": ["SC1"]}
    K = key(band("B", "dependencies-not-locked", 80, 100))

    def test_band_takes_its_score_only_from_score_dimensions(self):
        b = run(self.K, scores={"D12": 37, "SC1": 90}, mapping=self.M)["scoreBands"][0]
        self.assertEqual((b["scores"], b["outcome"]), ([{"source": "SC1", "score": 90}], "in"))

    def test_a_finding_dimension_score_alone_leaves_the_band_unscored(self):
        b = run(self.K, scores={"D12": 37, "D36": 25}, mapping=self.M)["scoreBands"][0]
        self.assertEqual((b["scores"], b["outcome"]), ([], "unscored"))

    def test_without_score_dimensions_all_dimensions_are_looked_up(self):
        m = copy.deepcopy(self.M)
        del m["concepts"]["dependencies-not-locked"]["scoreDimensions"]
        self.assertEqual(run(self.K, scores={"D12": 37}, mapping=m)["scoreBands"][0]["outcome"], "out")

    def test_score_dimensions_must_be_a_non_empty_list(self):
        for bad in ([], "SC1", [""], [1]):
            m = copy.deepcopy(self.M)
            m["concepts"]["dependencies-not-locked"]["scoreDimensions"] = bad
            with self.assertRaises(MappingError):
                Mapping(m)


if __name__ == "__main__":
    unittest.main()
