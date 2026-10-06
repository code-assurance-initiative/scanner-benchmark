import unittest

from cai_bench.paths import norm, path_match
from tests.helpers import band, clean, entry, key, mf, mnf, na, outcomes, res, run

PC = "src/Billing/PaymentClient.cs"


class LabelOutcomes(unittest.TestCase):
    def test_must_fire_hit_is_tp(self):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14])), res("D13", PC, 14))
        self.assertEqual(entry(r, "A")["outcome"], "TP")
        self.assertEqual(outcomes(r), [(0, "tp", "A")])
        self.assertEqual(r["summary"]["recall"], 1.0)

    def test_must_fire_silent_is_fn(self):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14])))
        self.assertEqual(entry(r, "A")["outcome"], "FN")
        self.assertEqual(r["summary"]["recall"], 0.0)

    def test_wrong_concept_on_the_site_is_not_a_hit(self):
        # a long-method result on the planted credential line does not find the credential
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14]), mf("B", "long-method", "src/Other.cs")),
                res("D1", PC, 14))
        self.assertEqual(entry(r, "A")["outcome"], "FN")
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])

    def test_trap_fired_is_fp_and_noise(self):
        r = run(key(mnf("T", "hardcoded-credential", PC, [40, 40])), res("D13", PC, 41))
        self.assertEqual(entry(r, "T")["outcome"], "FP")
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])
        s = r["summary"]
        self.assertEqual((s["trapFp"], s["trapTn"], s["trapResistance"], s["noiseRate"]), (1, 0, 0.0, 1.0))

    def test_trap_left_alone_is_tn(self):
        r = run(key(mnf("T", "hardcoded-credential", PC, [40, 40]), mf("A", "hardcoded-credential", PC, [10, 10])),
                res("D13", PC, 10))
        self.assertEqual(entry(r, "T")["outcome"], "TN")
        self.assertEqual(r["summary"]["trapResistance"], 1.0)
        self.assertEqual(r["summary"]["noiseRate"], 0.0)

    def test_trap_metrics_with_no_traps_are_undefined_not_perfect(self):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14])))
        self.assertIsNone(r["summary"]["trapResistance"])
        self.assertIsNone(r["summary"]["noiseRate"])


class CleanAndNotApplicable(unittest.TestCase):
    def test_clean_specific_concepts_fp_for_listed_concept(self):
        k = key(clean("C", ["hardcoded-credential", "sql-injection"], "src/Invoice.cs"))
        r = run(k, res("D13", "src/Invoice.cs", 7))
        self.assertEqual(entry(r, "C")["outcome"], "FP")
        self.assertEqual(outcomes(r), [(0, "clean-fp", "C")])
        self.assertEqual(r["concepts"]["hardcoded-credential"]["fp"], 1)
        self.assertEqual(r["concepts"]["sql-injection"]["tn"], 1)

    def test_clean_specific_concepts_ignore_other_concepts(self):
        # weak-hash is not listed, and nothing else in the key covers it: uncovered, not noise
        k = key(clean("C", ["hardcoded-credential"], "src/Invoice.cs"))
        r = run(k, res("D20", "src/Invoice.cs", 7))
        self.assertEqual(entry(r, "C")["outcome"], "TN")
        self.assertEqual(outcomes(r), [(0, "uncovered", None)])
        self.assertEqual(r["summary"]["noise"], 0)

    def test_clean_star_catches_any_concept_even_unmapped_rules(self):
        k = key(clean("C", "*", "src/Invoice.cs"))
        r = run(k, res("D20", "src/Invoice.cs", 7), res("X999", "src/Invoice.cs", 8))
        self.assertEqual(outcomes(r), [(0, "clean-fp", "C"), (1, "clean-fp", "C")])
        self.assertEqual(r["concepts"]["*"]["fp"], 1)
        self.assertEqual(r["summary"]["noise"], 2)

    def test_clean_star_outside_region_is_tn(self):
        k = key(clean("C", "*", "src/Invoice.cs", [10, 20]))
        r = run(k, res("D20", "src/Invoice.cs", 9), res("D20", "src/Invoice.cs", 21))
        self.assertEqual(entry(r, "C")["outcome"], "TN")  # regions are exact: no line tolerance
        self.assertEqual([o for _, o, _ in outcomes(r)], ["uncovered", "uncovered"])

    def test_not_applicable_fired_is_fp(self):
        r = run(key(na("N", "sql-injection")), res("D14", "src/Data/Repo.cs", 9), res("D14"))
        self.assertEqual(entry(r, "N")["outcome"], "FP")
        self.assertEqual(outcomes(r), [(0, "na-fp", "N"), (1, "na-fp", "N")])

    def test_not_applicable_silent_is_tn(self):
        r = run(key(na("N", "sql-injection")), res("D13", PC, 1))
        self.assertEqual(entry(r, "N")["outcome"], "TN")
        self.assertEqual(outcomes(r), [(0, "uncovered", None)])


class RepositoryLevel(unittest.TestCase):
    def test_repo_level_entry_matches_result_without_location(self):
        r = run(key(mf("R", "missing-security-policy")), res("P3"))
        self.assertEqual(entry(r, "R")["outcome"], "TP")

    def test_repo_level_entry_matches_result_outside_located_entries(self):
        r = run(key(mf("R", "missing-security-policy")), res("P3", "README.md", 1))
        self.assertEqual(entry(r, "R")["outcome"], "TP")

    def test_repo_level_entry_does_not_take_results_inside_a_located_entry(self):
        k = key(mf("R", "missing-security-policy"), mnf("T", "missing-security-policy", "docs/SECURITY.txt"))
        r = run(k, res("P3", "docs/SECURITY.txt", 1))
        self.assertEqual(entry(r, "R")["outcome"], "FN")
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])

    def test_located_entry_does_not_match_repo_level_result(self):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14])), res("D13"))
        self.assertEqual(entry(r, "A")["outcome"], "FN")
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])


class LineTolerance(unittest.TestCase):
    def _hit(self, line, **top):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 16]), **top), res("D13", PC, line))
        return entry(r, "A")["outcome"] == "TP"

    def test_plus_minus_three_hits(self):
        self.assertTrue(self._hit(11))
        self.assertTrue(self._hit(19))

    def test_plus_minus_four_misses(self):
        self.assertFalse(self._hit(10))
        self.assertFalse(self._hit(20))

    def test_key_can_set_the_tolerance(self):
        self.assertTrue(self._hit(9, lineTolerance=5))
        self.assertFalse(self._hit(13, lineTolerance=0))

    def test_whole_file_entry_takes_any_line_and_no_line(self):
        k = key(mf("A", "hardcoded-credential", PC), mf("B", "hardcoded-credential", PC))
        r = run(k, res("D13", PC, 999), res("D13", PC))
        self.assertEqual([entry(r, x)["outcome"] for x in "AB"], ["TP", "TP"])

    def test_lined_entry_does_not_take_a_result_without_a_line(self):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14])), res("D13", PC))
        self.assertEqual(entry(r, "A")["outcome"], "FN")


class Paths(unittest.TestCase):
    def _hit(self, uri, prefixes=()):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14])), res("D13", uri, 14), prefixes=prefixes)
        return entry(r, "A")["outcome"] == "TP"

    def test_relative(self):
        self.assertTrue(self._hit(PC))
        self.assertTrue(self._hit("./" + PC))

    def test_absolute_and_file_uri(self):
        self.assertTrue(self._hit("/home/ci/work/repo/" + PC))
        self.assertTrue(self._hit("file:///home/ci/work/repo/" + PC))
        self.assertTrue(self._hit("file:///C:/build/repo/" + PC.replace("/", "\\")))
        self.assertTrue(self._hit("file:///home/ci/my%20repo/" + PC))

    def test_suffix_must_fall_on_a_segment_boundary(self):
        self.assertFalse(self._hit("src/Billing/MyPaymentClient.cs"))
        self.assertFalse(self._hit("src/Billing/PaymentClient.cs.bak"))

    def test_scanner_reporting_from_inside_the_repo(self):
        # either side may be the suffix (kennel matching.py rule)
        self.assertTrue(self._hit("Billing/PaymentClient.cs"))

    def test_repo_root_prefix_is_stripped(self):
        self.assertEqual(norm("/work/repo/src/a.cs", ["/work/repo"]), "src/a.cs")
        self.assertTrue(self._hit("/work/repo/" + PC, prefixes=["/work/repo/"]))

    def test_dot_directories_survive_normalisation(self):
        self.assertEqual(norm("./.github/workflows/ci.yml"), ".github/workflows/ci.yml")
        self.assertTrue(path_match(norm("/r/.github/workflows/ci.yml"), norm(".github/workflows/ci.yml")))


class OneToOne(unittest.TestCase):
    def test_extra_results_on_a_planted_site_are_redundant_not_noise(self):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14])),
                res("D13", PC, 14), res("D13/aws", PC, 15), res("D13", PC, 13))
        self.assertEqual(outcomes(r), [(0, "tp", "A"), (1, "redundant", "A"), (2, "redundant", "A")])
        s = r["summary"]
        self.assertEqual((s["tp"], s["redundant"], s["noise"], s["results"]), (1, 2, 0, 3))
        self.assertEqual(len(entry(r, "A")["redundant"]), 2)

    def test_each_entry_consumes_one_result(self):
        k = key(mf("A", "hardcoded-credential", PC, [14, 14]), mf("B", "hardcoded-credential", PC, [16, 16]))
        r = run(k, res("D13", PC, 15), res("D13", PC, 15))
        self.assertEqual(outcomes(r), [(0, "tp", "A"), (1, "tp", "B")])

    def test_one_result_cannot_hit_two_entries(self):
        k = key(mf("A", "hardcoded-credential", PC, [14, 14]), mf("B", "hardcoded-credential", PC, [16, 16]))
        r = run(k, res("D13", PC, 15))
        self.assertEqual([entry(r, x)["outcome"] for x in "AB"], ["TP", "FN"])

    def test_redundant_takes_precedence_over_a_nearby_trap(self):
        k = key(mf("A", "hardcoded-credential", PC, [14, 14]), mnf("T", "hardcoded-credential", PC, [18, 18]))
        r = run(k, res("D13", PC, 14), res("D13", PC, 16))
        self.assertEqual(outcomes(r), [(0, "tp", "A"), (1, "redundant", "A")])
        self.assertEqual(entry(r, "T")["outcome"], "TN")


class Uncovered(unittest.TestCase):
    def test_uncovered_results_are_reported_never_noise(self):
        k = key(mf("A", "hardcoded-credential", PC, [14, 14]))
        r = run(k, res("D13", PC, 14), res("D20", "src/Crypto/Hash.cs", 5), res("X999", "src/x.cs", 1))
        self.assertEqual([o for _, o, _ in outcomes(r)], ["tp", "uncovered", "uncovered"])
        s = r["summary"]
        self.assertEqual((s["uncovered"], s["noise"], s["results"], s["noiseRate"]), (2, 0, 1, 0.0))
        self.assertEqual(r["concepts"]["weak-hash"]["uncovered"], 1)
        self.assertEqual(r["concepts"]["(unmapped)"]["uncovered"], 1)
        self.assertEqual(r["dimensions"]["X999"]["uncovered"], 1)

    def test_covered_concept_result_off_every_entry_is_noise(self):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14])), res("D13", "src/Elsewhere.cs", 3))
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])
        self.assertEqual(r["summary"]["noiseRate"], 1.0)


class Dimensions(unittest.TestCase):
    def test_per_dimension_matching_is_separate(self):
        # D13 hits the credential; a D14 result on the same line does not credit D14 with anything
        k = key(mf("A", "hardcoded-credential", PC, [14, 14]), na("N", "sql-injection"))
        r = run(k, res("D13", PC, 14), res("D14", PC, 14))
        d13, d14 = r["dimensions"]["D13"], r["dimensions"]["D14"]
        self.assertEqual((d13["tp"], d13["fn"], d13["noise"]), (1, 0, 0))
        self.assertEqual((d14["tp"], d14["fp"], d14["noise"]), (0, 1, 1))

    def test_dimension_with_no_results_shows_its_misses(self):
        r = run(key(mf("A", "hardcoded-credential", PC, [14, 14])))
        self.assertEqual(r["dimensions"]["D13"]["fn"], 1)


class ScoreBands(unittest.TestCase):
    K = key(band("B1", "security-policy-present", 80, 100))

    def test_in_band(self):
        self.assertEqual(run(self.K, scores={"security-policy-present": 80})["scoreBands"][0]["outcome"], "in")

    def test_out_of_band(self):
        self.assertEqual(run(self.K, scores={"security-policy-present": 79.9})["scoreBands"][0]["outcome"], "out")

    def test_dimension_score_used_when_concept_has_none(self):
        b = run(self.K, scores={"P3": 100})["scoreBands"][0]
        self.assertEqual((b["outcome"], b["scores"][0]["source"]), ("in", "P3"))

    def test_unscored(self):
        self.assertEqual(run(self.K, scores={"D13": 50})["scoreBands"][0]["outcome"], "unscored")

    def test_score_band_entries_take_no_part_in_matching(self):
        r = run(self.K, res("P3"))
        self.assertEqual(r["entries"], [])
        self.assertEqual(outcomes(r), [(0, "uncovered", None)])


if __name__ == "__main__":
    unittest.main()
