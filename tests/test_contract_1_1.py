"""Contract 1.1: message/property discriminators, per-rule conditions, `ignore` (summary rows), concept families,
and history entries pinned to a commit."""
import copy
import json
import unittest

from cai_bench.keyfile import validate_key
from cai_bench.mapping import Mapping, MappingError
from tests.helpers import MAPPING_DOC, TAXONOMY, entry, key, mf, mnf, outcomes, res, run

ENV = "src/Api/appsettings.json"


def mapping(**concepts_and_top):
    """The fixture mapping with some concepts replaced/added and top-level fields set."""
    m = copy.deepcopy(MAPPING_DOC)
    for k, v in concepts_and_top.items():
        if k in ("ignore",):
            m[k] = v
        else:
            m["concepts"][k.replace("_", "-")] = v
    return m


# One scanner rule (D13 here, like a real scanner's dimension-level rule id) carries several concepts; the message
# says which one.
SECRETS = dict(
    hardcoded_credential={"rules": ["^D13$", {"rule": "^D31$", "messages": ["^\\w+ IaC: DS-0031:"]}],
                          "messages": ["^Leaked secret: (?:aws-access-key|generic-api-key):"],
                          "dimensions": ["D13", "D31"], "family": "hardcoded-secret"},
    hardcoded_password={"rules": ["^D13$"], "messages": ["^Leaked secret: password:"], "dimensions": ["D13"],
                        "family": "hardcoded-secret"},
    secret_in_version_history={"rules": [{"rule": "^D13$", "properties": ["commitSha"]}], "dimensions": ["D13"]},
)


class Messages(unittest.TestCase):
    def test_message_decides_the_concept(self):
        m = Mapping(mapping(**SECRETS))
        self.assertEqual(m.concepts_of("D13", "Leaked secret: aws-access-key: x", {}), ["hardcoded-credential"])
        self.assertEqual(m.concepts_of("D13", "Leaked secret: password: x", {}), ["hardcoded-password"])
        self.assertEqual(m.concepts_of("D13", "Something else entirely", {}), [])

    def test_message_match_is_a_case_insensitive_search(self):
        m = Mapping(mapping(weak_hash={"rules": ["^D20$"], "messages": ["md5"], "dimensions": ["D20"]}))
        self.assertEqual(m.concepts_of("D20", "Uses MD5 here", {}), ["weak-hash"])

    def test_concept_without_messages_takes_every_result_of_its_rules(self):
        m = Mapping(mapping(**SECRETS))
        self.assertEqual(m.concepts_of("D14", "anything", {}), ["sql-injection"])

    def test_per_rule_messages_override_concept_messages(self):
        m = Mapping(mapping(**SECRETS))
        self.assertEqual(m.concepts_of("D31", "Medium IaC: DS-0031: secret in ENV", {}), ["hardcoded-credential"])
        self.assertEqual(m.concepts_of("D31", "Low IaC: DS-0026: No HEALTHCHECK defined", {}), [])

    def test_hygiene_result_on_a_secret_dimension_is_not_secret_noise(self):
        k = key(mf("A", "hardcoded-credential", ENV, [5, 5]))
        r = run(k, res("D31", "Dockerfile", 1, "Low IaC: DS-0026: No HEALTHCHECK defined"), mapping=mapping(**SECRETS))
        self.assertEqual(outcomes(r), [(0, "uncovered", None)])
        self.assertEqual(r["summary"]["noise"], 0)

    def test_required_property(self):
        m = Mapping(mapping(**SECRETS))
        self.assertIn("secret-in-version-history",
                      m.concepts_of("D13", "Leaked secret: aws-access-key: x", {"commitSha": "abc"}))
        self.assertNotIn("secret-in-version-history", m.concepts_of("D13", "Leaked secret: aws-access-key: x", {}))

    def test_bad_regexes_are_mapping_errors(self):
        for bad in (dict(weak_hash={"rules": ["^D20$"], "messages": ["("]}),
                    dict(weak_hash={"rules": [{"rule": "("}]}),
                    dict(weak_hash={"rules": [{"messages": ["x"]}]}),
                    dict(ignore=[{"rule": "^D28$", "message": "(", "reason": "x"}]),
                    dict(ignore=[{"reason": "matches everything"}])):
            with self.assertRaises(MappingError):
                Mapping(mapping(**bad))


class Ignore(unittest.TestCase):
    M = mapping(ignore=[{"rule": "^D13$", "message": "^Rotate the exposed", "reason": "roll-up of the located rows"}])

    def test_ignored_results_are_summary_and_in_no_metric(self):
        k = key(mf("A", "hardcoded-credential", ENV, [5, 5]))
        r = run(k, res("D13", ENV, 5), res("D13", None, None, "Rotate the exposed credentials: …"), mapping=self.M)
        self.assertEqual(outcomes(r), [(0, "tp", "A"), (1, "summary", None)])
        s = r["summary"]
        self.assertEqual((s["results"], s["noise"], s["uncovered"], s["summaryRows"]), (1, 0, 0, 1))
        self.assertEqual(r["dimensions"]["D13"]["results"], 1)
        self.assertEqual(r["results"][1]["ignoreReason"], "roll-up of the located rows")

    def test_ignore_needs_both_regexes_to_match(self):
        k = key(mf("A", "hardcoded-credential", ENV, [5, 5]))
        r = run(k, res("D14", None, None, "Rotate the exposed credentials"), mapping=self.M)
        self.assertEqual(outcomes(r), [(0, "uncovered", None)])


class Family(unittest.TestCase):
    M = mapping(**SECRETS)
    PW = "Leaked secret: password: x"
    KEY = "Leaked secret: aws-access-key: x"

    def test_sibling_concept_at_the_site_finds_the_plant(self):
        r = run(key(mf("A", "hardcoded-credential", ENV, [5, 5])), res("D13", ENV, 5, self.PW), mapping=self.M)
        self.assertEqual(outcomes(r), [(0, "tp", "A")])

    def test_exact_concept_is_preferred_over_a_sibling(self):
        k = key(mf("A", "hardcoded-credential", ENV, [5, 5]), mf("B", "hardcoded-password", ENV, [5, 5]))
        r = run(k, res("D13", ENV, 5, self.PW), mapping=self.M)
        self.assertEqual([entry(r, x)["outcome"] for x in "AB"], ["FN", "TP"])

    def test_sibling_on_a_trap_is_caught_in_the_trap(self):
        r = run(key(mnf("T", "hardcoded-credential", ENV, [9, 9])), res("D13", ENV, 9, self.PW), mapping=self.M)
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])

    def test_sibling_off_every_entry_is_noise_not_uncovered(self):
        r = run(key(mf("A", "hardcoded-credential", ENV, [5, 5])), res("D13", "src/Other.cs", 40, self.PW),
                mapping=self.M)
        self.assertEqual(outcomes(r), [(0, "unmatched-fp", None)])

    def test_without_a_declared_family_siblings_do_not_match(self):
        m = mapping(**{k: {kk: vv for kk, vv in v.items() if kk != "family"} for k, v in SECRETS.items()})
        r = run(key(mf("A", "hardcoded-credential", ENV, [5, 5])), res("D13", ENV, 5, self.PW), mapping=m)
        self.assertEqual(entry(r, "A")["outcome"], "FN")
        self.assertEqual(outcomes(r), [(0, "uncovered", None)])

    def test_redundant_includes_siblings(self):
        r = run(key(mf("A", "hardcoded-credential", ENV, [5, 5])),
                res("D13", ENV, 5, self.KEY), res("D13", ENV, 5, self.PW), mapping=self.M)
        self.assertEqual(outcomes(r), [(0, "tp", "A"), (1, "redundant", "A")])


class History(unittest.TestCase):
    M = mapping(**SECRETS)
    MSG = "Leaked secret: aws-access-key: x"
    K = key(mf("H", "secret-in-version-history", "src/Api/appsettings.Staging.json", [3, 3], commit="e920ad5"),
            schemaVersion="1.1")

    def test_commit_entry_matches_by_sha_prefix_at_any_line(self):
        r = run(self.K, res("D13", "src/Api/appsettings.Staging.json", 77, self.MSG, commit="E920AD5f00d"),
                mapping=self.M)
        self.assertEqual(entry(r, "H")["outcome"], "TP")
        self.assertEqual(r["results"][0]["commitSha"], "E920AD5f00d")

    def test_commit_entry_rejects_another_commit_or_none(self):
        r = run(self.K, res("D13", "src/Api/appsettings.Staging.json", 3, self.MSG, commit="d5166f8aa"),
                res("D13", "src/Api/appsettings.Staging.json", 3, self.MSG), mapping=self.M)
        self.assertEqual(entry(r, "H")["outcome"], "FN")

    def test_commit_entry_still_needs_the_file(self):
        r = run(self.K, res("D13", "src/Api/appsettings.json", 3, self.MSG, commit="e920ad5"), mapping=self.M)
        self.assertEqual(entry(r, "H")["outcome"], "FN")

    def test_commit_sha_is_none_for_working_tree_results(self):
        r = run(key(), res("D13", ENV, 1), mapping=self.M)
        self.assertIsNone(r["results"][0]["commitSha"])


class Validation(unittest.TestCase):
    def p(self, k):
        return validate_key(json.loads(json.dumps(k)), TAXONOMY)

    def test_schema_version_1_0_and_1_1_accepted(self):
        self.assertEqual(self.p(key(schemaVersion="1.0")), [])
        self.assertEqual(self.p(key(schemaVersion="1.1")), [])
        self.assertTrue(self.p(key(schemaVersion="2.0")))

    def test_commit_is_validated(self):
        ok = mf("H", "weak-hash", "a.cs", commit="e920ad5")
        self.assertEqual(self.p(key(ok)), [])
        self.assertTrue(any("'commit'" in x for x in self.p(key(mf("H", "weak-hash", "a.cs", commit="zz")))))
        self.assertTrue(any("'commit' requires 'file'" in x for x in self.p(key(mf("H", "weak-hash", commit="e920ad5")))))
        self.assertTrue(any("does not take 'commit'" in x
                            for x in self.p(key({"id": "N", "label": "not-applicable", "concept": "weak-hash",
                                                 "rationale": "x", "commit": "e920ad5"}))))


if __name__ == "__main__":
    unittest.main()
