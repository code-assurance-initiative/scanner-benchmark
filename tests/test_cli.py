import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.helpers import FIXTURES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cli(*args):
    return subprocess.run([sys.executable, "-m", "cai_bench", *args], cwd=ROOT, capture_output=True, text=True)


def fx(name):
    return os.path.join(FIXTURES, name)


class Cli(unittest.TestCase):
    def test_validate_ok(self):
        p = cli("validate", "--key", fx("answer-key.json"), "--taxonomy", fx("taxonomy.json"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("OK", p.stdout)

    def test_validate_reports_every_problem_and_fails(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "k.json")
            with open(fx("answer-key.json")) as f:
                k = json.load(f)
            k["entries"].append(dict(k["entries"][0]))           # duplicate id
            k["entries"][1]["concept"] = "not-a-concept"
            with open(path, "w") as f:
                json.dump(k, f)
            p = cli("validate", "--key", path, "--taxonomy", fx("taxonomy.json"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("duplicate id 'SEC-001'", p.stderr)
        self.assertIn("'not-a-concept' is not in the taxonomy", p.stderr)

    def test_sha256(self):
        import hashlib
        with open(fx("answer-key.json"), "rb") as f:
            want = hashlib.sha256(f.read()).hexdigest()
        p = cli("sha256", "--key", fx("answer-key.json"))
        self.assertEqual(p.stdout.strip(), want)

    def test_score_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            p = cli("score", "--key", fx("answer-key.json"), "--sarif", fx("report.sarif"),
                    "--mapping", fx("mapping.json"), "--scores", fx("scores.json"), "--json", out)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(out) as f:
                r = json.load(f)
        self.assertIn("scanner dimension", p.stdout)
        self.assertIn("FN SEC-002", p.stdout)
        got = {(x["index"], x["outcome"], x["entryId"], x["ruleId"], x["file"], x["line"]) for x in r["results"]}
        self.assertEqual(got, {
            # contract 1.4: the absolute uri under the checkout directory (named after the key's repo) is made
            # repo-relative and compared exactly
            # contract 1.7: the row on the plant's own line (14) is the TP, the one within tolerance (15) redundant
            (0, "redundant", "SEC-001", "D13", "src/Billing/PaymentClient.cs", 15),
            (1, "tp", "SEC-001", "D13/aws", "src/Billing/PaymentClient.cs", 14),
            (2, "trap-fp", "TRP-001", "D13", "src/Billing/PaymentClient.cs", 40),
            (3, "clean-fp", "CLN-001", "D1", "src/Billing/Invoice.cs", 3),   # ruleIndex -> driver.rules[1]
            (4, "na-fp", "NA-001", "D14", "src/Data/Repo.cs", 9),
            (5, "uncovered", None, "D20", "src/Crypto/Hash.cs", 5),
        })
        s = r["summary"]
        self.assertEqual((s["tp"], s["fn"], s["trapFp"], s["trapTn"], s["redundant"], s["uncovered"]),
                         (1, 1, 1, 0, 1, 1))
        self.assertEqual((s["noise"], s["results"]), (3, 5))
        self.assertAlmostEqual(s["recall"], 0.5)
        self.assertAlmostEqual(s["noiseRate"], 0.6)
        self.assertEqual(r["scoreBands"][0]["outcome"], "in")
        self.assertEqual(r["key"]["repo"], "code-assurance-initiative/bench-fixture")
        self.assertEqual(len(r["sarif"]["sha256"]), 64)
        sec2 = next(e for e in r["entries"] if e["id"] == "SEC-002")
        self.assertEqual((sec2["outcome"], sec2["results"]), ("FN", []))

    def test_score_refuses_an_invalid_key(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "k.json")
            with open(path, "w") as f:
                json.dump({"schemaVersion": "1.0", "repo": "a/b", "keyVersion": "1.0.0",
                           "entries": [{"id": "A", "label": "must-fire", "rationale": "x"}]}, f)
            p = cli("score", "--key", path, "--sarif", fx("report.sarif"), "--mapping", fx("mapping.json"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("requires 'concept'", p.stderr)

    def test_unreadable_input_is_a_clear_error(self):
        p = cli("score", "--key", fx("answer-key.json"), "--sarif", fx("nope.sarif"), "--mapping", fx("mapping.json"))
        self.assertEqual(p.returncode, 2)
        self.assertIn("SARIF: cannot read", p.stderr)


if __name__ == "__main__":
    unittest.main()
