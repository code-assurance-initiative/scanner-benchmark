"""`python3 -m cai_bench compare` and cai_bench.baseline: per-lens / per-dimension aggregation and deltas against a
frozen baseline."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

from cai_bench.baseline import aggregate, compare, metrics
from cai_bench.mapping import Mapping

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCHDOG = os.path.join(ROOT, "results", "watchdog")
FROZEN = os.path.join(WATCHDOG, "baseline-2026-10-07.json")

MAPPING = Mapping({
    "scanner": "fixture", "version": "1",
    "concepts": {
        "secret": {"rules": [{"rule": "^D13$"}], "dimensions": ["D13", "D28"]},
        "sqli": {"rules": [{"rule": "^D29$"}], "dimensions": ["D29"]},
        "god-class": {"rules": [{"rule": "^D3$"}], "dimensions": ["D3"]},
    },
})
LENS = {"D13": "productionReadiness", "D28": "securityCompliance", "D29": "securityCompliance", "D3": "codeHealth"}


def row(id, tp=0, fn=0, trapFp=0, trapTn=0, results=0, noise=0, fileLevelTp=None, **kw):
    r = {"id": id, "tp": tp, "fn": fn, "trapFp": trapFp, "trapTn": trapTn, "fp": trapFp, "tn": trapTn,
         "results": results, "noise": noise, "redundant": 0, "uncovered": 0,
         "fileLevelTp": tp if fileLevelTp is None else fileLevelTp}
    r.update(kw)
    return metrics(r)


def repo(name, lang, concepts, dims, bands=(), tag="v1.0.0", key="a" * 64):
    tot = {}
    for c in concepts:
        for k in ("tp", "fn", "trapFp", "trapTn", "fp", "tn", "results", "noise", "redundant", "fileLevelTp"):
            tot[k] = tot.get(k, 0) + c[k]
    return {"name": name, "tag": tag, "keySha256": key, "languages": [lang], "family": "security",
            "summary": metrics(dict(tot, uncovered=0)), "concepts": list(concepts), "dimensions": list(dims),
            "scoreBands": list(bands)}


def final_doc():
    return {"instrument": "fixture engine A", "repos": [
        repo("cs", "csharp",
             concepts=[row("secret", tp=2, fn=1, trapTn=3, trapFp=1, results=4, noise=1),
                       row("sqli", tp=1, fn=1, results=2, noise=1),
                       row("react-index-as-key", fn=1)],
             dims=[row("D13", tp=2, fn=1, trapTn=3, trapFp=1, results=3, noise=1),
                   row("D28", tp=1, fn=2, trapTn=4, results=1, noise=0),
                   row("D29", tp=1, fn=1, results=2, noise=1),
                   row("(no scanner rule)", fn=1)],
             bands=[{"id": "B1", "concept": "god-class", "band": [0, 50], "scores": [{"source": "D3", "score": 80}],
                     "outcome": "out"},
                    {"id": "B2", "concept": "sqli", "band": [0, 50], "scores": [], "outcome": "unscored"}]),
        repo("ts", "typescript",
             concepts=[row("god-class", tp=1, fn=1, trapTn=1, results=1)],
             dims=[row("D3", tp=1, fn=1, trapTn=1, results=1)]),
    ]}


def baseline_doc(final):
    agg = aggregate(final, MAPPING, LENS)
    return {"instrument": final["instrument"], "dimensionLens": LENS,
            "lensOrder": ["codeHealth", "productionReadiness", "securityCompliance", "(no scanner rule)"],
            "lensLabels": {"codeHealth": "Code Health", "productionReadiness": "Readiness",
                           "securityCompliance": "Security"},
            "totals": agg["totals"], "byLanguage": agg["byLanguage"], "byLens": agg["byLens"],
            "byDimension": agg["byDimension"],
            "repos": [{"name": r["name"], "tag": r["tag"], "keySha256": r["keySha256"]} for r in final["repos"]]}


class Aggregate(unittest.TestCase):
    def test_lens_counts_a_plant_once_per_lens_and_partitions_results(self):
        agg = aggregate(final_doc(), MAPPING, LENS)
        sec = agg["byLens"]["securityCompliance"]["all"]
        # secret (3 plants, via D28) + sqli (2 plants, via D29): each plant once, from the concept rows
        self.assertEqual((sec["tp"], sec["fn"], sec["trapTn"], sec["trapFp"]), (3, 2, 3, 1))
        # results/noise: the lens's dimension rows D28 + D29
        self.assertEqual((sec["results"], sec["noise"]), (3, 1))
        rdy = agg["byLens"]["productionReadiness"]["all"]
        self.assertEqual((rdy["tp"], rdy["fn"], rdy["results"], rdy["noise"]), (2, 1, 3, 1))
        self.assertEqual(agg["byLens"]["(no scanner rule)"]["all"]["fn"], 1)
        # results partition exactly across lenses
        self.assertEqual(sum(v["all"]["results"] for v in agg["byLens"].values()), agg["totals"]["results"])
        self.assertEqual(agg["byLens"]["codeHealth"]["typescript"]["tp"], 1)

    def test_dimension_rows_sum_and_split_by_language(self):
        agg = aggregate(final_doc(), MAPPING, LENS)
        d3 = agg["byDimension"]["D3"]
        self.assertEqual((d3["all"]["tp"], d3["typescript"]["tp"], d3["csharp"]["tp"]), (1, 1, 0))
        self.assertEqual(d3["repos"], ["cs", "ts"])  # banded on cs, measured by ts
        self.assertEqual(d3["bandCounts"], {"in": 0, "out": 1, "unscored": 0})
        # an unscored band goes to the dimensions the mapping says measure its concept
        self.assertEqual(agg["byDimension"]["D29"]["bandCounts"]["unscored"], 1)
        self.assertEqual(agg["byLens"]["codeHealth"]["bands"], {"in": 0, "out": 1, "unscored": 0})


class Compare(unittest.TestCase):
    def test_identical_run_has_no_changed_dimension(self):
        f = final_doc()
        doc, text = compare(baseline_doc(f), copy.deepcopy(f), MAPPING)
        self.assertEqual(doc["changedDimensions"], 0)
        self.assertEqual(doc["warnings"], [])
        self.assertIn("(no dimension changed)", text)

    def test_a_better_engine_shows_per_dimension_and_per_lens_deltas(self):
        f = final_doc()
        base = baseline_doc(f)
        cur = copy.deepcopy(f)
        cur["instrument"] = "fixture engine B"
        cs = cur["repos"][0]
        cs["concepts"][1] = row("sqli", tp=2, fn=0, results=2, noise=0)
        cs["dimensions"][2] = row("D29", tp=2, fn=0, results=2, noise=0)
        doc, text = compare(base, cur, MAPPING)
        self.assertEqual(doc["changedDimensions"], 1)
        d29 = doc["byDimension"]["D29"]
        self.assertEqual((d29["baseline"]["tp"], d29["current"]["tp"]), (1, 2))
        self.assertTrue(d29["changed"])
        self.assertFalse(doc["byDimension"]["D13"]["changed"])
        sec = doc["byLens"]["securityCompliance"]
        self.assertEqual((sec["baseline"]["recall"], sec["current"]["recall"]), (0.6, 0.8))
        self.assertIn("D29", text)
        self.assertIn("+20.0", text)   # Security lens recall 60 % -> 80 %
        self.assertIn("+50.0", text)   # D29 recall 50 % -> 100 %
        self.assertNotIn("\nD13 ", text)

    def test_a_different_key_or_missing_repository_is_flagged(self):
        f = final_doc()
        base = baseline_doc(f)
        cur = copy.deepcopy(f)
        cur["repos"][0]["tag"], cur["repos"][0]["keySha256"] = "v1.1.0", "b" * 64
        del cur["repos"][1]
        doc, text = compare(base, cur, MAPPING)
        self.assertEqual(len(doc["warnings"]), 2)
        self.assertIn("not like for like", text)
        self.assertIn("missing from the current run", text)


@unittest.skipUnless(os.path.exists(FROZEN), "no frozen Watchdog baseline")
class FrozenWatchdogBaseline(unittest.TestCase):
    def test_baseline_reconciles_with_the_summary(self):
        with open(FROZEN) as f:
            b = json.load(f)
        with open(os.path.join(WATCHDOG, "SUMMARY.json")) as f:
            s = json.load(f)
        for k in ("tp", "fn", "trapTn", "trapFp", "results", "noise"):
            self.assertEqual(b["totals"][k], s["totals"][k], k)
        self.assertTrue(all(x["ok"] for x in b["reconciliation"]["withSummary"]))
        self.assertEqual(sum(v["all"]["results"] for v in b["byLens"].values()), s["totals"]["results"])
        self.assertEqual(sum(v["all"]["noise"] for v in b["byLens"].values()), s["totals"]["noise"])

    def test_cli_compare_of_the_baseline_run_against_itself_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "delta.json")
            p = subprocess.run([sys.executable, "-m", "cai_bench", "compare", "--baseline", FROZEN,
                                "--current", os.path.join(WATCHDOG, "final-scores.json"), "--json", out],
                               cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(out) as f:
                doc = json.load(f)
        self.assertEqual(doc["changedDimensions"], 0, p.stdout)
        self.assertEqual(doc["warnings"], [])
        self.assertIn("PER LENS", p.stdout)
        self.assertIn("(no dimension changed)", p.stdout)

    def test_cli_compare_rejects_a_non_baseline(self):
        p = subprocess.run([sys.executable, "-m", "cai_bench", "compare", "--baseline",
                            os.path.join(WATCHDOG, "SUMMARY.json"), "--current",
                            os.path.join(WATCHDOG, "final-scores.json")], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("not a baseline document", p.stderr)


if __name__ == "__main__":
    unittest.main()
