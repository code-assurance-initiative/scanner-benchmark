"""cai_bench.engine_report: CAI decision 0024 §3, the per-cell F0.5, the engine score, its coverage and its interval."""
import unittest

from cai_bench.engine_report import cell_f05, engine_report


def unit(name, language, **dims):
    """dims: dimension -> (tp, fn, noise, results)."""
    return {"unit": name, "language": language,
            "byDimension": {d: {"tp": t, "fn": f, "noise": n, "results": r} for d, (t, f, n, r) in dims.items()}}


class CellScoreTests(unittest.TestCase):
    def test_the_decisions_two_worked_examples(self):
        # 0024 §3: recall 100 % at 80 % noise scores 24; recall 60 % at 25 % noise scores 71.
        self.assertEqual(24, round(cell_f05(recall=1.0, precision=0.2)))
        self.assertEqual(71, round(cell_f05(recall=0.6, precision=0.75)))

    def test_nothing_reported_or_only_noise_scores_zero(self):
        self.assertEqual(0.0, cell_f05(recall=0.0, precision=0.0))
        self.assertEqual(0.0, cell_f05(recall=0.0, precision=None))


class EngineReportTests(unittest.TestCase):
    def setUp(self):
        self.units = [
            unit("a", "csharp", D1=(8, 2, 1, 9), D2=(0, 4, 0, 0)),
            unit("b", "csharp", D1=(6, 4, 3, 9), D2=(2, 2, 2, 4)),
            unit("c", "typescript", D1=(5, 5, 0, 5)),
            unit("d", "python", D1=(3, 1, 0, 3)),
        ]

    def report(self, declared, **kw):
        return engine_report(self.units, declared=declared, supported=["csharp", "typescript"],
                             applicable=[("D1", "csharp"), ("D2", "csharp"), ("D1", "typescript"), ("D3", "csharp")],
                             resamples=kw.get("resamples", 200), seed=7)

    def test_a_cell_pools_its_language_units(self):
        r = self.report({("D1", "csharp"), ("D2", "csharp"), ("D1", "typescript")})
        c = r["cells"][("D1", "csharp")]
        self.assertEqual((14, 6, 4, 18), (c["tp"], c["fn"], c["noise"], c["results"]))
        self.assertAlmostEqual(0.7, c["recall"])
        self.assertAlmostEqual(1 - 4 / 18, c["precision"])

    def test_the_score_is_the_unweighted_mean_of_declared_cells(self):
        r = self.report({("D1", "csharp"), ("D2", "csharp"), ("D1", "typescript")})
        expected = sum(r["cells"][k]["f05"] for k in [("D1", "csharp"), ("D2", "csharp"), ("D1", "typescript")]) / 3
        self.assertAlmostEqual(expected, r["score"])

    def test_coverage_is_declared_over_applicable_cells_with_planted_defects(self):
        # D3/csharp applies but the holdout plants nothing there: it counts in neither the score nor coverage.
        r = self.report({("D1", "csharp"), ("D1", "typescript")})
        self.assertEqual((2, 3), (r["coverage"]["declared"], r["coverage"]["applicable"]))
        self.assertIn(("D3", "csharp"), r["unplanted"])

    def test_a_declared_cell_with_no_findings_scores_zero(self):
        units = [unit("a", "csharp", D1=(0, 5, 0, 0))]
        r = engine_report(units, declared={("D1", "csharp")}, supported=["csharp"], applicable=[("D1", "csharp")],
                          resamples=50, seed=1)
        self.assertEqual(0.0, r["cells"][("D1", "csharp")]["f05"])
        self.assertEqual(0.0, r["score"])

    def test_unsupported_languages_are_shown_beside_the_score_not_in_it(self):
        r = self.report({("D1", "csharp"), ("D2", "csharp"), ("D1", "typescript")})
        self.assertIn(("D1", "python"), r["unsupported"])
        self.assertNotIn(("D1", "python"), r["cells"])

    def test_the_interval_is_seeded_and_brackets_the_score(self):
        a = self.report({("D1", "csharp"), ("D2", "csharp"), ("D1", "typescript")})
        b = self.report({("D1", "csharp"), ("D2", "csharp"), ("D1", "typescript")})
        self.assertEqual(a["interval"], b["interval"])
        lo, hi = a["interval"]
        self.assertLessEqual(lo, a["score"])
        self.assertGreaterEqual(hi, a["score"])
        self.assertEqual(7, a["seed"])


if __name__ == "__main__":
    unittest.main()
