"""The engine score and its coverage, as CAI decision 0024 §3 defines them.

Per (scored dimension, supported language) cell, from one window's measurement:

    F0.5 = 100 × 1.25 · P · R / (0.25 · P + R),   R = recall,  P = 1 − noise (noise as a share of the findings)

pooled over the holdout's units of that language. A declared cell where the engine reports nothing, or only noise,
scores 0. A cell in which the holdout plants no defect has no F0.5: it is listed apart and counts neither in the mean
nor in coverage. The engine score is the unweighted mean of the F0.5 of its declared cells; coverage is declared cells
÷ applicable cells with planted defects. Its 95 % interval is a percentile bootstrap that resamples the holdout's units
within each language. Results on languages the engine does not support are shown beside the score, not in it.

Input: per-unit reports carrying `language` and `byDimension` rows of `cai_bench.scoring` (tp, fn, noise, results).
"""
import random


def cell_f05(recall, precision):
    """F-score with β = 0.5, on a 0-100 scale. No precision (nothing reported) or nothing found is 0."""
    if not recall or not precision:
        return 0.0
    return 100.0 * 1.25 * precision * recall / (0.25 * precision + recall)


def _pool(units, language, dimension):
    tp = fn = noise = results = 0
    for u in units:
        if u["language"] != language:
            continue
        row = u["byDimension"].get(dimension)
        if not row:
            continue
        tp += row["tp"]
        fn += row["fn"]
        noise += row["noise"]
        results += row["results"]
    return tp, fn, noise, results


def _cell(units, language, dimension):
    tp, fn, noise, results = _pool(units, language, dimension)
    planted = tp + fn
    recall = tp / planted if planted else None
    precision = 1 - noise / results if results else None
    f05 = cell_f05(recall, precision) if planted else None
    return {"tp": tp, "fn": fn, "noise": noise, "results": results, "planted": planted,
            "recall": recall, "precision": precision, "f05": f05}


def _score(units, declared):
    scores = []
    for dimension, language in sorted(declared):
        c = _cell(units, language, dimension)
        if c["planted"]:
            scores.append(c["f05"])
    return sum(scores) / len(scores) if scores else None


def _percentile(sorted_values, q):
    if not sorted_values:
        return None
    k = (len(sorted_values) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def engine_report(units, declared, supported, applicable, resamples=10_000, seed=0):
    """The engine's report for one window.

    units: per-unit reports ({"unit", "language", "byDimension"}).
    declared: the (dimension, language) cells the engine declares it measures.
    supported: the languages it lists as supported.
    applicable: the (dimension, language) cells of scored dimensions that apply, by their dimension pages.
    """
    supported = set(supported)
    declared = {(d, l) for d, l in declared if l in supported}
    applicable = {(d, l) for d, l in applicable if l in supported}

    cells, unplanted = {}, {}
    for d, l in sorted(declared | applicable):
        c = _cell(units, l, d)
        if not c["planted"]:
            unplanted[(d, l)] = c
        elif (d, l) in declared:
            cells[(d, l)] = c

    planted_applicable = {k for k in applicable if k not in unplanted}
    score = sum(c["f05"] for c in cells.values()) / len(cells) if cells else None

    rng = random.Random(seed)
    by_language = {}
    for u in units:
        if u["language"] in supported:
            by_language.setdefault(u["language"], []).append(u)
    draws = []
    for _ in range(resamples):
        sample = [rng.choice(pool) for pool in by_language.values() for _ in pool]
        s = _score(sample, set(cells))
        if s is not None:
            draws.append(s)
    draws.sort()

    unsupported = {}
    for u in units:
        if u["language"] in supported:
            continue
        for d in u["byDimension"]:
            unsupported.setdefault((d, u["language"]), _cell(units, u["language"], d))

    return {
        "cells": cells,
        "score": score,
        "interval": (_percentile(draws, 0.025), _percentile(draws, 0.975)),
        "resamples": resamples,
        "seed": seed,
        "coverage": {"declared": len(cells), "applicable": len(planted_applicable),
                     "share": len(cells) / len(planted_applicable) if planted_applicable else None},
        "unplanted": unplanted,
        "unsupported": unsupported,
    }
