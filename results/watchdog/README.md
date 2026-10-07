# Watchdog results

One JSON file per benchmark repository, `<repo>.json` (e.g. `bench-csharp-security-secrets.json`), recording what
Watchdog found while that repository was being authored and at its frozen tag: every scan, every finding that was not
an expected hit with its verdict, and every planted defect it missed.

During authoring Watchdog is the **instrument** used to make a repository golden, not the thing being graded: where
it is right about something nobody meant to plant, the **repository** is fixed; where it is wrong, the finding is
recorded here as Watchdog noise. Nothing in this directory is ever fixed by changing a key.

The repositories these files describe are now **units of the training set**
[`training-set-2026`](https://github.com/code-assurance-initiative/training-set-2026) (one git bundle each, full
history and every tag, plus a readable snapshot of the latest tag); `repo` stays the unit id. The scan directories the
files name (`_scans/<repo>/…`) are in the authoring workspace, recorded by sha256. To reproduce a result: materialise
the unit (`tools/materialize.sh <repo> <dir>` in the set), scan `<dir>/<repo>`, re-score with
[`rescore.py`](rescore.py) `--units-dir <dir>` (or score one unit with `python3 -m cai_bench score`), and compare —
see [BASELINE-2026-10-07 § 11](BASELINE-2026-10-07.md#11-re-measuring-against-this-baseline).

Scripts here: [`summarise.py`](summarise.py) (`final-scores.json` → `SUMMARY.json`), [`baseline.py`](baseline.py)
(the frozen baseline and its doc tables; `--check`), [`rescore.py`](rescore.py) (a new set of scans → a
`final-scores.json` to `compare`). The two that read keys take `--units-dir` (materialised units) and `--set-dir` (the
set's bundles; default `training-set-2026` next to scanner-benchmark) and check every key's sha256.

## Verdict classes

Each finding that is not a `must-fire` hit is placed in exactly one of five classes. The definitions are quoted from
the Watchdog noise-measurement protocol (`watchdog-benchmark/METHOD.md`, version 2.0, §1):

| Class | Signal? | Rule |
|---|---|---|
| `valid` | signal | Factually true at the cited location, and an informed maintainer of *this* codebase would accept it as a real, non-trivial issue (or an accurate measurement). **Uncertain = valid** — the auditor never manufactures noise; ambiguity is resolved in the tool's favour. |
| `false-positive` | noise | Asserts something factually untrue of the code, or publishes a score/claim with no supporting evidence. The auditor must be able to state the concrete disproof — file, line, mechanism — not merely disagree. |
| `opinion-not-fact` | noise | The measurement is accurate, but the stated conclusion, framing, or quantified promise goes beyond what the measurement supports. |
| `redundant` | noise | True, but — *after the logical-finding collapse below* — still restates another finding such that one remediation clears both and the second adds no separately-actionable information. Multi-lens detection of one issue is **not** redundant (see below). |
| `shape-irrelevant` | noise | Factually grounded, but applies an expectation foreign to the *kind* of software being scanned (a library / CLI / service / desktop app / framework), which an informed maintainer would decline as "not applicable to what this is". |

The protocol fixes the procedure as well (§1.1): **collapse first** — same-issue-same-site detections by several
dimensions are one logical finding, annotated with every contributing dimension — **then classify, in this
precedence**, the first rule that applies deciding the class: false-positive, opinion-not-fact, redundant,
shape-irrelevant, valid.

In the benchmark loop a `valid` verdict means the repository is fixed; the other four are recorded as noise (and a
good site may be promoted to a `must-not-fire` trap); `redundant` is recorded and counted once.

## Per-repository format

```jsonc
{
  "repo": "code-assurance-initiative/bench-csharp-security-secrets",
  "tag": "v1.0.0",                         // the tag the final scan was taken at; null while authoring
  "engineVersion": "…",                    // Watchdog engine / rubric version the scans ran on
  "scans": [
    {
      "iteration": 1,                      // 1, 2, … in the order of the authoring loop
      "date": "2026-10-07",                // ISO 8601
      "sarifSha256": "…",                  // sha256 of the report.sarif bytes scored
      "configuration": { "label": "wcag-2.2", "env": { "CODEHEALTH_COMPLIANCE_FRAMEWORKS": "wcag-2.2" } },
                                           // optional: ONLY on a non-default configuration (a secondary run, excluded
                                           // from headline numbers); absent = the scanner's default configuration
      "outcomes": {                        // the `summary` block of `python3 -m cai_bench score --json`
        "tp": 0, "fn": 0, "fp": 0, "tn": 0, "trapFp": 0, "trapTn": 0,
        "results": 0, "noise": 0, "redundant": 0, "uncovered": 0
      }
    }
  ],
  "verdicts": [
    {
      "ruleId": "D13",                     // as in the SARIF result
      "file": "src/Billing/PaymentClient.cs",   // repo-relative; null for a repository-level finding
      "line": 40,                          // null when the finding has none
      "message": "…",                      // the finding's message, verbatim
      "class": "false-positive",           // valid | false-positive | opinion-not-fact | redundant | shape-irrelevant
      "reason": "…",                       // the concrete argument; for false-positive, the disproof (file, line, mechanism)
      "action": "…"                        // what was done: repo fixed (commit), recorded as noise, promoted to trap <entry id>
    }
  ],
  "falseNegatives": [
    { "entryId": "SEC-002", "reason": "…why the plant is real and was not reported…" }
  ]
}
```

Verdicts are kept for every iteration's findings, not only the last scan's, so the history of how the repository
became golden can be read back. A finding that recurs in a later scan is not judged twice unless the code at its site
changed.
