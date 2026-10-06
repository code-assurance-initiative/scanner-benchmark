# Harness contract (v1)

The fixed interfaces between the parts of this harness. Change only with a version bump.

## Labels vs outcomes

The answer key holds LABELS; TP/FP/TN/FN are OUTCOMES of one scanner run against it.

| Label | Meaning | Scanner fires | Scanner silent |
|---|---|---|---|
| `must-fire` | a planted defect | TP | FN |
| `must-not-fire` | a trap: looks like a defect, is not | FP (caught in the trap) | TN |
| `clean` | a file/region certified defect-free for the listed concepts (or all concepts: `"concepts": "*"`) | FP | TN |
| `not-applicable` | the concept has nothing to measure in this repo | FP | TN |
| `score-band` | a posture / metric / judged property: an expected score range on a 0–100 scale | in band / out of band | — |

## `benchmark/answer-key.json` (in every benchmark repository)

```jsonc
{
  "schema": "https://github.com/code-assurance-initiative/scanner-benchmark/schema/answer-key.schema.json",
  "schemaVersion": "1.0",
  "repo": "code-assurance-initiative/bench-csharp-security-secrets",
  "keyVersion": "1.0.0",                 // matches the frozen git tag v<keyVersion>
  "languages": ["csharp"],
  "theme": "Hardcoded credentials and their look-alikes",
  "lineTolerance": 3,                    // optional, default 3
  "entries": [
    {
      "id": "SEC-001",                   // unique within the key, stable across versions
      "label": "must-fire",              // must-fire | must-not-fire | clean | not-applicable | score-band
      "concept": "hardcoded-credential", // id from taxonomy.json  (clean: use "concepts" instead)
      "cwe": "CWE-798",                  // optional; must equal the taxonomy's cwe when both exist
      "file": "src/Billing/PaymentClient.cs",   // omitted = repository-level
      "lines": [14, 14],                 // omitted with a file = whole file
      "rationale": "…why this is (or is not) a defect, in one or two sentences…",
      "scannerHints": { "watchdog": ["D13"] }   // optional, informative; the authoritative mapping is mappings/<scanner>.json
    },
    { "id": "CLN-001", "label": "clean", "concepts": "*", "file": "src/Billing/Invoice.cs", "rationale": "…" },
    { "id": "NA-001", "label": "not-applicable", "concept": "sql-injection", "rationale": "no database access" },
    { "id": "BND-001", "label": "score-band", "concept": "security-policy-present", "band": [80, 100], "rationale": "…" }
  ]
}
```

## `taxonomy.json`

Scanner-neutral concepts. `{ "version": "1.0", "concepts": [ { "id": "hardcoded-credential", "title": "…",
"cwe": "CWE-798" | null, "family": "security|codehealth|architecture|domain|testing|readiness|maturity|frontend|ops|compliance|ai",
"kind": "finding|posture|metric|judged", "description": "…" } ] }`. Ids are kebab-case and never reused.

## `mappings/<scanner>.json`

```jsonc
{
  "scanner": "watchdog",
  "version": "rubric-2026.10.1",
  "concepts": {
    "hardcoded-credential": {
      "rules": ["^D13$", "^D13[/.:-]"],   // regexes over the SARIF result's ruleId
      "dimensions": ["D13"]                 // the scanner's own grouping, for per-dimension reporting
    }
  },
  "ruleDimension": [ { "rule": "^(D\\d+)", "dimension": "$1" } ]  // ruleId → dimension for findings no concept claims
}
```

Note: bench repositories stay vendor-neutral, so they normally omit `scannerHints`; the harness mappings carry
scanner knowledge.

## Matching (mirrors kennel tools/multilang/matching.py semantics)

A SARIF result matches a located entry iff its ruleId matches one of the entry concept's `rules`, its path ends with
the entry's `file` (suffix-tolerant, `/`-normalised), and its startLine is within `lineTolerance` of `lines`. A
repository-level entry matches any result of the concept that has no location or whose location is outside every
located entry. One-to-one for `must-fire` (each entry consumes at most one result; extra results on the same site are
`redundant`, counted once and not as noise). `clean` entries match any result whose location falls inside the region,
for any concept listed (or any concept at all for `"*"`).

## Metrics (per concept, and per scanner dimension via the mapping)

- recall = TP / (TP + FN) over `must-fire`
- trap resistance = TN / (TN + FP) over `must-not-fire`
- noise = (results on `must-not-fire` + `clean` + `not-applicable`, and results matching no entry of a
  concept the key covers) / all results of covered concepts
- score-band: in/out per entry (scores supplied separately as `{concept|dimension: score}` JSON)

Results whose concept the key does not cover at all are reported as `uncovered`, never as noise.
