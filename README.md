# scanner-benchmark

A vendor-neutral benchmark for code scanners. A set of small, public, MIT-licensed repositories, each of which
contains **exactly** the defects its answer key says it contains, plus **traps** that look like defects and are not.
Run any scanner over them (SonarQube, CodeScene, Snyk, CodeQL, Semgrep, Watchdog, …), export SARIF, and this harness
measures, per concept and per scanner dimension:

- **recall** — planted defects found ÷ planted defects;
- **trap resistance** — traps left alone ÷ traps;
- **noise** — findings on traps, on certified-clean code, on not-applicable concepts, or matching nothing the key
  expects ÷ all findings of the concepts the key covers.

This repository holds the harness: the answer-key schema, the scanner-neutral concept taxonomy (CWE-anchored where a
CWE exists), one mapping per scanner, the scoring CLI, the registry of frozen benchmark repositories, and recorded
results. The fixed formats and the exact matching rules are in [`docs/CONTRACT.md`](docs/CONTRACT.md) (contract 1.4).

## Labels and outcomes

The answer key holds **labels**. TP / FP / TN / FN are **outcomes** of one scanner run against it.

| Label | Meaning | Scanner fires | Scanner silent |
|---|---|---|---|
| `must-fire` | a planted defect | TP | FN |
| `must-not-fire` | a trap: looks like a defect, is not | FP (caught in the trap) | TN |
| `clean` | a file/region certified defect-free for the listed concepts (or all: `"concepts": "*"`) | FP | TN |
| `not-applicable` | the concept has nothing to measure in this repository | FP | TN |
| `score-band` | a posture / metric / judged property: an expected score range, 0–100 | in band / out of band | — |

## Benchmark repositories

All under [`github.com/code-assurance-initiative`](https://github.com/code-assurance-initiative). C# and TypeScript
first. Each is one theme, small and idiomatic.

| Repository | Theme |
|---|---|
| `bench-csharp-baseline-clean` | a clean baseline: nothing to find |
| `bench-csharp-security-secrets` | hard-coded credentials and their look-alikes |
| `bench-csharp-security-injection` | injection |
| `bench-csharp-security-dependencies` | vulnerable dependencies |
| `bench-csharp-security-iac` | infrastructure-as-code |
| `bench-csharp-codehealth` | code health |
| `bench-csharp-architecture` | architecture |
| `bench-csharp-domain-events` | domain modelling, events, event sourcing |
| `bench-csharp-readiness` | operational readiness |
| `bench-csharp-maturity-history` | scripted git history, ADRs, docs |
| `bench-csharp-tests` | build and tests |
| `bench-ts-baseline-clean` | a clean baseline: nothing to find |
| `bench-ts-security-secrets` | hard-coded credentials and their look-alikes |
| `bench-ts-security-injection` | injection |
| `bench-ts-security-dependencies` | vulnerable dependencies |
| `bench-ts-frontend-a11y` | front-end accessibility |
| `bench-ts-codehealth` | code health |
| `estate-<company>-<service>` ×4–6 | a reference estate: a fictional company's services, scored at integration level |

Frozen versions are listed in [`registry.json`](registry.json) with their tag, commit and the sha256 of their answer
key. Only a registered (repo, tag, keySha256) is a benchmark result; anything else is a work in progress.

Every benchmark repository carries `benchmark/answer-key.json` (the labels, schema
[`schema/answer-key.schema.json`](schema/answer-key.schema.json)), `benchmark/README.md` (the theme, what is planted,
what the traps are and why), `benchmark/journal.md` (the authoring log) and an MIT `LICENSE`. Planted secrets are
generated fakes in a real-looking format that cannot authenticate anything.

## Scoring a scanner run

Python 3, standard library only.

```sh
# 1. scan a checkout of the benchmark repo at its registered tag, with SARIF 2.1.0 output
git clone --branch v1.0.0 https://github.com/code-assurance-initiative/bench-csharp-security-secrets
<your scanner> … --format sarif --output report.sarif

# 2. score it
python3 -m cai_bench score \
    --key bench-csharp-security-secrets/benchmark/answer-key.json \
    --sarif report.sarif \
    --mapping mappings/<scanner>.json \
    [--scores scores.json] [--repo-root-prefix /abs/path/of/checkout] [--json report.json] \
    [--configuration-label "<non-default configuration>"]
```

`score` prints a per-concept and a per-scanner-dimension table (recall, trap resistance, noise, TP/FN/FP/TN,
redundant, uncovered) and lists every entry that went wrong. `--json` writes the full report, including every
individual outcome — each key entry with the result(s) it matched, and each SARIF result (run and result index,
ruleId, file, line) with its outcome — so a reader can audit every number.

- Result paths may be relative, absolute or `file://` URIs. Each is made **repository-relative** — a relative uri is
  taken as relative to the repository root; SARIF `uriBaseId`s are resolved through `originalUriBaseIds`; an absolute
  path loses a `--repo-root-prefix`, the `/src` container mount or everything up to the checkout directory named
  after the repository — and then compared with the key's path **exactly**, so `tools/x/.nvmrc` never matches a
  plant at the root `.nvmrc`. Only a path that cannot be made repo-relative (an absolute path under an unknown root,
  a site read out of a message) falls back to suffix matching; each result records `pathMatch: exact | suffix`. A
  result without a location is repository-level.
- A concept no rule of the scanner detects is still a concept: the mapping lists it under `unmapped` (or omits it),
  and its plants are false negatives — real defects the scanner cannot see. The report lists them as
  `unmappedConcepts` and in a `(no scanner rule)` dimension row.
- A location-less row the mapping declares a summary of its concept (`summaryOfConcept`, e.g. "not all async methods
  take a cancellation token") does not find a plant at a located site — it does not say where — and is not noise; the
  report lists it under `summaryOfConcept` beside the plants it summarises.
- A result's concept comes from the scanner mapping: `mappings/<scanner>.json` maps each concept to regexes over the
  SARIF `ruleId`, narrowed where one rule id carries several concepts by regexes over the message text and by
  required result properties. Scanner roll-up rows can be listed under `ignore` and are reported as `summary`, in no
  metric. A scanner with no mapping file cannot be scored — write one first.
- A result carrying SARIF `properties.commitSha` is a history finding; an entry with `commit` matches it by commit
  in the same file, at any line.
- `score-band` entries need `--scores`, a JSON object `{ "<concept or scanner dimension>": <0–100> }`. An entry with
  no score is reported `unscored`.
- Results of concepts the key does not cover are reported as **uncovered** and never counted as noise. A second
  result on an already-found plant is **redundant**: it is neither a hit nor noise.

### Default and secondary configurations

The headline numbers of a scanner are those of its **default configuration** — what a user gets without switching
anything on. A run with a non-default configuration (a compliance framework enabled, an extra rule pack, a stricter
profile) is a **secondary run**: score it with `--configuration-label "<what was switched on>"`, which stamps the JSON
report `"configuration": {"label": …, "headline": false}` (a default run carries `{"label": "default", "headline":
true}`), and record it in the results file's `scans[]` with a `configuration` object (e.g. `{"label": "wcag-2.2",
"env": {"CODEHEALTH_COMPLIANCE_FRAMEWORKS": "wcag-2.2"}}`). Secondary runs are reported beside the headline, never
merged into it; a concept a scanner measures only in a non-default configuration is "not measured" in the headline.

Other commands:

```sh
python3 -m cai_bench validate --key benchmark/answer-key.json --taxonomy taxonomy.json   # exit 1 + one line per problem
python3 -m cai_bench sha256   --key benchmark/answer-key.json                           # for registry.json
python3 -m unittest                                                                     # the harness's own tests
```

## Adding a benchmark repository

1. **Answer key first.** Write `benchmark/answer-key.json` and `benchmark/README.md` before the code, and validate
   the key (`validate --taxonomy taxonomy.json`). New concepts go into `taxonomy.json` first, with their CWE when one
   exists.
2. **Implement** small, realistic code that contains exactly the planted defects and traps.
3. **Scan** with at least one scanner and **triage every finding that is not an expected hit**, writing each verdict
   down in `benchmark/journal.md`:
   - the scanner is right (a defect was planted by accident) → **fix the repository** so it disappears;
   - the scanner is wrong → keep the code and record the noise; a good site may become a `must-not-fire` trap.
4. **Check every missed `must-fire`**: if the plant is wrong, fix the plant (journal it); if it is real, it is the
   scanner's false negative — record it and **keep the label**.
5. Repeat until the repository holds only what its key says and every `clean` region is clean.
6. **Freeze**: tag `v<keyVersion>`, then add `{ "repo", "tag", "commit", "keySha256", "frozenAt" }` to
   `registry.json`.

## Integrity rules

- **Never select on the outcome.** A label is never dropped, moved or weakened because a scanner misses it or fires on
  it. A repository is never tuned to make a scanner look good: fixing an accidental *real* defect is allowed, hiding a
  trap is not.
- **A key change after freeze is a new version.** A frozen tag and its registered key hash are never edited in
  place; a change ships as `v1.1.0` (or later) with a new registry entry and a journal entry saying why.
- **Every verdict is written down** with its reason, so any number can be traced back to the labels and the findings
  it was computed from.
- Recorded results for a scanner live under `results/<scanner>/`. They never feed back into the keys except through
  the authoring loop above, before freeze.

## Layout

```
docs/CONTRACT.md                   fixed formats, matching and metric semantics (v1)
schema/answer-key.schema.json      JSON Schema (draft 2020-12) for benchmark/answer-key.json
taxonomy.json                      scanner-neutral concepts
mappings/<scanner>.json            concept -> the scanner's rule ids and dimensions
registry.json                      frozen benchmark repositories
results/<scanner>/                 recorded results per scanner
cai_bench/                         the CLI (python3 -m cai_bench)
tests/                             its tests, with fixture keys, SARIF, taxonomy and mapping
```

## License

MIT — see [`LICENSE`](LICENSE).
