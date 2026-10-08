# scanner-benchmark

A vendor-neutral benchmark for code scanners. A set of small, public, MIT-licensed code repositories ("units", held
together in the training set
[`training-set-2026`](https://github.com/code-assurance-initiative/training-set-2026)), each of which contains **exactly** the defects its answer key says it contains, plus **traps** that look like defects and are not.
Run any scanner over them (SonarQube, CodeScene, Snyk, CodeQL, Semgrep, Watchdog, …), export SARIF, and this harness
measures, per concept and per scanner dimension:

- **recall** — planted defects found ÷ planted defects;
- **trap resistance** — traps left alone ÷ traps;
- **noise** — findings on traps, on certified-clean code, on not-applicable concepts, or matching nothing the key
  expects ÷ all findings of the concepts the key covers.

This repository holds the harness: the answer-key schema, the scanner-neutral concept taxonomy (CWE-anchored where a
CWE exists), one mapping per scanner, the scoring CLI, the registry of frozen benchmark units, and recorded
results. The units themselves are in the training set. The fixed formats and the exact matching rules are in [`docs/CONTRACT.md`](docs/CONTRACT.md) (contract 1.6).

## The benchmark challenge

Every quarter a sealed holdout is opened for any engine that registers: one offline run per engine, every result
published, the holdout revealed afterwards. The calendar is [challenge/calendar.json](challenge/calendar.json), each
window is announced here at least 30 days ahead, and how to take part is in [docs/CHALLENGE-RUN.md](docs/CHALLENGE-RUN.md).

## Labels and outcomes

The answer key holds **labels**. TP / FP / TN / FN are **outcomes** of one scanner run against it.

| Label | Meaning | Scanner fires | Scanner silent |
|---|---|---|---|
| `must-fire` | a planted defect | TP | FN |
| `must-not-fire` | a trap: looks like a defect, is not | FP (caught in the trap) | TN |
| `clean` | a file/region certified defect-free for the listed concepts (or all: `"concepts": "*"`) | FP | TN |
| `not-applicable` | the concept has nothing to measure in this repository | FP | TN |
| `score-band` | a posture / metric / judged property: an expected score range, 0–100 | in band / out of band | — |

## Benchmark units

The benchmark units live in ONE repository, the **training set**
[`code-assurance-initiative/training-set-2026`](https://github.com/code-assurance-initiative/training-set-2026): 25
units, C# and TypeScript, each one theme, small and idiomatic, labelled against rubric generation `rubric-2026.10.1`.
Each unit is a git bundle there (`units/<unit>.bundle`: full history, every tag — several units measure history) with a
readable snapshot of its latest tag (`units/<unit>/`); the set's `tools/materialize.sh` turns a bundle into a
freestanding clone to scan. The units were authored as separate repositories named as the unit (the names below stay
the unit ids, and the `repo` field of each frozen key); the bundles are now the canonical copy, the `bench-*`
repositories are retired, and the `estate-quellbrook-*` repositories stay live for other uses. The five `estate-quellbrook-*`
units are a reference estate — the services of one fictional company (Quellbrook Freight), with Dockerfiles, Kubernetes
manifests, CI, ADRs and about three sprints of scripted history — scored at integration level. The tag below is the
LATEST registered one; earlier tags stay registered and valid, and are in the bundles.

| Unit | Language | Latest tag | Theme |
|---|---|---|---|
| [`bench-csharp-baseline-clean`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-baseline-clean) | C# | v1.0.0 | certified-clean control: nothing planted, traps only |
| [`bench-csharp-security-secrets`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-security-secrets) | C# | v1.0.0 | hard-coded secrets and their look-alikes (incl. git history) |
| [`bench-csharp-security-injection`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-security-injection) | C# | v1.0.0 | injection and unsafe input handling |
| [`bench-csharp-security-dependencies`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-security-dependencies) | C# | v1.1.0 | vulnerable, deprecated, outdated, copyleft and end-of-life dependencies |
| [`bench-csharp-security-iac`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-security-iac) | C# | v1.2.0 | Kubernetes, Dockerfile, compose, Terraform and CI-workflow security |
| [`bench-csharp-codehealth`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-codehealth) | C# | v1.0.0 | code health |
| [`bench-csharp-architecture`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-architecture) | C# | v1.1.0 | architecture and structure in a multi-project solution |
| [`bench-csharp-domain-events`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-domain-events) | C# | v1.1.1 | domain modelling, messaging and event sourcing |
| [`bench-csharp-readiness`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-readiness) | C# | v1.0.0 | production readiness of an API + worker |
| [`bench-csharp-maturity-history`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-maturity-history) | C# | v1.0.0 | scripted git history (hotspots, silos, coupling), ADRs and documentation drift |
| [`bench-csharp-tests`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-tests) | C# | v1.0.0 | test-suite quality |
| [`bench-csharp-blazor-a11y`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-csharp-blazor-a11y) | C# | v1.0.0 | Blazor / Razor Pages accessibility and JS-interop correctness |
| [`bench-ts-baseline-clean`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-ts-baseline-clean) | TypeScript | v1.0.0 | certified-clean control: nothing planted, traps only |
| [`bench-ts-security-secrets`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-ts-security-secrets) | TypeScript | v1.0.0 | hard-coded secrets and their look-alikes |
| [`bench-ts-security-injection`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-ts-security-injection) | TypeScript | v1.0.0 | injection and unsafe input handling |
| [`bench-ts-security-dependencies`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-ts-security-dependencies) | TypeScript | v1.0.0 | npm dependency risk, incl. unused / undeclared / misplaced packages |
| [`bench-ts-codehealth`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-ts-codehealth) | TypeScript | v1.0.0 | code health |
| [`bench-ts-frontend-a11y`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-ts-frontend-a11y) | TypeScript | v1.1.0 | React front-end quality and accessibility |
| [`bench-ts-domain-privacy`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-ts-domain-privacy) | TypeScript | v1.0.1 | domain modelling, vertical slices and personal-data handling |
| [`bench-ts-readiness`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/bench-ts-readiness) | TypeScript | v1.0.0 | production readiness of an npm-workspaces monorepo on Kubernetes |
| [`estate-quellbrook-gateway`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/estate-quellbrook-gateway) | TypeScript | v1.0.0 | reference estate: API gateway / BFF (Fastify) |
| [`estate-quellbrook-orders`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/estate-quellbrook-orders) | C# | v1.0.0 | reference estate: order service (DDD, outbox) |
| [`estate-quellbrook-dispatch`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/estate-quellbrook-dispatch) | C# | v1.0.0 | reference estate: dispatch service — carries the estate's regression |
| [`estate-quellbrook-notifier`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/estate-quellbrook-notifier) | C# | v1.0.0 | reference estate: notifier worker — carries the secret left in history |
| [`estate-quellbrook-web`](https://github.com/code-assurance-initiative/training-set-2026/tree/main/units/estate-quellbrook-web) | TypeScript | v1.0.0 | reference estate: operator web front end (React + Vite) |

Frozen versions are listed in [`registry.json`](registry.json) with their tag, commit, the sha256 of their answer
key and their `source` (the training set and the bundle that holds them). Only a registered (repo, tag, keySha256) is
a benchmark result; anything else is a work in progress. Every tool here that reads a key (`results/watchdog/rescore.py`,
`results/watchdog/baseline.py`, `mappings/watchdog-build/build.py`) reads it through `cai_bench/units.py`: from
materialised units (`--units-dir` / `BENCH_UNITS_DIR`), else from the set's bundles (`--set-dir` / `BENCH_SET_DIR`,
default a `training-set-2026` checkout next to this one), else from a legacy clone — always sha256-checked.

Every benchmark unit carries `benchmark/answer-key.json` (the labels, schema
[`schema/answer-key.schema.json`](schema/answer-key.schema.json)), `benchmark/README.md` (the theme, what is planted,
what the traps are and why), `benchmark/journal.md` (the authoring log) and an MIT `LICENSE`. Planted secrets are
generated fakes in a real-looking format that cannot authenticate anything.

## Scoring a scanner run

Python 3, standard library only.

```sh
# 1. materialise the unit from the training set (full history, at its latest registered tag) and scan it,
#    with SARIF 2.1.0 output
git clone https://github.com/code-assurance-initiative/training-set-2026
training-set-2026/tools/materialize.sh bench-csharp-security-secrets units     # -> units/bench-csharp-security-secrets
<your scanner> units/bench-csharp-security-secrets … --format sarif --output report.sarif

# 2. score it
python3 -m cai_bench score \
    --key units/bench-csharp-security-secrets/benchmark/answer-key.json \
    --sarif report.sarif \
    --mapping mappings/<scanner>.json \
    [--scores scores.json] [--repo-root-prefix /abs/path/of/checkout] [--json report.json] \
    [--repo-dir units/bench-csharp-security-secrets] [--configuration-label "<non-default configuration>"]
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
- `--repo-dir` is the scanned checkout (the materialised unit at the key's tag). Contract 1.6 reads IaC resource
  boundaries from its files — a YAML document, a Dockerfile build stage, a top-level HCL block — so that an absence-type
  IaC concept (no limits, no probes, no securityContext, no USER, no HEALTHCHECK) reported anywhere in the entry's
  resource is on the entry's site. Without it those entries keep the line rule and say `resource-unavailable`.
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
python3 -m cai_bench compare  --baseline results/watchdog/baseline-2026-10-07.json \
                              --current <new final-scores.json> [--all] [--json delta.json]  # deltas vs a baseline
python3 -m unittest                                                                     # the harness's own tests
```

### Reproducing a recorded score

Every recorded number can be recomputed from public inputs. For a registry entry `(repo, tag, keySha256)`:

```sh
training-set-2026/tools/verify.sh <repo>                                  # bundle, tags, key hashes vs the set registry
training-set-2026/tools/materialize.sh <repo> units --tag <tag>          # a freestanding clone named <repo>
python3 -m cai_bench sha256 --key units/<repo>/benchmark/answer-key.json # must equal keySha256 in registry.json
<scanner> units/<repo> --format sarif --output report.sarif              # sha256 of the SARIF scored is recorded
python3 -m cai_bench score --key units/<repo>/benchmark/answer-key.json --sarif report.sarif \
    --mapping mappings/<scanner>.json --scores scores.json --repo-dir units/<repo> --json report.json
```

For all 25 units at once — materialise, scan, re-score, compare — follow
[BASELINE-2026-10-07 § 11](results/watchdog/BASELINE-2026-10-07.md#11-re-measuring-against-this-baseline).

For the recorded Watchdog results, `results/watchdog/final-scores.json` gives per repository the tag, commit, key
sha256, the `sarifSha256` of the scan that was scored and the full outcome; a SARIF with that hash scored with the
command above reproduces the row (score bands need the scanner's dimension scores, made by
`mappings/watchdog_scores.py <scan>/scorecard.json`). `python3 results/watchdog/summarise.py` rebuilds
`SUMMARY.json` from `final-scores.json`.

## Results

- [`results/watchdog/SUMMARY.md`](results/watchdog/SUMMARY.md) — Watchdog over all 25 repositories at their latest
  tags: headline recall / trap resistance / noise per repository, language and family; per dimension; the general
  false-negative and noise mechanisms; instrument notes and method lessons. Machine-readable:
  [`SUMMARY.json`](results/watchdog/SUMMARY.json), [`final-scores.json`](results/watchdog/final-scores.json);
  per-repository verdicts in `results/watchdog/<repo>.json`.
- [`results/watchdog/BASELINE-2026-10-07.md`](results/watchdog/BASELINE-2026-10-07.md) — the frozen **iteration-1
  baseline** of Watchdog before any improvement work: per lens, per dimension (one table per lens), per repository,
  recall gaps and noise by mechanism (with backlog ids), score bands, model non-determinism, and how to re-measure a
  new engine against it (`results/watchdog/rescore.py` + `python3 -m cai_bench compare`). Machine-readable:
  [`baseline-2026-10-07.json`](results/watchdog/baseline-2026-10-07.json).
- [`results/cai-reference/COMPARISON-TRAINING.md`](results/cai-reference/COMPARISON-TRAINING.md) — the CAI reference
  implementation (C#/.NET) over the 15 C# units, scored by the same harness 1.6 as Watchdog and set beside it: headline,
  per lens, per dimension, mechanisms, and a reproduction of its self-reported numbers. **In-sample for that engine**,
  which was calibrated on these units (see the caveat there). Mapping: `mappings/cai-reference.json` (its generated
  mapping plus the taxonomy's parents, `mappings/cai-reference-build/`).
- [`coverage/MATRIX.md`](coverage/MATRIX.md) — every Watchdog dimension, whether it is in scope, and which frozen
  repositories label it (read from their keys at the registered tags).

## Adding a benchmark unit, a new set or a holdout

A unit is authored as an ordinary git repository — a local repository outside any other git tree (or a temporary
GitHub repository when CI or Dependabot behaviour is part of the theme) — and only then bundled into a set. The loop
is in [`docs/AUTHORING.md`](docs/AUTHORING.md):

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
6. **Freeze**: tag `v<keyVersion>`, then add `{ "repo", "tag", "commit", "keySha256", "frozenAt", "source" }` to
   `registry.json`.
7. **Bundle into the set**: `git fetch --tags && git bundle create <set>/units/<unit>.bundle --all`, run the set's
   `tools/build_set.py` (verifies every registered tag and key hash from the bundle, writes the snapshot, the set
   registry and the README table) and `tools/verify.sh`, commit, and tag a new set version. A temporary GitHub
   repository is deleted once its bundle is verified.

Sets: one **training set per rubric generation** (`training-set-2026`, then `training-set-2027`, …) — a new rubric
generation is a new set repository, never a rewrite of an old one — and **private quarterly holdouts**
(`holdout-2026-q4`, …) in the same format, whose units are not published while the holdout is in use.

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
docs/CONTRACT.md                   fixed formats, matching and metric semantics (v1.6)
schema/answer-key.schema.json      JSON Schema (draft 2020-12) for benchmark/answer-key.json
taxonomy.json                      scanner-neutral concepts
mappings/<scanner>.json            concept -> the scanner's rule ids and dimensions
registry.json                      frozen benchmark units (unit id, tag, commit, keySha256, source bundle in the set)
coverage/                          coverage matrix (matrix.json, MATRIX.md, render_matrix.py)
results/<scanner>/                 recorded results per scanner (watchdog: SUMMARY.md, BASELINE-*.md + baseline-*.json, final-scores.json, <repo>.json)
cai_bench/                         the CLI (python3 -m cai_bench); cai_bench/units.py reads a key from the set
tests/                             its tests, with fixture keys, SARIF, taxonomy and mapping
```

## License

MIT — see [`LICENSE`](LICENSE).
