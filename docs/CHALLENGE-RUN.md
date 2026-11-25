# Running a challenge window

How an engine is submitted and run in a benchmark challenge window. The scheme it implements is
[ENGINE-QUALIFICATION.md](https://github.com/code-assurance-initiative/CodeAssuranceIndex/blob/main/docs/ENGINE-QUALIFICATION.md);
the calendar is [challenge/calendar.json](../challenge/calendar.json), and a daily workflow announces each window at
least 30 days ahead.

## What the container must do

The engine is submitted as an OCI image, referenced by digest. For each holdout unit the operator runs:

```
docker run --rm --network none --read-only --tmpfs /tmp \
  -v <unit checkout>:/src:ro -v <out dir>:/out <image@digest>
```

- Read the repository at `/src` (a full git checkout, history included, at the unit's frozen tag).
- Write `/out/results.sarif` (SARIF 2.1.0). Paths repository-relative; history findings carry
  `properties.commitSha` ([CONTRACT.md](CONTRACT.md)).
- Optionally write `/out/scores.json` (`{ "<concept or dimension>": 0-100 }`) for score-band entries.
- No network. Data the engine needs (a vulnerability database, a licence list) is either inside the image or supplied
  by the operator as the same fixed snapshot for every participant, mounted read-only at `/data`.
- Exit 0 on success. A unit the engine fails on is scored as an empty result, not skipped.

## The window

1. **Registration** (from the announcement until it closes): a `register-engine` issue per engine — image digest,
   configuration label, mapping, declared interests. The mapping goes into `mappings/` by pull request, and its sha256
   is recorded. Nothing changes after registration closes.
2. **Open:** the operators materialise each sealed unit, check it against the hashes published in
   [registry.json](../registry.json) (`preregistrations[].contentCommitment`), run every registered image once per unit
   as above, and score with `cai_bench`. Engines that are not deterministic get one run, with the configuration
   recorded.
3. **Reveal:** the holdout (units, answer keys, authoring log), the raw SARIF and the scores of every engine are
   published together under `results/`. Anyone can check them against the sealed hashes.
4. **Disputes:** for 30 days after reveal anyone may dispute an answer-key entry, and a scanner's owner may dispute
   an entry for 30 days after its own verdict is published. A corrected entry gets a new key version and every
   engine's result in the window is rescored against it, published beside the original. Who files and how, what
   counts as evidence, who decides and every outcome: [disputes/README.md](../disputes/README.md), the process adopted
   by [CAI decision 0001](https://github.com/code-assurance-initiative/CodeAssuranceIndex/blob/main/docs/decisions/0001-adopt-the-answer-key-dispute-path.md).
5. **Release:** the revealed holdout joins the public training set.

## The engine report

[CAI decision 0024](https://github.com/code-assurance-initiative/CodeAssuranceIndex/blob/main/docs/decisions/0024-a-definition-says-what-not-how.md)
§3 makes CAI's own run of each window the measurement that counts for an engine that publishes CAI or is registered
to be measured, from the first window whose holdout covers the languages that decision names (every language in the
platform family of each language such an engine supports, where a platform family is the languages of one platform:
.NET is C#, F# and Visual Basic .NET, the JVM is Java, Kotlin and Scala, BEAM is Erlang and Elixir, Apple is Swift and
Objective-C, and every other language is a family of one; the web front of JavaScript, TypeScript, HTML and CSS, and
C, C++, Objective-C and R; planned for the first window of 2027). Until then the reports below are provisional
figures, with no pass, grade or ceiling.

The operators score every unit with `cai_bench score --json`, then compute the engine's report for the window:

```sh
python3 -m cai_bench engine-report --manifest window.json --seed <published seed> --json results/<engine>/<window>.json
```

`window.json` is published beside the window file, with every unit's score report, so anyone can recompute both:

```json
{"window": "2027-q1",
 "engine": {"name": "<engine>", "supportedLanguages": ["csharp", "typescript"],
            "declaredCells": [["D1", "csharp"], ["D1", "typescript"]]},
 "applicableCells": [["D1", "csharp"], ["D1", "typescript"], ["D2", "csharp"]],
 "units": [{"report": "scores/<unit>.json", "language": "csharp"}]}
```

Only **scored** dimensions count: those the rubric catalog does not declare advisory, whatever an evidence bundle
marks (ENGINE-QUALIFICATION.md). `applicableCells` are the cells of scored dimensions that apply, by their dimension
pages, to the engine's supported languages. A declared cell counts only if it is also in `applicableCells`; a
declared cell outside them (an advisory dimension, a dimension whose page does not cover that language, or a language
the engine does not list as supported) is listed apart in the window file and counts neither in the score nor in
coverage. Each unit's score report gives, per dimension, `tp` (planted defects the engine found), `fn` (planted
defects it missed), `results` (its findings of that dimension) and `noise` (those of them that hit a trap,
certified-clean code or a not-applicable concept, or match nothing the answer key expects), as the matching rules of
[CONTRACT.md](CONTRACT.md) define them.

- **Per cell:** the units of that language are pooled; recall `R` = tp ÷ (tp + fn); precision `P` = 1 − noise ÷
  results; then `F0.5 = 100 × 1.25 · P · R / (0.25 · P + R)`. A declared cell where the engine reports nothing, or
  only noise, scores 0. A cell in which the holdout plants no defect has no F0.5 and is listed apart with its trap
  resistance (traps left alone ÷ traps); it counts neither in the mean nor in coverage. A dimension measured only by
  score bands has no cell here; its band agreement is in each unit's score report.
- **The engine score:** the unweighted mean of the F0.5 of the declared applicable cells in which the holdout plants
  defects, with **coverage** beside it: those cells ÷ all applicable cells in which the holdout plants defects.
- **Its 95 % interval:** a percentile bootstrap that resamples the units within each supported language 10,000
  times, with the seed published in the window file; with the manifest and the unit reports it reproduces exactly.
- **Languages the engine does not support** are reported beside the score, never in it.

The window files of an engine, read together (`cai_bench.engine_report.history`), give each cell's noise, recall and
F0.5 per window: the trend its report page draws. A window in which a cell was not declared, or had no planted
defect, is a gap in that cell's series, never a zero.

## Today

Announcement, registration and the calendar are automated. Opening and revealing are run by the operators by this
procedure; automating them on a self-hosted runner is the next step.
