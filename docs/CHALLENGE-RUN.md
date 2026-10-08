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
4. **Disputes:** for 30 days after reveal anyone may dispute an answer-key entry. A corrected entry gets a new key
   version and every engine's result in the window is rescored against it.
5. **Release:** the revealed holdout joins the public training set.

## Today

Announcement, registration and the calendar are automated. Opening and revealing are run by the operators by this
procedure; automating them on a self-hosted runner is the next step.
