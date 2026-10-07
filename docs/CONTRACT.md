# Harness contract (v1.3)

The fixed interfaces between the parts of this harness. Change only with a version bump.

## What changed in 1.3 (2026-10-07) — backward compatible

Three finished results files (bench-csharp-security-injection, -iac, -dependencies) showed three gaps. A scanner that
names a workflow finding's site only in its message (`release.yml:7`) could never match a located plant. A coarse
concept let an unrelated row score a plant: a registry allow-list result on the container line was a TP for the
missing-probes plant because both were `iac-misconfiguration`. And a scanner that reports a resource at line 1 for a
plant at line 71 was only visible as an FN, never as "found the file, missed the line". 1.3 adds, all optional — every
valid 1.0/1.1/1.2 key and mapping means the same under 1.3, and the answer-key format is unchanged:

- **mapping** — `locationFromMessage` (mapping level): regexes that read a location-less result's site out of its
  message (see Matching, "Location from the message"); per concept `parent` naming its umbrella concept (see Matching,
  "Umbrella concepts").
- **taxonomy** — a concept may carry `parent`: the umbrella concept it refines.
- **metrics** — file-level recall, a SECONDARY diagnostic beside recall (see Metrics). It changes no outcome.
- **report** — each result carries `locationSource` (`sarif` | `message` | `none`), the summary carries
  `locationSources` (how many results took each), each must-fire entry row carries `fileLevel`, and every counts row
  carries `fileLevelTp` and `fileLevelRecall`. The text table has a `fileRec*` column with its footnote.

Watchdog mapping changes shipped with 1.3 (mapping data, no contract impact of their own): `weak-hash-algorithm` and
`insufficient-password-hashing` are one family (`weak-password-hashing`); `watchdog-secret-interpolated-into-run` maps to
`secret-in-process-arguments` (its own CWE-214; a secret expanded into a run script reaches the script file and the argv
of the commands it launches, and no untrusted code receives it, which is what `ci-secret-exposure` denotes — the two are
deliberately NOT a family); new concept `log-injection` (CWE-117) evidenced by D29 `crlf-injection-logs`; and
`container-excessive-privilege` / `iac-misconfiguration` became umbrellas over fifteen precise concepts.

## What changed in 1.2 (2026-10-07) — backward compatible

A dependency scan showed that dependency, licence, vulnerability and end-of-life scanners often report per PACKAGE,
with no file or line: such a result could only match a repository-level entry, so a scanner that found 7 of 8 planted
dependency defects scored 0 % recall. And a score band for lockfiles took the score of a dimension dominated by
vulnerable packages. 1.2 adds, all optional — every valid 1.0/1.1 key and mapping means the same under 1.2:

- **answer key** — `schemaVersion` may be `"1.2"`; a `must-fire`, `must-not-fire` or `clean` entry may carry
  `subject` (a non-empty string: a NuGet/npm/… package id, or a framework moniker such as `net6.0`).
- **matching** — an entry with a `subject` also matches a location-less (or manifest-located) result of its concept
  whose message names the subject as a whole token (see Matching, "Subjects").
- **mapping** — per concept `scoreDimensions`: the dimensions whose score measures the concept, used for score-band
  lookup when `dimensions` (finding attribution) is broader.
- **report** — an entry row carries its `subject`.

## What changed in 1.1 (2026-10-07) — backward compatible

A real scan showed that one scanner rule id can carry several concepts (a dimension-level ruleId covering secrets,
dependency-bot configuration and injection alike), so a Dockerfile "no HEALTHCHECK" result was scored as
hard-coded-credential noise. 1.1 adds, all optional — every valid 1.0 key and mapping means the same under 1.1:

- **mapping** — per concept `messages` (message-text regexes) and `properties` (required SARIF result properties);
  rule items may be objects carrying their own conditions; a mapping-level `ignore` list whose results are
  `summary` rows (in no metric); `family` to group sibling concepts.
- **answer key** — `schemaVersion` may be `"1.1"`; an entry may carry `commit` (pins a history finding to a commit).
- **matching** — concept families (siblings match plants and traps after exact matches); `commit` entries.
- **report** — each result carries `commitSha` (SARIF `properties.commitSha`) and, for a summary row, `ignoreReason`.

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
  "schemaVersion": "1.2",                // "1.0", "1.1" or "1.2"
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
      // "commit": "e920ad5",            // 1.1, optional, must-fire/must-not-fire only, needs file: see Matching
      // "subject": "Newtonsoft.Json",   // 1.2, optional, must-fire/must-not-fire/clean only: see Matching, Subjects
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
"kind": "finding|posture|metric|judged", "description": "…", "parent": "…" } ] }`. Ids are kebab-case and never reused
(so an id is never removed either: a concept that turns out too coarse becomes an umbrella).

`parent` (1.3, optional) names the UMBRELLA concept this one refines (one level deep). The umbrella stays a concept: as a
concept of its own it denotes what none of its children names (its residue), and an answer-key entry written against it
keeps its meaning (see Matching, "Umbrella concepts"). New keys name the precise concept.

## `mappings/<scanner>.json`

```jsonc
{
  "scanner": "watchdog",
  "version": "rubric-2026.10.1",
  "concepts": {
    "hardcoded-credential": {
      "rules": [                            // a result belongs to the concept if ANY rule item accepts it
        "^D13$",                            // a regex over the SARIF result's ruleId …
        { "rule": "^D31$",                  // … or (1.1) an object whose own conditions replace the concept-level ones
          "messages": ["^\\w+ IaC: DS-0031:"] }
      ],
      "messages": ["^Leaked secret: (?:aws-access-key|github-token):"],  // 1.1, optional, applies to string rules
      "properties": ["commitSha"],          // 1.1, optional: these SARIF result properties must be present (non-null)
      "family": "hardcoded-secret",         // 1.1, optional: sibling concepts (see Matching)
      "dimensions": ["D13", "D31"]          // the scanner's own grouping, for per-dimension reporting
    },
    "privileged-container": {
      "rules": [ … ],
      "dimensions": ["D31"],
      "parent": "container-excessive-privilege"  // 1.3, optional: the umbrella concept (see Matching)
    },
    "dependencies-not-locked": {
      "rules": [ … ],
      "dimensions": ["D12", "D36", "SC1"],  // findings of all three are attributed to the concept …
      "scoreDimensions": ["SC1"]            // 1.2, optional: … but only SC1's score measures it (see Metrics)
    }
  },
  "ruleDimension": [ { "rule": "^(D\\d+)", "dimension": "$1" } ],  // ruleId → dimension
  "ignore": [                               // 1.1, optional: scanner roll-up rows
    { "rule": "^D28$", "message": "^Rotate the exposed credentials", "reason": "roll-up of the located rows" }
  ],
  "locationFromMessage": [                  // 1.3, optional: sites named only in the message
    { "rule": "^D36$",                      // regex over the ruleId (required)
      "message": "^Secret passed as",       // optional regex over the message (case-insensitive search)
      "pattern": "(?P<file>[\\w./-]+\\.ya?ml):(?P<line>\\d+)",  // Python regex: named group `file` required, `line` optional
      "source": "…" }                       // informational
  ]
}
```

`parent` names another concept of the mapping (no cycles); it should mirror the taxonomy's `parent`. Children are
mapped so that each result still lands on ONE concept: the umbrella's own rules keep only the residue no child names.

`locationFromMessage` entries are tried in order on every result that has **no SARIF location** (no artifact URI): the
first entry whose `rule` (and `message`, if given) matches and whose `pattern` finds a match gives the result the
`file` group as its path (normalised like a SARIF URI, then matched by the suffix rule) and the `line` group, when the
pattern has one and it is a positive integer, as its line; without a line the result is located in the file only, so it
matches whole-file entries and file-level recall, never a lined entry. A result with a SARIF location is never
relocated. This is scanner-specific knowledge and deliberately generous: a scanner that names a location only in prose
is given the benefit of that location, and the report says so (`locationSource: "message"`, `summary.locationSources`)
so a reader can tell such matches from located ones. A message that names several sites gives the first one.

A rule item accepts a result when its ruleId matches the rule regex, AND — if `messages` apply to it — at least one
`messages` regex matches the result's `message.text` (case-insensitive search), AND — if `properties` apply — every
named property is present in the result's `properties` bag. An object rule item's own `messages` / `properties`
replace the concept-level ones for that item (one concept often spans several scanner rules whose messages have
different formats); a string rule uses the concept-level ones. With neither, the ruleId alone decides (1.0).

An `ignore` entry matches a result when every regex it gives matches (`rule` over the ruleId, `message` over the
message text, case-insensitive); it needs at least one. Such a result is a `summary` row: listed in the report with
its reason, never matched, and counted in no metric — not as a hit, not as noise, not as uncovered. Use it only for
rows that restate other rows (roll-ups, totals), and give the reason.

`family` here is a mapping-level grouping of concepts one scanner may confuse with each other (e.g. a credential
reported under a sibling secret type). It is unrelated to the taxonomy's `family` field.

A mapping may also carry informational keys that the harness ignores: `notes` (prose), `offConcept`
(`[{rule, message, source}]`: results the scanner really emits under a rule that denote none of the concepts mapped
to it, so they map to no concept; recorded so the omission is visibly deliberate) and `unevidenced`
(`[{concept, dimension, source}]`: a dimension listed for a concept although none of its results evidences it at
this scanner version, so it has no rule item). They change no outcome, so they need no version bump.

**Watchdog `locationFromMessage` (1.3).** D36's workflow rows (token permissions, secrets in env, advisory schedule,
release gates) are written without a location but name `basename:line` sites; secret-argv rows name the workflow path
only. Two entries cover them (`mappings/watchdog-build/discrim.py`, `LOCATION_FROM_MESSAGE`). A basename suffix-matches
every file of that name, so two workflows of one name in different directories would both match it.

**Watchdog umbrellas (1.3).** `container-excessive-privilege` is the parent of `container-runs-as-root`,
`privileged-container`, `host-namespace-sharing`, `host-path-mount`, `container-privilege-escalation-allowed`,
`container-excess-capabilities`, `container-writable-root-filesystem`, `container-confinement-profile-unset` and
`container-security-context-missing`; `iac-misconfiguration` of `missing-health-probes`, `missing-image-healthcheck`,
`automounted-service-account-token`, `overly-permissive-rbac`, `image-not-from-allowed-registry` and
`container-missing-resource-requests`. The children partition the umbrellas' pre-split D31/D29 rule ids (asserted when
the mapping is built), so a key naming an umbrella scores exactly as it did under 1.2.

**Watchdog `scoreDimensions` (1.2).** `dependencies-not-locked` → SC1 (not D12, D36); `security-tooling-in-ci` → P3
(not D36); `high-cognitive-complexity` → D2 (R2 raises rows on cyclomatic complexity only); `duplicated-code` → D4,
R10 (not X10, a single-predicate finding). Curated in `mappings/watchdog-build/dims.py` (`SCORE_DIMS`).

**Watchdog (rubric-2026.10.1).** Watchdog's ruleId is the bare dimension id, so the message title decides the
concept. In `mappings/watchdog.json` every multi-concept in-scope dimension is fully discriminated: D3, D5, D7, D10,
D12, D13, D17, D28, D29, D31, D32, D36, IC1, PF3, R2, R8, S1, X1, X3 and X5, plus SC1. Each result lands on exactly
the concept its title denotes, or on none (`offConcept`). The tables are curated in
`mappings/watchdog-build/discrim.py`, with the engine source line of each title format. The out-of-scope runtime
card AXR1 is not discriminated. Single-concept dimensions keep the bare ruleId rule.

Note: bench repositories stay vendor-neutral, so they normally omit `scannerHints`; the harness mappings carry
scanner knowledge.

## Matching (mirrors kennel tools/multilang/matching.py semantics)

A SARIF result matches a located entry iff its ruleId matches one of the entry concept's `rules`, its path ends with
the entry's `file` (suffix-tolerant, `/`-normalised), and its startLine is within `lineTolerance` of `lines`. A
repository-level entry matches any result of the concept that has no location or whose location is outside every
located entry. One-to-one for `must-fire` (each entry consumes at most one result; extra results on the same site are
`redundant`, counted once and not as noise). `clean` entries match any result whose location falls inside the region,
for any concept listed (or any concept at all for `"*"`), with no line tolerance.

Precedence when a result could match several entries: a `must-fire` it can consume (key order, located before
repository-level) → `redundant` on an already-found plant → `must-not-fire` → `clean` → `not-applicable` → noise
if one of its concepts is covered by the key → `uncovered`.

**Subjects (1.2).** An entry with a `subject` matches, besides the results on its site (as above), a result of its
concept (exactly, or as a family sibling where families apply) that has **no location or a location in a dependency
manifest** (`Directory.Packages.props`, `Directory.Build.props`, `*.csproj`/`*.fsproj`/`*.vbproj`, `packages.config`,
`packages.lock.json`, `global.json`, `package.json`, the npm/yarn/pnpm lock files, `requirements*.txt`,
`pyproject.toml`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`, `Gemfile`, `composer.json` and their locks;
the full list is `MANIFEST_NAMES` in `cai_bench/scoring.py`), at any line, when the subject occurs in the result's
`message.text` as a **whole token**, case-insensitive. A token is bounded by any character that is not a word
character (letter, digit, `_`), except that `.`, `-` and `/` belong to the token when a word character is on their
far side. So `GPL-2.0` does not occur in `LGPL-2.0` nor in `GPL-2.0-only`, `Newtonsoft.Json` does not occur in
`Newtonsoft.Json.Bson` and `core` does not occur in `@angular/core`; `Newtonsoft.Json` does occur in
`Newtonsoft.Json 12.0.3`, `Newtonsoft.Json@12.0.3`, `(Newtonsoft.Json)` and at the end of a sentence. A
repository-level entry with a `subject` matches only results naming its subject. A subject match obeys the same
one-to-one consumption, redundancy and precedence as any other: matching runs in passes — exact concept on the site,
exact concept by subject, family sibling on the site, family sibling by subject — so a stronger match always wins, a
second result naming an already-found plant's subject is `redundant`, and a subject on a trap or clean entry catches
the scanner (FP). A location-less result that names the subject of a subject entry of its concept is never taken by a
repository-level entry without a subject: the subject entry is its site. Without `subject`, matching is as in 1.1.

**Location from the message (1.3).** Before matching, a result without a SARIF location takes the site its message
names, per the mapping's `locationFromMessage` (see the mapping section). From then on it is matched like any located
result — on a plant it is a TP, on a trap it is caught, in a clean region it is a clean FP, off every entry it is noise.

**Umbrella concepts (1.3).** If the mapping gives concept C a `parent` P, a result of C also counts as P for matching,
in the same pass as an exact match (it is not a family match): an entry naming P matches results of P and of every
child of P, while an entry naming C is matched only by results of C — never by a sibling child, nor by a residue result
of P itself. Coverage follows: a key that names P covers its children's results (they are noise off every entry, a
`clean` region listing P catches them). The report lists the result's own concept under `concepts`; its
`attributedConcept` is the one the key speaks about (P for a key written against the umbrella). Umbrellas and their
children take no family.

**History entries (1.1).** An entry with `commit` matches a result whose SARIF `properties.commitSha` starts with
`commit` (case-insensitive), in the same file (suffix rule), at **any** line: in a history finding the commit, not the
line, is the site. A result without `commitSha` never matches such an entry.

**Concept families (1.1).** If the mapping gives concepts the same `family`, a result of a *sibling* concept may
match a `must-fire` or a `must-not-fire` entry on the entry's site — but only after every exact-concept match has been
made, so a result of the entry's own concept is always preferred. The rule is symmetric so that it cannot flatter a
scanner: a sibling at a plant is a TP, a sibling at a trap is caught in the trap (FP), and a sibling result that
matches no entry is noise (the siblings of a covered concept count as covered). `clean` and `not-applicable` entries
name their concepts explicitly and match them exactly. Without a declared family, concepts never stand in for each
other (1.0).

## Metrics (per concept, and per scanner dimension via the mapping)

- recall = TP / (TP + FN) over `must-fire`
- trap resistance = TN / (TN + FP) over `must-not-fire`
- noise = (results on `must-not-fire` + `clean` + `not-applicable`, and results matching no entry of a
  concept the key covers) / all results of covered concepts
- score-band: in/out per entry (scores supplied separately as `{concept|dimension: score}` JSON). The score is the
  concept's own, if supplied; else that of each of the concept's `scoreDimensions` (1.2), defaulting to its
  `dimensions`, that has a score — the band is `in` only when every score found lies in it, `unscored` when none is
  found. A dimension whose findings evidence the concept does not necessarily have a score that measures it (a
  dependency-hygiene score is dominated by vulnerable packages, not by lockfiles), which is what `scoreDimensions` is
  for.

- file-level recall (1.3, SECONDARY) = must-fire entries found at file level / must-fire. A plant is found at file level
  when it is a TP, or when any result of its concept (exactly, as a child of an umbrella it names, or as a family
  sibling) is located anywhere in the plant's file, at any line; a repository-level plant only when it is a TP. It
  changes no TP/FN: a result on the wrong line stays an FN (a scanner that points at line 1 for a resource at line 71
  is imprecise, and recall says so). The gap between file-level recall and recall is the scanner's location
  imprecision. Reported per concept, per dimension and in total, always labelled as secondary.

Results whose concept the key does not cover at all are reported as `uncovered`, never as noise. `summary` rows
(mapping `ignore`) are in no metric. A metric with a zero denominator is reported as n/a, never as 0 or 100 %.
