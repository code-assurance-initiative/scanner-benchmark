# CAI reference implementation vs Watchdog — training set, 15 C# units

> ## ⚠ CAVEAT — this comparison is IN-SAMPLE for the reference implementation
>
> The CAI reference implementation (RI) was **calibrated against exactly these 15 C# units**. Its own documents say so:
> the commit that precedes its documentation is "Accessibility lens, **calibration pass over all 15 C# benchmark
> units**, project-model fixes"; its README states "Every calibration made against the benchmark is a rule a reviewer
> would accept on any repository"; its RESULTS.md itemises every miss and every noise row on these units. The rules
> were written while looking at these answer keys, so its numbers here measure fit to the keys as much as detection.
>
> **Watchdog was not trained on the answer keys.** The Watchdog row is its frozen iteration-1 baseline scan (kennel
> `6a05dfb6c`, taken before any improvement work), re-scored under harness 1.6. Its engine backlog was later fed
> **partly from this set's findings** (BASELINE-2026-10-07 §8: 91 false-negative backlog items filed after the
> baseline), but the scans compared here precede that work. One asymmetry runs the other way: Watchdog was the
> **instrument used while authoring** these units. Where it reported a real defect nobody had planted, the unit was
> fixed (results/watchdog/README.md). That shapes the units without ever dropping or weakening a label.
>
> **The honest comparison is the private holdout** (`holdout-2026-q4`): units written to the same contract, in
> domains and code shapes that appear nowhere in this set, which neither scanner has seen. Nothing here should be
> read as a ranking of the two scanners. It is a like-for-like re-measurement of the RI's published claim, plus a
> mechanism-level account of where the two differ on code the RI was tuned on.

## 1 What was run

| | CAI reference implementation | Watchdog |
|---|---|---|
| Engine | `cai-reference` 0.1.0, [reference-implementation](https://github.com/code-assurance-initiative/reference-implementation) `d3c2e24`, `dotnet build src/Cai.Reference -c Release`; rubric-2026.10.2 | kennel `main` `6a05dfb6c`, rubric-2026.10.1, contained (`codehealth-analyzer:train-src-89d1e8def87553cc`) — the frozen baseline scans |
| Configuration | default: `cai-ref scan <unit> --out <dir> --quiet`; no `--nuget-packages`, no network, no model | default: contained, no compliance framework, no `--with-llm` |
| Harness | `cai_bench` 1.5.0, **contract 1.6**, `--repo-dir` = the materialised unit (resource scope) | the same: `results/watchdog/rescore-harness-1.6.json` |
| Mapping | `mappings/cai-reference.json`: the RI's own `cai-ref mapping --taxonomy taxonomy.json` output, plus the taxonomy's `parent` links (§6) | `mappings/watchdog.json` |
| Units | the 15 C# units of `training-set-2026` at their latest registered tags, materialised with `tools/materialize.sh --all`; keys sha256-checked against the set registry | the same units and keys (‡ below) |
| Runtime | 2–5 s and 158–190 MB peak RSS per unit; two scans of one tree are byte-identical (checked on `bench-csharp-codehealth`) | (baseline §2) |

‡ **Key versions.** Watchdog's 1.6 row scores `bench-csharp-security-iac` at **v1.1.0**, the tag of its baseline
scan. The latest tag is v1.2.0, which fixes the broken plant IAC-017 (erratum E1). For a like-for-like comparison the
RI was **also** scanned at v1.1.0, and the tables below use that row. The RI's result is identical at both tags
(19/19, 20/20, 3/25): it finds IAC-017 even in the v1.1.0 tree, where the invalid YAML hides it from YAML parsers.
Watchdog's figure becomes 158/225 once its row is re-scored at v1.2.0 (erratum E1).
`results/cai-reference/final-scores.json` holds the RI at the latest tags (the unit files are built from it);
`final-scores-at-watchdog-tags.json` holds the comparison row. `compare.py` refuses to compare two sides whose
(tag, key sha256) differ.

## 2 Headline (15 C# units, same keys, same harness)

| Metric | CAI RI | Watchdog |
|---|---|---|
| Units | 15 | 15 |
| Recall (TP / plants) [Wilson 95 %] | **213/225 (94.7 %) [91–97]** | **157/225 (69.8 %) [63–75]** |
| Trap resistance (held / traps) [Wilson 95 %] | **260/260 (100.0 %) [99–100]** | **212/260 (81.5 %) [76–86]** |
| Noise share (noise / results of covered concepts) | **14/273 (5.1 %)** | **218/415 (52.5 %)** |
| File-level recall (secondary) | 213/225 (94.7 %) | 160/225 (71.1 %) |
| Redundant results (2nd hit on a found plant; no metric) | 46 | 40 |
| Uncovered results (concept not in the key; no metric) | 141 | 109 |

Per unit:

| Unit | Tag | RI recall | WD recall | RI traps | WD traps | RI noise | WD noise |
|---|---|---|---|---|---|---|---|
| `bench-csharp-baseline-clean` | v1.0.0 | – | – | 1/1 | 0/1 | – | 1/1 |
| `bench-csharp-security-secrets` | v1.0.0 | 17/17 | 11/17 | 24/24 | 23/24 | 0/31 | 1/22 |
| `bench-csharp-security-dependencies` | v1.1.0 | 5/8 | 7/8 | 8/8 | 6/8 | 0/27 | 2/12 |
| `bench-csharp-security-injection` | v1.0.0 | 20/20 | 10/20 | 23/23 | 19/23 | 0/22 | 6/18 |
| `bench-csharp-security-iac` | v1.1.0 ‡ | 19/19 | 15/19 | 20/20 | 17/20 | 3/25 | 53/83 |
| `bench-csharp-architecture` | v1.1.0 | 17/17 | 11/17 | 22/22 | 18/22 | 0/18 | 11/24 |
| `bench-csharp-domain-events` | v1.1.1 | 27/30 | 24/30 | 27/27 | 25/27 | 2/31 | 77/102 |
| `bench-csharp-codehealth` | v1.0.0 | 50/50 | 45/50 | 30/30 | 27/30 | 4/54 | 3/54 |
| `bench-csharp-tests` | v1.0.0 | 11/11 | 7/11 | 13/13 | 12/13 | 0/12 | 1/8 |
| `bench-csharp-readiness` | v1.0.0 | 12/12 | 3/12 | 25/25 | 18/25 | 0/13 | 15/19 |
| `bench-csharp-maturity-history` | v1.0.0 | 5/7 | 3/7 | 10/10 | 9/10 | 2/7 | 2/5 |
| `bench-csharp-blazor-a11y` | v1.0.0 | 22/25 | 16/25 | 22/22 | 20/22 | 0/22 | 2/18 |
| `estate-quellbrook-orders` | v1.0.0 | 2/2 | 0/2 | 12/12 | 6/12 | 0/2 | 20/20 |
| `estate-quellbrook-dispatch` | v1.0.0 | 4/5 | 4/5 | 15/15 | 6/15 | 3/7 | 20/24 |
| `estate-quellbrook-notifier` | v1.0.0 | 2/2 | 1/2 | 8/8 | 6/8 | 0/2 | 4/5 |

- **Recall: RI +56 plants.** Of Watchdog's 68 FNs the RI finds 61. Of the RI's 12 FNs Watchdog finds 5. 7 plants
  defeat both (§4).
- **Traps: RI 260/260, Watchdog 212/260.** Watchdog's 48 caught traps concentrate in `suppressed-diagnostic` (8/9),
  `missing-image-healthcheck` (5/6), `non-idempotent-message-handler` (3/5) and `solution-structure` (3/4).
- **Noise: RI 14/273 (5.1 %), Watchdog 218/415 (52.5 %).** Watchdog's noise is concentrated: D23
  `boundary-type-leakage` (61 rows on `bench-csharp-domain-events`), ED3 `event-not-named-in-past-tense` (26), the
  Kubernetes/Dockerfile umbrellas (33), ED5 (12) and the estate units (44 of 49 rows). Excluding the two units with the
  most noise, Watchdog is at 88/230 (38 %).
- **Not in any metric:** results of concepts a unit's key does not cover (`uncovered`), RI 141 vs Watchdog 109. The
  harness never judges these, so neither scanner is charged or credited for them.

## 3 Per lens

Plants and traps are counted once per lens, from the per-concept rows. Results are partitioned by dimension
(BASELINE §2). A lens's plant count follows each scanner's own concept→dimension mapping: Watchdog attributes a
hard-coded credential to D13, D28, D29 and D31 (Readiness **and** Security), the RI to D13 only. So the same plant can
sit in different lenses on the two sides, and the denominators differ. Totals do not overlap: the headline has 225
plants on both sides.

| Lens | CAI RI recall | CAI RI traps | CAI RI noise | Watchdog recall | Watchdog traps | Watchdog noise |
|---|---|---|---|---|---|---|
| Code Health | 59/59 (100.0 %) | 51/51 (100.0 %) | 6/65 (9.2 %) | 53/61 (86.9 %) | 36/52 (69.2 %) | 16/74 (21.6 %) |
| Architecture | 20/20 (100.0 %) | 24/24 (100.0 %) | 1/22 (4.5 %) | 13/19 (68.4 %) | 22/24 (91.7 %) | 64/79 (81.0 %) |
| Maturity | 4/4 (100.0 %) | 6/6 (100.0 %) | 1/5 (20.0 %) | 4/7 (57.1 %) | 9/9 (100.0 %) | 1/5 (20.0 %) |
| Readiness | 34/35 (97.1 %) | 56/56 (100.0 %) | 0/51 (0.0 %) | 29/42 (69.0 %) | 57/64 (89.1 %) | 17/42 (40.5 %) |
| Security | 50/50 (100.0 %) | 56/56 (100.0 %) | 3/79 (3.8 %) | 49/75 (65.3 %) | 82/98 (83.7 %) | 76/135 (56.3 %) |
| Domain Modelling | 17/17 (100.0 %) | 20/20 (100.0 %) | 1/19 (5.3 %) | 14/17 (82.4 %) | 15/19 (78.9 %) | 13/28 (46.4 %) |
| Event-Driven | 6/6 (100.0 %) | 10/10 (100.0 %) | 2/9 (22.2 %) | 4/4 (100.0 %) | 7/9 (77.8 %) | 26/30 (86.7 %) |
| Event Sourcing | 4/4 (100.0 %) | 3/3 (100.0 %) | 0/4 (0.0 %) | 3/4 (75.0 %) | 3/4 (75.0 %) | 1/4 (25.0 %) |
| Accessibility | 19/19 (100.0 %) | 18/18 (100.0 %) | 0/19 (0.0 %) | 14/19 (73.7 %) | 15/17 (88.2 %) | 2/16 (12.5 %) |
| Performance | – (n/a) | 2/2 (100.0 %) | – (n/a) | 1/2 (50.0 %) | 1/3 (33.3 %) | 2/2 (100.0 %) |
| (no scanner rule) | 0/11 (0.0 %) | 14/14 (100.0 %) | – (n/a) | 0/8 (0.0 %) | 5/5 (100.0 %) | – (n/a) |

## 4 Per dimension — same plants on both sides

The harness's per-dimension rows count a plant under every dimension its concept maps to. They therefore follow each
scanner's attribution, and the two sides would be counting different plants (D29: 19 plants for the RI, 56 for
Watchdog). For a side-by-side comparison, each concept is counted ONCE, under one canonical catalog dimension: the one
the RI's mapping names (the RI maps every concept to exactly the catalog dimension whose score it measures), else
Watchdog's; an umbrella goes under its children's dimension. Recall and traps come from the harness's per-concept
rows. Noise comes from the results each scanner attributed to those concepts. Columns and rows reconcile exactly with
§2 (213/157 TP, 260/212 traps held, 14/273 and 218/415 noise). The harness's own per-dimension rows for both scanners
are in `comparison-training.json` → `byHarnessDimension`. "rule?" = the scanner's mapping has at least one finding rule
in that dimension.

**Dimensions each scanner measures at all.** Watchdog's mapping has finding rules in 165 catalog dimensions, the RI's
in 124. Watchdog has rules where the RI has none in AXA1–AXS1 (runtime), D8, D19–D22, D24, D25, DM8, ED5, ES3,
LA1–LA6, M4 (model-judged or runtime: the RI's COVERAGE.md lists them as not measured), R1–R11 (TypeScript), X10, X12,
X14, X24 and X31 (Erlang). For X10/X12/X14/X24 the RI does detect the concepts, but attributes them to D4, D17, D29 and
D29 (duplicated-code, unreachable-code, server-side-request-forgery, cross-site-scripting). The RI has rules in no dimension that Watchdog lacks. On these 15 C# units, the dimensions only Watchdog has rules
for carry 9 plants. Watchdog finds 3 of them (DM8, ED5, ES3); the other 6 (D25 ×2, LA2, LA5, LA6, M4) are model-judged
and are FNs for both scanners in the default configuration.

| Dimension | Lens | Plants | CAI RI found | Watchdog found | Δ TP | Traps | CAI RI held | Watchdog held | CAI RI noise | Watchdog noise | CAI RI rule? | Watchdog rule? |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|
| AC1 | Accessibility | 3 | 3 | 2 | +1 | 2 | 2 | 2 | 0/3 | 0/2 | yes | yes |
| AC2 | Accessibility | 3 | 3 | 2 | +1 | 3 | 3 | 3 | 0/3 | 0/2 | yes | yes |
| AC3 | Accessibility | 2 | 2 | 2 | +0 | 2 | 2 | 1 | 0/2 | 1/3 | yes | yes |
| AC4 | Accessibility | 4 | 4 | 3 | +1 | 4 | 4 | 4 | 0/4 | 0/3 | yes | yes |
| AC5 | Accessibility | 1 | 1 | 1 | +0 | 2 | 2 | 2 | 0/1 | 0/1 | yes | yes |
| AC6 | Accessibility | 5 | 5 | 3 | +2 | 5 | 5 | 4 | 0/5 | 1/4 | yes | yes |
| AC7 | Accessibility | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| AX1 | Architecture | 1 | 1 | 1 | +0 | 2 | 2 | 1 | 0/2 | 1/2 | yes | yes |
| AX2 | Architecture | 1 | 1 | 1 | +0 | 2 | 2 | 2 | 0/1 | 0/1 | yes | yes |
| AX3 | Architecture | 1 | 1 | 0 | +1 | 1 | 1 | 1 | 0/1 | 0/0 | yes | yes |
| AX4 | Architecture | 3 | 3 | 3 | +0 | 6 | 6 | 6 | 0/3 | 0/5 | yes | yes |
| AX6 | Architecture | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| AX7 | Architecture | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| AX8 | Architecture | 1 | 1 | 0 | +1 | 1 | 1 | 1 | 0/1 | 0/0 | yes | yes |
| AX9 | Architecture | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| AX10 | Architecture | 1 | 1 | 0 | +1 | 0 | 0 | 0 | 0/1 | 0/0 | yes | yes |
| C1 | Security | 0 | 0 | 0 | +0 | 0 | 0 | 0 | 0/0 | 1/1 | yes | yes |
| C4 | Security | 0 | 0 | 0 | +0 | 2 | 2 | 0 | 0/0 | 2/2 | yes | yes |
| D1 | Code Health | 2 | 2 | 2 | +0 | 3 | 3 | 3 | 0/2 | 0/2 | yes | yes |
| D2 | Code Health | 2 | 2 | 2 | +0 | 0 | 0 | 0 | 0/2 | 0/2 | yes | yes |
| D3 | Code Health | 2 | 2 | 2 | +0 | 2 | 2 | 2 | 0/2 | 0/2 | yes | yes |
| D4 | Code Health | 3 | 3 | 3 | +0 | 2 | 2 | 2 | 6/9 | 0/4 | yes | yes |
| D5 | Architecture | 1 | 1 | 0 | +1 | 2 | 2 | 1 | 0/1 | 2/2 | yes | yes |
| D6 | Architecture | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| D7 | Architecture | 2 | 2 | 1 | +1 | 2 | 2 | 2 | 0/2 | 0/1 | yes | yes |
| D10 | Readiness | 6 | 6 | 4 | +2 | 6 | 6 | 5 | 0/6 | 1/5 | yes | yes |
| D11 | Readiness | 3 | 3 | 2 | +1 | 6 | 6 | 6 | 0/3 | 0/2 | yes | yes |
| D12 | Readiness | 2 | 0 | 1 | -1 | 2 | 2 | 2 | 0/0 | 0/1 | yes | yes |
| D13 | Readiness | 18 | 18 | 13 | +5 | 34 | 34 | 33 | 0/33 | 1/26 | yes | yes |
| D14 | Readiness | 1 | 0 | 1 | -1 | 1 | 1 | 0 | 0/0 | 1/2 | yes | yes |
| D15 | Maturity | 2 | 2 | 2 | +0 | 3 | 3 | 3 | 0/2 | 0/2 | yes | yes |
| D16 | Maturity | 1 | 1 | 1 | +0 | 2 | 2 | 2 | 0/1 | 1/2 | yes | yes |
| D17 | Code Health | 10 | 10 | 9 | +1 | 12 | 12 | 3 | 0/10 | 9/21 | yes | yes |
| D18 | Code Health | 1 | 1 | 1 | +0 | 4 | 4 | 1 | 0/1 | 3/4 | yes | yes |
| D20 | Maturity | 0 | 0 | 0 | +0 | 2 | 2 | 2 | 0/0 | 0/0 | no | yes |
| D23 | Architecture | 2 | 2 | 2 | +0 | 1 | 1 | 1 | 0/2 | 61/63 | yes | yes |
| D25 | Maturity | 2 | 0 | 0 | +0 | 1 | 1 | 1 | 0/0 | 0/0 | no | yes |
| D26 | Architecture | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| D27 | Architecture | 1 | 1 | 0 | +1 | 1 | 1 | 1 | 0/1 | 0/0 | yes | yes |
| D28 | Security | 2 | 2 | 1 | +1 | 0 | 0 | 0 | 0/2 | 0/1 | yes | yes |
| D29 | Security | 19 | 19 | 7 | +12 | 23 | 23 | 21 | 0/20 | 3/12 | yes | yes |
| D30 | Security | 4 | 4 | 4 | +0 | 2 | 2 | 2 | 0/26 | 0/7 | yes | yes |
| D31 | Security | 11 | 11 | 9 | +2 | 17 | 17 | 9 | 3/15 | 64/86 | yes | yes |
| D32 | Security | 3 | 3 | 1 | +2 | 3 | 3 | 2 | 0/4 | 2/3 | yes | yes |
| D34 | Maturity | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 1/2 | 0/1 | yes | yes |
| D35 | Architecture | 1 | 1 | 0 | +1 | 2 | 2 | 2 | 1/2 | 0/0 | yes | yes |
| D36 | Security | 5 | 5 | 4 | +1 | 7 | 7 | 7 | 0/6 | 2/6 | yes | yes |
| D39 | Code Health | 1 | 1 | 1 | +0 | 3 | 3 | 1 | 0/1 | 2/3 | yes | yes |
| D41 | Security | 0 | 0 | 0 | +0 | 0 | 0 | 0 | 0/0 | 1/1 | yes | yes |
| D42 | Security | 0 | 0 | 0 | +0 | 0 | 0 | 0 | 0/0 | 1/1 | yes | yes |
| D43 | Security | 0 | 0 | 0 | +0 | 1 | 1 | 1 | 0/0 | 0/0 | yes | yes |
| D44 | Security | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| DM1 | Domain Modelling | 1 | 1 | 1 | +0 | 2 | 2 | 1 | 0/2 | 2/4 | yes | yes |
| DM2 | Domain Modelling | 1 | 1 | 1 | +0 | 4 | 4 | 2 | 0/1 | 4/5 | yes | yes |
| DM3 | Domain Modelling | 1 | 1 | 1 | +0 | 2 | 2 | 1 | 0/1 | 3/4 | yes | yes |
| DM4 | Domain Modelling | 1 | 1 | 1 | +0 | 2 | 2 | 2 | 0/1 | 0/1 | yes | yes |
| DM5 | Domain Modelling | 4 | 4 | 2 | +2 | 3 | 3 | 3 | 0/4 | 0/2 | yes | yes |
| DM6 | Domain Modelling | 3 | 3 | 1 | +2 | 1 | 1 | 1 | 0/3 | 0/1 | yes | yes |
| DM7 | Domain Modelling | 2 | 2 | 2 | +0 | 1 | 1 | 1 | 0/2 | 4/6 | yes | yes |
| DM8 | Domain Modelling | 1 | 0 | 1 | -1 | 0 | 0 | 0 | 0/0 | 0/1 | no | yes |
| DM9 | Domain Modelling | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 1/2 | 0/1 | yes | yes |
| DM10 | Domain Modelling | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| DM11 | Domain Modelling | 1 | 1 | 1 | +0 | 2 | 2 | 2 | 0/1 | 0/1 | yes | yes |
| DM12 | Domain Modelling | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| ED1 | Event-Driven | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| ED2 | Event-Driven | 3 | 3 | 1 | +2 | 2 | 2 | 2 | 2/6 | 0/1 | yes | yes |
| ED3 | Event-Driven | 1 | 1 | 1 | +0 | 4 | 4 | 2 | 0/1 | 26/27 | yes | yes |
| ED4 | Event-Driven | 1 | 1 | 1 | +0 | 3 | 3 | 3 | 0/1 | 0/1 | yes | yes |
| ED5 | Readiness | 1 | 0 | 1 | -1 | 5 | 5 | 2 | 0/0 | 12/13 | no | yes |
| ES1 | Event Sourcing | 2 | 2 | 1 | +1 | 1 | 1 | 1 | 0/2 | 0/1 | yes | yes |
| ES2 | Event Sourcing | 2 | 2 | 1 | +1 | 2 | 2 | 2 | 0/2 | 0/1 | yes | yes |
| ES3 | Event Sourcing | 1 | 0 | 1 | -1 | 2 | 2 | 1 | 0/0 | 1/2 | no | yes |
| GD1 | Code Health | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/2 | yes | yes |
| IC1 | Code Health | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| LA2 | Accessibility | 1 | 0 | 0 | +0 | 0 | 0 | 0 | 0/0 | 0/0 | no | yes |
| LA5 | Accessibility | 1 | 0 | 0 | +0 | 0 | 0 | 0 | 0/0 | 0/0 | no | yes |
| LA6 | Accessibility | 1 | 0 | 0 | +0 | 1 | 1 | 1 | 0/0 | 0/0 | no | yes |
| M4 | Maturity | 1 | 0 | 0 | +0 | 0 | 0 | 0 | 0/0 | 0/0 | no | yes |
| P2 | Readiness | 1 | 1 | 0 | +1 | 2 | 2 | 2 | 0/2 | 1/1 | yes | yes |
| P6 | Readiness | 1 | 1 | 0 | +1 | 0 | 0 | 0 | 0/1 | 0/0 | yes | yes |
| P7 | Readiness | 1 | 1 | 0 | +1 | 3 | 3 | 3 | 0/1 | 0/0 | yes | yes |
| P8 | Readiness | 1 | 1 | 0 | +1 | 2 | 2 | 2 | 0/1 | 0/0 | yes | yes |
| P10 | Readiness | 0 | 0 | 0 | +0 | 1 | 1 | 0 | 0/0 | 1/1 | yes | yes |
| P12 | Readiness | 2 | 2 | 2 | +0 | 0 | 0 | 0 | 0/3 | 0/2 | yes | yes |
| PF2 | Performance | 0 | 0 | 0 | +0 | 0 | 0 | 0 | 0/0 | 1/1 | yes | yes |
| PF3 | Performance | 0 | 0 | 0 | +0 | 2 | 2 | 1 | 0/0 | 1/1 | yes | yes |
| R3 | Code Health | 0 | 0 | 0 | +0 | 1 | 1 | 1 | 0/0 | 0/0 | yes | yes |
| R4 | Readiness | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| S1 | Security | 3 | 3 | 0 | +3 | 0 | 0 | 0 | 0/3 | 0/0 | yes | yes |
| X1 | Code Health | 3 | 3 | 2 | +1 | 2 | 2 | 1 | 0/3 | 1/3 | yes | yes |
| X2 | Code Health | 4 | 4 | 0 | +4 | 1 | 1 | 1 | 0/4 | 0/0 | yes | yes |
| X3 | Code Health | 4 | 4 | 3 | +1 | 4 | 4 | 4 | 0/4 | 0/5 | yes | yes |
| X4 | Code Health | 2 | 2 | 2 | +0 | 2 | 2 | 2 | 0/2 | 0/2 | yes | yes |
| X5 | Code Health | 3 | 3 | 3 | +0 | 3 | 3 | 3 | 0/3 | 0/3 | yes | yes |
| X6 | Code Health | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| X7 | Code Health | 1 | 1 | 1 | +0 | 2 | 2 | 1 | 0/1 | 1/2 | yes | yes |
| X8 | Code Health | 2 | 2 | 2 | +0 | 2 | 2 | 2 | 0/2 | 0/2 | yes | yes |
| X9 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X13 | Code Health | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| X15 | Security | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| X16 | Code Health | 1 | 1 | 0 | +1 | 1 | 1 | 1 | 0/1 | 0/0 | yes | yes |
| X17 | Security | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| X18 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X19 | Code Health | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| X20 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X21 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X22 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X23 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X25 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X26 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X27 | Code Health | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| X28 | Code Health | 1 | 1 | 1 | +0 | 1 | 1 | 1 | 0/1 | 0/1 | yes | yes |
| X29 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X30 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |
| X32 | Code Health | 1 | 1 | 1 | +0 | 0 | 0 | 0 | 0/1 | 0/1 | yes | yes |

## 5 Where each wins, and why (mechanism level)

### Top 5 dimensions where the RI wins (same plants)

| Dimension | Plants | RI | Watchdog | Mechanism behind Watchdog's misses (BASELINE §8) |
|---|---:|---:|---:|---|
| D29 injection & web security | 19 | 19 | 7 | Of Watchdog's 12 misses: 7 are sinks with no rule in its baked semgrep packs (Dapper, `FromSqlRaw`, `TypeNameHandling`, `ContentResult`/`MarkupString` XSS, `Redirect`, Regex without timeout), 2 are taint confined to the request handler, 1 is MD5-for-passwords matched by call name, 1 is a repository-wide authorization switch, and 1 is Ingress without TLS (absent from the pinned IaC rule sets). The RI detects each of these C# sinks with its own Roslyn rules, and its traps on the same concepts hold 25/25 (Watchdog 23/25). |
| D13 secrets in code | 18 | 18 | 13 | Prefix-less secrets (punctuated `Password=`, credentials inside connection URIs, inline Bearer): Watchdog finds every vendor-prefixed secret and none without a prefix. The RI parses connection strings and assignments. It is calibrated here: its README cites the rule "a connection-string password needs a connection string around it". |
| X2 cancellation propagation | 4 | 4 | 0 | Watchdog measures X2 but emits only a location-less roll-up (`summaryOfConcept`), and its check is presence-only (a token parameter exists, not that it is forwarded). The RI emits one located row per non-forwarding call. |
| S1 web hardening (HTTPS, headers, input validation) | 3 | 3 | 0 | A repository-wide posture switch: one qualifying site anywhere credits the whole repository, so the defective site is never itemised. The RI reports the specific endpoint or pipeline. |
| D31 container & Kubernetes | 11 | 11 | 9 | Recall is close: Watchdog's two misses (hostNetwork IAC-004, hostPath IAC-006) are location imprecision, found in the right file at the wrong line. The real gap is precision: RI traps 15/15 and noise 0/12, Watchdog 7/15 and 31/53. checkov/trivy report each pod-level check at line 1 or at the pod spec, which lands on traps and in clean regions. |

Also decisive in RI-favoured rows: D17 traps 12/12 vs 3/12 (Watchdog fires on justified `#pragma`/`SuppressMessage`
suppressions); D23 noise 0/2 vs 61/63 and ED3 0/1 vs 26/27 (Watchdog false-positive families, see BASELINE §9); the
estate units, where the RI holds every trap (35/35) and Watchdog holds 18/35. By Watchdog's own mechanism labels, the
61 Watchdog FNs the RI finds are: no rule for the concept 10, architecture/domain detectors reading too narrow a
population 9, injection sink without a rule 7, repository-wide posture switch 7, prefix-less secret 6, shallow pattern
recogniser 4, call-name matching 3, measured but never reported 3, taint confined to the handler 2, location
imprecision 2, IaC/CI check absent 2 (one of them the broken plant IAC-017), presence-only runtime checks 2, AC6 not
reading .css 2, ADR conformance 1, flaky-test detection 1.

### The dimensions where Watchdog wins (same plants)

There are exactly five, each by one plant:

| Dimension | Plant concept | Why the RI misses it |
|---|---|---|
| D12 | `deprecated-dependency` (DEP-005) | needs package-registry deprecation metadata; the RI runs offline (mapping: unmapped). Watchdog reports it in its default contained scan |
| D14 | `license-policy-violation` (DEP-007) | the RI reads licences only with `--nuget-packages` (a restored NuGet cache). The default configuration passes none, and the bundle lists D14 under `notMeasured` |
| DM8 | `primitive-obsession` | the catalog marks DM8 `llm`-evaluated; the RI makes no model calls. Watchdog has a deterministic detector |
| ED5 | `non-idempotent-message-handler` | `llm`-evaluated in the catalog, as above. Watchdog's detector finds the plant, but pays 12/13 noise and holds 2/5 traps on the concept |
| ES3 | `personal-data-in-event-store` | `llm`-evaluated, as above. Watchdog holds 1/2 traps |

Watchdog also has finding rules in 41 dimensions the RI does not cover at all (§4), and produces more results that no
key covers. Neither shows in a metric here.

### Plants neither scanner finds (7)

ADR conformance ×2 (`adr-conformance`) and documentation drift (`documentation-accuracy`): model-judged. The three
Razor/Blazor text-quality cards (`alt-text-quality`, `link-and-button-text-quality`, `heading-and-label-text-quality`):
model-judged, and in Watchdog switched on only with a compliance framework. `outdated-dependency` (DEP-006): the RI is
offline; Watchdog measures it but emits it only below SARIF level (BASELINE §8, "measured but never reported"). Every plant of the training set that either scanner misses
for lack of a language model is a default-configuration effect, not a detector gap.

## 6 The RI's noise and false negatives, judged

**Noise: all 14 rows** judged under the five-class protocol (results/watchdog/README.md): **9 redundant, 5 valid,
0 false-positive, 0 opinion-not-fact, 0 shape-irrelevant.** The full reasons are in the unit files.

| Rows | Class | Mechanism |
|---:|---|---|
| 7 | redundant | **The other half of a found clone pair, or a clone window starting early.** The RI deliberately reports both halves of a duplicated block, and starts a clone block up to 7 lines above the key's span. The plant itself is found by another RI row (codehealth CH-006/CH-007, dispatch DSP-003). Declaring `sitesFromMessage` for the RI's "also found at file:line" format was evaluated: it would change no outcome, so the mapping does not carry it. |
| 2 | redundant | **The other file of a found file pair**: STL-001's stale module (RecurrenceRule beside RecurrenceExpander) and CPL-001's coupled pair. |
| 2 | valid | **Events raised and never handled** that the unit's README deliberately leaves "not certified either way" (`ExtendLoanEvent`, `MemberReinstated`). True, and uncertain = valid. |
| 2 | valid | **Unlabelled IaC absences** on a container the key labels only as privileged: no seccomp/AppArmor profile and no read-only root filesystem on the fluent-bit DaemonSet. |
| 1 | redundant | **The requests half of IAC-009**, whose rationale says "no CPU or memory requests or limits". |
| 1 | valid | **DM9 scattered-domain-rule**: the driver-eligibility check copied into two policies. It is the same defect as DSP-003 seen through the domain-modelling lens, and multi-lens detection is not redundant under the protocol. |

The last three IaC rows count as noise only because the mapping declares the taxonomy's parents (§7). Under the
RI's generated mapping they are `uncovered`.

**False negatives: all 12, grouped by mechanism.** 11 have no rule by design (mapping `unmapped`): 9 are
model-judged concepts the RI does not attempt (alt-text, link/button text, heading/label text, primitive obsession,
non-idempotent handler, personal data in the event store, ADR conformance ×2, documentation accuracy), and 2 need
registry data the offline engine lacks (deprecated, outdated). 1 is a configuration effect: a licence violation needs
`--nuget-packages`. On these units the RI has **no detector miss**: every plant of a concept it implements is found,
on its line. That is what in-sample calibration produces, and it is the reason the CAVEAT exists.

## 7 Does the RI's self-reported 95 % / 100 % / 4 % reproduce? — Yes, exactly

The RI's RESULTS.md reports 213/225 recall, 260/260 traps and 11/270 noise, measured with `cai_bench` 1.3.1,
contract 1.4, its generated mapping and no `--repo-dir`. The same SARIFs scored here (`reproducibility.json`):

| Mapping | Contract | Unit files | Recall | Traps | Noise |
|---|---|---|---|---|---|
| generated (as the RI publishes it) | 1.4 | – | 213/225 (94.7 %) | 260/260 | 11/270 (4.1 %) |
| generated | 1.5 | – | 213/225 | 260/260 | 11/270 |
| generated | 1.6 | no | 213/225 | 260/260 | 11/270 |
| generated | 1.6 | `--repo-dir` | 213/225 | 260/260 | 11/270 |
| **built (generated + taxonomy parents)** | **1.6** | **`--repo-dir`** | **213/225 (94.7 %)** | **260/260** | **14/273 (5.1 %)** |

- **Harness version:** no effect. The 1.5 file-scope and clone-site rules and the 1.6 resource-scope rule change no RI
  outcome. Its file-scope results already sit on their entries' lines or files, and all 7 resource-scope entries of
  `bench-csharp-security-iac` are met on their lines (`resourceScope.applied` 7, `resourceScopeMatches` 0).
- **Key versions:** no effect. The RI ran at the latest tags, which are the registered keys used here; at the iac v1.1.0
  tag its row is identical.
- **Scope rules (`--repo-dir`):** no effect (as above).
- **Mapping: the only difference.** The generated mapping declares no `parent`, although the taxonomy links 17
  children to 3 umbrellas, and the RI's own mapping says of two umbrellas "this engine emits the precise child
  concepts". Without `parent`, the harness cannot know that a child's result counts as its umbrella. A key entry or
  clean region that names an umbrella then never sees the RI's child results: the RI could neither be credited at an
  umbrella plant nor caught at an umbrella trap or clean region. Watchdog's mapping declares these links. Contract 1.3
  says a mapping's parents should mirror the taxonomy's. `mappings/cai-reference-build/build.py` adds exactly the
  taxonomy's parents to the generated file and changes nothing else (asserted by
  `tests/test_cai_reference_mapping.py`). On this set that moves 3 RI results (`bench-csharp-security-iac`) from
  `uncovered` to noise, giving 14/273 instead of 11/270. Recall and traps do not change.

So the claim reproduces: the published 95 % / 100 % / 4 % are exactly what this harness computes from the RI's output
and mapping. Under the harness's symmetric treatment of umbrellas, noise is 5.1 % rather than 4.1 %.

## 8 Files and how to reproduce

- `results/cai-reference/<unit>.json` (15): the scan (sha256 of `findings.sarif`, `scores.json`, `evidence.json`),
  the harness summary, the outcome of every result, every FN with its mechanism, and the verdicts (all noise rows).
  Format of `results/watchdog/<repo>.json`. Built by `unit_files.py` from `verdicts-training.json`.
- `final-scores.json` (latest tags), `final-scores-at-watchdog-tags.json` (iac at v1.1.0), `comparison-training.json`
  (headline, per lens, per canonical dimension, per harness dimension), `reproducibility.json`.
- `mappings/cai-reference.json` with `mappings/cai-reference-build/` (generated file + `build.py`, `--check`).

```sh
training-set-2026/tools/materialize.sh --all <units>
dotnet build src/Cai.Reference -c Release            # in reference-implementation @ d3c2e24
for u in <the 15 C# units>; do dotnet src/Cai.Reference/bin/Release/net10.0/Cai.Reference.dll scan <units>/$u --out <scans>/$u --quiet; done
dotnet …/Cai.Reference.dll mapping --taxonomy taxonomy.json --out /tmp/gen.json
python3 mappings/cai-reference-build/build.py /tmp/gen.json --check          # the committed mapping is its build
python3 results/cai-reference/score_units.py --set-registry ../training-set-2026/registry.json \
    --units-dir <units> --scans-root <scans> --out final-scores.json --reports-dir <reports>
python3 results/cai-reference/compare.py --a final-scores-at-watchdog-tags.json --a-mapping mappings/cai-reference.json \
    --a-label "CAI RI" --b results/watchdog/rescore-harness-1.6.json --b-mapping mappings/watchdog.json \
    --b-label Watchdog --units <the 15 C# units>
```

Every number above equals the CLI's: `python3 -m cai_bench score --key … --sarif <scan>/findings.sarif --mapping
mappings/cai-reference.json --scores <scan>/scores.json --repo-dir <unit>` gives the same entries, results and
summary as `score_units.py` (checked on `bench-csharp-security-iac` and `bench-csharp-codehealth`).
