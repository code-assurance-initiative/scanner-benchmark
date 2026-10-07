# Watchdog — benchmark summary (all registered repositories, final harness)

Scanner: **Watchdog**, kennel main `6a05dfb6c`, rubric `rubric-2026.10.1`, scanned **contained** (gitleaks, semgrep,
trivy, checkov and osv inside the analyzer image `codehealth-analyzer:train-src-89d1e8def87553cc`) in its **default
configuration**. Harness: `cai_bench` 1.3.1, contract 1.4, mapping `mappings/watchdog.json` (`rubric-2026.10.1`).

Every one of the **25 repositories** in [`registry.json`](../../registry.json) is scored at its **latest registered
tag**: the key is read with `git show <tag>:benchmark/answer-key.json` and its sha256 checked against the registry (all
25 match), and the SARIF is the repository's final contained scan (named in each results file's `scans[]`; the scanned
commit is the tag or a commit whose code is identical to it). Per-repository numbers, per-concept and per-dimension
rows, score bands and every remaining false negative are in [`final-scores.json`](final-scores.json); the aggregates
below are in [`SUMMARY.json`](SUMMARY.json), produced by [`summarise.py`](summarise.py) from those two inputs. Every
finding judged during authoring, with its verdict and reason, is in the per-repository `<repo>.json` files beside this
one. **[`BASELINE-2026-10-07.md`](BASELINE-2026-10-07.md) freezes these numbers as the iteration-1 baseline** (per lens,
per dimension, mechanisms, and how to compare a new engine against it).

**Where the units live.** The 25 repositories were consolidated on 2026-10-07 into one training set,
[`training-set-2026`](https://github.com/code-assurance-initiative/training-set-2026) v1.0.0: one git bundle per unit
(full history, every registered tag; byte-identical commits and keys) plus a readable snapshot of its latest tag. The
repository names stay the unit ids; the `bench-*` repositories are retired. To reproduce these numbers: materialise
the units from the bundles (`tools/materialize.sh --all <dir>`), scan each contained, re-score with
`rescore.py --units-dir <dir> --scans-root …`, and `python3 -m cai_bench compare` against the baseline —
[BASELINE § 11](BASELINE-2026-10-07.md#11-re-measuring-against-this-baseline) has the exact commands. Three units
were re-measured that way when the set was made, with outcomes identical to `final-scores.json`. [`PHASE1.md`](PHASE1.md) is the earlier Phase-1 write-up and is kept as it was.

Definitions (contract 1.4): **recall** = TP / (TP + FN) over planted defects; **trap resistance** = traps left alone /
traps; **noise share** = results on traps, clean regions, not-applicable concepts or matching no entry of a covered
concept / all results of covered concepts; **file-level recall** (secondary) counts a plant found when a result of its
concept lands anywhere in its file.

## Headline

| | Recall | Trap resistance | Noise share | File-level recall |
|---|---|---|---|---|
| **All 25 repositories** | **232 / 384 = 60.4 %** | **361 / 446 = 80.9 %** | **280 / 558 = 50.2 %** | 61.7 % |
| C# (15) | 155 / 225 = 68.9 % | 213 / 260 = 81.9 % | 226 / 415 = 54.5 % | 71.1 % |
| TypeScript (10) | 77 / 159 = 48.4 % | 148 / 186 = 79.6 % | 54 / 143 = 37.8 % | 48.4 % |
| All, without bench-csharp-security-iac | 218 / 365 = 59.7 % | 343 / 426 = 80.5 % | 220 / 475 = 46.3 % | 60.3 % |

Score bands (posture, metric and judged properties): 212 in band, 41 out of band, 144 unscored (no score composed in
the contained default configuration — most are model-judged dimensions, see the instrument notes).

How the 232 hits were matched: 205 at their located site, 18 by **subject** (a location-less package / framework /
type row naming the planted subject, contract 1.2), 8 repository-level, 1 by a location read out of the message
(contract 1.3).

### Per repository

| Repository | Tag | Lang | Family | Recall TP/(TP+FN) | Trap resistance | Noise share | File-level recall |
|---|---|---|---|---|---|---|---|
| bench-csharp-baseline-clean | v1.0.0 | C# | control | 0/0 (n/a) | 0/1 (0.0 %) | 1/1 (100.0 %) | n/a |
| bench-csharp-security-secrets | v1.0.0 | C# | security | 11/17 (64.7 %) | 23/24 (95.8 %) | 1/22 (4.5 %) | 64.7 % |
| bench-csharp-security-dependencies | v1.1.0 | C# | security | 7/8 (87.5 %) | 6/8 (75.0 %) | 2/12 (16.7 %) | 87.5 % |
| bench-csharp-security-injection | v1.0.0 | C# | security | 10/20 (50.0 %) | 19/23 (82.6 %) | 6/18 (33.3 %) | 50.0 % |
| bench-csharp-security-iac | v1.1.0 | C# | security | 14/19 (73.7 %) | 18/20 (90.0 %) | 60/83 (72.3 %) | 89.5 % |
| bench-csharp-architecture | v1.1.0 | C# | architecture | 11/17 (64.7 %) | 18/22 (81.8 %) | 11/24 (45.8 %) | 64.7 % |
| bench-csharp-domain-events | v1.1.1 | C# | domain | 24/30 (80.0 %) | 25/27 (92.6 %) | 77/102 (75.5 %) | 80.0 % |
| bench-csharp-codehealth | v1.0.0 | C# | codehealth | 45/50 (90.0 %) | 27/30 (90.0 %) | 3/54 (5.6 %) | 90.0 % |
| bench-csharp-tests | v1.0.0 | C# | testing | 7/11 (63.6 %) | 12/13 (92.3 %) | 1/8 (12.5 %) | 72.7 % |
| bench-csharp-readiness | v1.0.0 | C# | readiness | 3/12 (25.0 %) | 18/25 (72.0 %) | 15/19 (79.0 %) | 25.0 % |
| bench-csharp-maturity-history | v1.0.0 | C# | maturity | 3/7 (42.9 %) | 9/10 (90.0 %) | 2/5 (40.0 %) | 42.9 % |
| bench-ts-baseline-clean | v1.0.0 | TypeScript | control | 0/0 (n/a) | 1/3 (33.3 %) | 2/2 (100.0 %) | n/a |
| bench-ts-security-secrets | v1.0.0 | TypeScript | security | 12/17 (70.6 %) | 22/23 (95.7 %) | 1/22 (4.5 %) | 70.6 % |
| bench-ts-security-injection | v1.0.0 | TypeScript | security | 7/21 (33.3 %) | 20/25 (80.0 %) | 7/16 (43.8 %) | 33.3 % |
| bench-ts-frontend-a11y | v1.1.0 | TypeScript | frontend | 12/24 (50.0 %) | 19/22 (86.4 %) | 3/15 (20.0 %) | 50.0 % |
| bench-ts-security-dependencies | v1.0.0 | TypeScript | security | 6/13 (46.2 %) | 12/14 (85.7 %) | 3/9 (33.3 %) | 46.2 % |
| bench-ts-codehealth | v1.0.0 | TypeScript | codehealth | 29/51 (56.9 %) | 30/36 (83.3 %) | 8/38 (21.1 %) | 56.9 % |
| bench-ts-domain-privacy | v1.0.1 | TypeScript | domain | 5/11 (45.5 %) | 13/14 (92.9 %) | 5/10 (50.0 %) | 45.5 % |
| bench-csharp-blazor-a11y | v1.0.0 | C# | frontend | 16/25 (64.0 %) | 20/22 (90.9 %) | 2/18 (11.1 %) | 64.0 % |
| bench-ts-readiness | v1.0.0 | TypeScript | readiness | 3/17 (17.6 %) | 21/35 (60.0 %) | 18/21 (85.7 %) | 17.6 % |
| estate-quellbrook-gateway | v1.0.0 | TypeScript | estate | 0/2 (0.0 %) | 6/7 (85.7 %) | 3/3 (100.0 %) | 0.0 % |
| estate-quellbrook-orders | v1.0.0 | C# | estate | 0/2 (0.0 %) | 6/12 (50.0 %) | 20/20 (100.0 %) | 0.0 % |
| estate-quellbrook-dispatch | v1.0.0 | C# | estate | 3/5 (60.0 %) | 6/15 (40.0 %) | 21/24 (87.5 %) | 80.0 % |
| estate-quellbrook-notifier | v1.0.0 | C# | estate | 1/2 (50.0 %) | 6/8 (75.0 %) | 4/5 (80.0 %) | 50.0 % |
| estate-quellbrook-web | v1.0.0 | TypeScript | estate | 3/3 (100.0 %) | 4/7 (57.1 %) | 4/7 (57.1 %) | 100.0 % |

The two `baseline-clean` repositories are controls: nothing planted, traps and clean certificates only.

### By language and by family

| Slice | Repos | Recall | Trap resistance | Noise share | File-level recall |
|---|---|---|---|---|---|
| **All** | 25 | 232/384 (60.4 %) | 361/446 (80.9 %) | 280/558 (50.2 %) | 61.7 % |
| C# | 15 | 155/225 (68.9 %) | 213/260 (81.9 %) | 226/415 (54.5 %) | 71.1 % |
| TypeScript | 10 | 77/159 (48.4 %) | 148/186 (79.6 %) | 54/143 (37.8 %) | 48.4 % |
| family: architecture | 1 | 11/17 (64.7 %) | 18/22 (81.8 %) | 11/24 (45.8 %) | 64.7 % |
| family: codehealth | 2 | 74/101 (73.3 %) | 57/66 (86.4 %) | 11/92 (12.0 %) | 73.3 % |
| family: control | 2 | 0/0 (n/a) | 1/4 (25.0 %) | 3/3 (100.0 %) | n/a |
| family: domain | 2 | 29/41 (70.7 %) | 38/41 (92.7 %) | 82/112 (73.2 %) | 70.7 % |
| family: estate | 5 | 7/14 (50.0 %) | 28/49 (57.1 %) | 52/59 (88.1 %) | 57.1 % |
| family: frontend | 2 | 28/49 (57.1 %) | 39/44 (88.6 %) | 5/33 (15.2 %) | 57.1 % |
| family: maturity | 1 | 3/7 (42.9 %) | 9/10 (90.0 %) | 2/5 (40.0 %) | 42.9 % |
| family: readiness | 2 | 6/29 (20.7 %) | 39/60 (65.0 %) | 33/40 (82.5 %) | 20.7 % |
| family: security | 7 | 67/115 (58.3 %) | 120/137 (87.6 %) | 80/182 (44.0 %) | 60.9 % |
| family: testing | 1 | 7/11 (63.6 %) | 12/13 (92.3 %) | 1/8 (12.5 %) | 72.7 % |

### The IaC noise caveat

`bench-csharp-security-iac` alone contributes 60 of the 280 noise rows (72 % of its own results). This is a location
artefact of how the harness must score, not 60 false findings: the harness calls every result of a covered concept that
matches no entry within ±3 lines noise, and checkov reports every Kubernetes check at **line 1** of the manifest while
trivy reports pod-level checks on the **workload spec** line. 51 of the 54 off-entry rows sit at line 1 / the spec /
the RBAC header of the two planted workloads and restate defects planted further down (no securityContext, no
resources, the privileged forwarder, the wildcard ClusterRole); the authoring triage judged 33 of them `redundant` and
only 13 rows across every iteration `false-positive` or `opinion-not-fact`. The same imprecision turns three IaC plants
into FNs (file-level recall 89.5 % vs recall 73.7 %). Read the IaC noise share as "location imprecision", and the
all-repository noise share without it (46.3 %) as the better headline for noise. The other two heavy noise sources are
mechanisms, not location: `bench-csharp-domain-events` (77 rows: 61 D23 "cross-context type" rows from one rule that
takes each project for a bounded context, plus 9 ED5, 4 DM7, 2 DM1, 1 ES3) and the estate (52 of 59: 16 ED3/DM3 rows
reading HTTP/contract DTOs as events, D31 hardening rows on manifests the key certifies clean, the documented CA2007
suppression (D17), and D18 / ED5 / C4 / AC4 / R2 traps).

## Per dimension (dimensions with at least 3 labelled plants + traps)

A plant is counted under every dimension its concept maps to, so the rows overlap.

| Dimension | Plants found | Traps held | Noise share |
|---|---|---|---|
| (no scanner rule) ‡ | 0/15 (0.0 %) | 11/11 (100.0 %) | 0/0 (n/a) |
| AC1 | 5/5 (100.0 %) | 5/5 (100.0 %) | 0/5 (0.0 %) |
| AC2 | 5/5 (100.0 %) | 5/5 (100.0 %) | 0/5 (0.0 %) |
| AC3 | 4/4 (100.0 %) | 2/3 (66.7 %) | 1/5 (20.0 %) |
| AC4 | 7/7 (100.0 %) | 6/9 (66.7 %) | 3/10 (30.0 %) |
| AC5 | 2/2 (100.0 %) | 3/3 (100.0 %) | 0/2 (0.0 %) |
| AC6 | 4/8 (50.0 %) | 7/9 (77.8 %) | 2/6 (33.3 %) |
| AX1 | 1/1 (100.0 %) | 1/2 (50.0 %) | 1/2 (50.0 %) |
| AX2 | 1/1 (100.0 %) | 2/2 (100.0 %) | 0/1 (0.0 %) |
| AX3 | 0/2 (0.0 %) | 2/2 (100.0 %) | 0/0 (n/a) |
| AX4 | 1/4 (25.0 %) | 8/8 (100.0 %) | 0/1 (0.0 %) |
| AX6 | 2/2 (100.0 %) | 3/3 (100.0 %) | 0/2 (0.0 %) |
| AX7 | 2/2 (100.0 %) | 2/2 (100.0 %) | 0/2 (0.0 %) |
| AXR1 † | 0/19 (0.0 %) | 23/23 (100.0 %) | 0/0 (n/a) |
| C2 | 0/0 (n/a) | 0/4 (0.0 %) | 4/4 (100.0 %) |
| D1 | 3/3 (100.0 %) | 9/9 (100.0 %) | 0/3 (0.0 %) |
| D10 | 6/15 (40.0 %) | 16/17 (94.1 %) | 2/8 (25.0 %) |
| D11 | 0/5 (0.0 %) | 9/9 (100.0 %) | 0/0 (n/a) |
| D12 | 4/14 (28.6 %) | 10/10 (100.0 %) | 0/4 (0.0 %) |
| D13 | 16/34 (47.1 %) | 57/59 (96.6 %) | 2/20 (10.0 %) |
| D14 | 2/2 (100.0 %) | 2/3 (66.7 %) | 1/3 (33.3 %) |
| D15 | 2/2 (100.0 %) | 3/3 (100.0 %) | 0/2 (0.0 %) |
| D16 | 1/1 (100.0 %) | 2/2 (100.0 %) | 1/2 (50.0 %) |
| D17 | 12/26 (46.2 %) | 16/25 (64.0 %) | 9/21 (42.9 %) |
| D18 | 1/1 (100.0 %) | 1/4 (25.0 %) | 3/4 (75.0 %) |
| D2 | 3/3 (100.0 %) | 1/1 (100.0 %) | 0/3 (0.0 %) |
| D20 | 0/0 (n/a) | 4/4 (100.0 %) | 0/0 (n/a) |
| D23 | 3/3 (100.0 %) | 2/2 (100.0 %) | 64/67 (95.5 %) |
| D25 | 0/2 (0.0 %) | 1/1 (100.0 %) | 0/0 (n/a) |
| D28 | 24/37 (64.9 %) | 59/59 (100.0 %) | 0/24 (0.0 %) |
| D29 | 16/101 (15.8 %) | 137/141 (97.2 %) | 7/24 (29.2 %) |
| D3 | 5/6 (83.3 %) | 6/6 (100.0 %) | 0/5 (0.0 %) |
| D30 | 9/9 (100.0 %) | 4/4 (100.0 %) | 0/9 (0.0 %) |
| D31 | 9/28 (32.1 %) | 54/67 (80.6 %) | 83/99 (83.8 %) |
| D32 | 3/8 (37.5 %) | 7/9 (77.8 %) | 2/5 (40.0 %) |
| D35 | 0/1 (0.0 %) | 2/2 (100.0 %) | 0/0 (n/a) |
| D36 | 1/6 (16.7 %) | 7/7 (100.0 %) | 2/3 (66.7 %) |
| D39 | 1/1 (100.0 %) | 1/3 (33.3 %) | 2/3 (66.7 %) |
| D4 | 1/5 (20.0 %) | 6/6 (100.0 %) | 1/3 (33.3 %) |
| D40 | 0/1 (0.0 %) | 3/3 (100.0 %) | 0/0 (n/a) |
| D44 | 1/2 (50.0 %) | 2/2 (100.0 %) | 0/1 (0.0 %) |
| D5 | 1/7 (14.3 %) | 11/12 (91.7 %) | 2/3 (66.7 %) |
| D6 | 2/2 (100.0 %) | 2/2 (100.0 %) | 0/2 (0.0 %) |
| D7 | 4/8 (50.0 %) | 12/12 (100.0 %) | 0/4 (0.0 %) |
| DM1 | 2/2 (100.0 %) | 3/4 (75.0 %) | 2/5 (40.0 %) |
| DM10 | 1/2 (50.0 %) | 2/2 (100.0 %) | 0/1 (0.0 %) |
| DM11 | 1/2 (50.0 %) | 4/4 (100.0 %) | 0/1 (0.0 %) |
| DM2 | 2/2 (100.0 %) | 3/5 (60.0 %) | 4/6 (66.7 %) |
| DM3 | 1/1 (100.0 %) | 1/2 (50.0 %) | 3/4 (75.0 %) |
| DM4 | 2/2 (100.0 %) | 2/3 (66.7 %) | 2/4 (50.0 %) |
| DM5 | 3/4 (75.0 %) | 3/3 (100.0 %) | 0/3 (0.0 %) |
| DM6 | 1/4 (25.0 %) | 2/2 (100.0 %) | 0/1 (0.0 %) |
| DM7 | 2/3 (66.7 %) | 2/2 (100.0 %) | 4/6 (66.7 %) |
| DM9 | 1/2 (50.0 %) | 2/2 (100.0 %) | 0/1 (0.0 %) |
| ED3 | 1/1 (100.0 %) | 2/4 (50.0 %) | 26/27 (96.3 %) |
| ED4 | 1/1 (100.0 %) | 3/3 (100.0 %) | 0/1 (0.0 %) |
| ED5 | 1/1 (100.0 %) | 2/5 (40.0 %) | 12/13 (92.3 %) |
| ES1 | 1/2 (50.0 %) | 1/1 (100.0 %) | 0/1 (0.0 %) |
| ES3 | 1/1 (100.0 %) | 1/2 (50.0 %) | 1/2 (50.0 %) |
| GD1 | 1/2 (50.0 %) | 1/1 (100.0 %) | 0/1 (0.0 %) |
| IC1 | 5/17 (29.4 %) | 17/17 (100.0 %) | 0/7 (0.0 %) |
| P10 | 0/2 (0.0 %) | 2/3 (66.7 %) | 1/1 (100.0 %) |
| P2 | 0/2 (0.0 %) | 2/2 (100.0 %) | 1/1 (100.0 %) |
| P7 | 0/2 (0.0 %) | 5/5 (100.0 %) | 0/0 (n/a) |
| P8 | 0/2 (0.0 %) | 5/5 (100.0 %) | 0/0 (n/a) |
| PF3 | 1/3 (33.3 %) | 3/4 (75.0 %) | 1/2 (50.0 %) |
| R10 | 2/5 (40.0 %) | 5/6 (83.3 %) | 1/3 (33.3 %) |
| R11 | 1/4 (25.0 %) | 6/8 (75.0 %) | 2/3 (66.7 %) |
| R2 | 1/6 (16.7 %) | 5/10 (50.0 %) | 5/6 (83.3 %) |
| R3 | 0/2 (0.0 %) | 3/3 (100.0 %) | 0/0 (n/a) |
| R5 | 0/2 (0.0 %) | 3/3 (100.0 %) | 0/0 (n/a) |
| R7 | 0/6 (0.0 %) | 2/6 (33.3 %) | 4/4 (100.0 %) |
| R8 | 0/3 (0.0 %) | 2/2 (100.0 %) | 1/1 (100.0 %) |
| R9 | 1/2 (50.0 %) | 2/2 (100.0 %) | 0/1 (0.0 %) |
| S1 | 1/19 (5.3 %) | 14/16 (87.5 %) | 3/4 (75.0 %) |
| X1 | 3/6 (50.0 %) | 3/4 (75.0 %) | 1/4 (25.0 %) |
| X10 | 1/5 (20.0 %) | 6/6 (100.0 %) | 0/1 (0.0 %) |
| X12 | 2/3 (66.7 %) | 2/2 (100.0 %) | 0/2 (0.0 %) |
| X13 | 1/2 (50.0 %) | 2/2 (100.0 %) | 0/1 (0.0 %) |
| X14 | 1/3 (33.3 %) | 3/4 (75.0 %) | 1/2 (50.0 %) |
| X16 | 1/2 (50.0 %) | 2/2 (100.0 %) | 0/1 (0.0 %) |
| X17 | 2/2 (100.0 %) | 2/2 (100.0 %) | 0/2 (0.0 %) |
| X18 | 2/2 (100.0 %) | 1/1 (100.0 %) | 0/2 (0.0 %) |
| X19 | 2/2 (100.0 %) | 2/2 (100.0 %) | 0/2 (0.0 %) |
| X2 | 0/6 (0.0 %) | 1/1 (100.0 %) | 1/1 (100.0 %) |
| X23 | 2/2 (100.0 %) | 1/1 (100.0 %) | 0/2 (0.0 %) |
| X24 | 2/6 (33.3 %) | 7/7 (100.0 %) | 0/5 (0.0 %) |
| X3 | 3/7 (42.9 %) | 6/6 (100.0 %) | 0/3 (0.0 %) |
| X4 | 4/4 (100.0 %) | 3/5 (60.0 %) | 2/6 (33.3 %) |
| X5 | 4/6 (66.7 %) | 3/4 (75.0 %) | 1/5 (20.0 %) |
| X6 | 2/2 (100.0 %) | 2/2 (100.0 %) | 0/2 (0.0 %) |
| X7 | 2/2 (100.0 %) | 2/3 (66.7 %) | 1/3 (33.3 %) |
| X8 | 2/2 (100.0 %) | 2/2 (100.0 %) | 0/2 (0.0 %) |
| X9 | 2/2 (100.0 %) | 1/1 (100.0 %) | 0/2 (0.0 %) |

† AXR1 is Watchdog's out-of-scope runtime (browser) accessibility card; the mapping lists it as a dimension of four
accessibility concepts (text alternatives, form labels, keyboard access, visual/motion safety), but no static scan
composes it, so it is 0 by construction — the static AC1–AC6 rows carry the same plants.
‡ Plants and traps of concepts no Watchdog rule maps (contract 1.4 `unmapped`).

Weakest well-populated dimensions: **D29** (SAST, 16 / 101 — the injection repositories, see mechanisms below),
**S1** (1 / 19), **IC1** (5 / 17), **D12** (4 / 14), **D31** (9 / 28 by line, most of the rest found in the file),
**D10** (6 / 15). Strongest: D28 history secrets (24 / 37 with 59 / 59 traps held), D30 (9 / 9), AC1–AC5 (all plants),
D13's trap resistance (57 / 59).

## False negatives — the general mechanisms

All **152** remaining false negatives of the final re-score, each assigned to exactly one mechanism (`summarise.py`
asserts the assignment is complete and matches the re-score). Sources: each results file's `falseNegatives` (the
reason recorded when the plant was re-verified) and the "Engine facts" lines of the authoring log.

| FNs | Mechanism | Languages | Representative sites |
|---|---|---|---|
| 19 | No rule for the concept at all (scanner-neutral concepts beyond the reference scanner: unmapped or unevidenced in the mapping) | C#, TypeScript | csharp-architecture BLC-001 (`src/FleetOps.Api/Controllers/WorkOrdersController.cs`); csharp-domain-events VOM-001 (`src/Rentals.Lending.Domain/Catalogue/StorageLocation.cs`); csharp-domain-events DEH-001 (`src/Rentals.Lending.Domain/Catalogue/EquipmentRelocated.cs`) |
| 15 | Repository-wide posture switches: one qualifying site anywhere credits the whole repository, so the defective site is never itemised (P7, P8, C2, S1, D40, D42, P10, P11, P6) | C#, TypeScript | csharp-readiness RDY-001 (`src/ParcelTracking.Infrastructure/DependencyInjection.cs`); csharp-readiness RDY-004 (`src/ParcelTracking.Api/Controllers/ReportsController.cs`); csharp-readiness RDY-005 (`src/ParcelTracking.Api/Contracts/RedirectParcelRequest.cs`) |
| 12 | Code-health and test rules with no TypeScript arm (suppressions, commented-out code, empty catch, dead private code, @deprecated use, catch-rethrow, null dereference, swallowed test failures, mock dominance) | TypeScript | ts-codehealth CH-010 (`src/application/labels/label-service.ts`); ts-codehealth CH-013 (`src/application/labels/label-service.ts`); ts-codehealth CH-014 (`src/application/labels/label-service.ts`) |
| 12 | Pattern recognisers too shallow for the defect's shape (.Result, Assert.True(true), WarningsNotAsErrors, eslint config off-switches, Error('Not implemented'), hollow methods, density bars, bare floating promises, inert options, undrained stderr, vitest test without expect, truncation loops) | C#, TypeScript | csharp-codehealth CH-023 (`src/Shipping.Rates.Api/Endpoints/LabelEndpoints.cs`); csharp-codehealth CH-034 (`src/Shipping.Rates.Core/Labels/ZplLabelRenderer.cs`); csharp-codehealth CH-049 (`src/Shipping.Rates.Core/Shipping.Rates.Core.csproj`) |
| 11 | Prefix-less secrets: every vendor-prefixed secret was found, every secret without a vendor prefix was missed (punctuated Password=, credentials in connection URIs, inline Bearer, unquoted dotenv, .http files, Vite define) | C#, TypeScript | csharp-security-secrets SEC-005 (`src/DocumentExport.Api/Persistence/AuditStoreSettings.cs`); csharp-security-secrets SEC-006 (`src/DocumentExport.Api/appsettings.Production.json`); csharp-security-secrets SEC-007 (`src/DocumentExport.Api/appsettings.Development.json`) |
| 11 | Injection taint confined to the request handler: the tainted value arrives as a method parameter, model-bound argument, component state or ternary, or passes a function assumed safe (path.join) | C#, TypeScript | csharp-security-injection CMD-001 (`src/ReportDesk.Api/Conversion/DocumentConverter.cs`); csharp-security-injection SSRF-001 (`src/ReportDesk.Api/Controllers/ImportsController.cs`); ts-security-injection SQL-001 (`src/search/document-search-repository.ts`) |
| 10 | Injection sink or library with no rule in the baked packs (Dapper, EF FromSqlRaw, Newtonsoft TypeNameHandling, ContentResult XSS, Redirect, Regex without timeout, MongoDB filters, dynamic RegExp, log injection, Blazor MarkupString) | C#, TypeScript | csharp-security-injection SQL-001 (`src/ReportDesk.Api/Search/DocumentSearchRepository.cs`); csharp-security-injection SQL-002 (`src/ReportDesk.Api/Reports/ReportRepository.cs`); csharp-security-injection DESER-001 (`src/ReportDesk.Api/SavedSearches/SavedSearchSerializer.cs`) |
| 9 | Architecture / domain detectors read too narrow a population (project-reference cycles only, test edges in instability, no pass-through detection, attributes and projections ignored, entities without Id, declared references excuse co-change, test-support project not seen as test code) | C# | csharp-architecture DOM-001 (`src/FleetOps.Domain/Maintenance/MaintenanceDueEvaluator.cs`); csharp-architecture SDP-001 (`src/FleetOps.ServiceDefaults/FleetOps.ServiceDefaults.csproj`); csharp-architecture CYC-001 (`src/FleetOps.Infrastructure/Email/ReminderMailer.cs`) |
| 8 | Measured but never reported: per-site rows at Info/Recommendation level or below a score threshold never reach SARIF; only a location-less roll-up does (X2 CancellationToken, D12/npm outdated, R7 unused exports, R3 size) | C#, TypeScript | csharp-security-dependencies DEP-006 (`Directory.Packages.props`); ts-security-dependencies OUT-001 (`package.json`); ts-codehealth CH-016 (`src/domain/value-objects/tracking-number.ts`) |
| 7 | Data-flow rules that match call NAMES, not data: source-generated [LoggerMessage] methods, structured log fields, headers inside a logged object, localStorage under a neutral key, MD5.HashData / createHash('md5') for passwords | C#, TypeScript | csharp-security-injection PII-001 (`src/ReportDesk.Api/Delivery/ReportMailer.cs`); csharp-security-injection HASH-001 (`src/ReportDesk.Api/Shares/SharePasswordHasher.cs`); estate-quellbrook-notifier NTF-002 (`src/Quellbrook.Notifier/Channels/EmailSender.cs`) |
| 5 | DM9-DM11 have no TypeScript arm, and DM6/DM7 only partial ones (decorators only; no interface type arguments) | TypeScript | ts-domain-privacy DIB-001 (`src/membership/domain/members/contact-uniqueness.ts`); ts-domain-privacy REP-001 (`src/billing/domain/invoices/invoice-line-repository.ts`); ts-domain-privacy SDR-001 (`None`) |
| 5 | Found the file, missed the site: checkov/trivy Kubernetes rows at line 1 or the pod spec, a duplicate-block window that starts early, a misplaced dependency reported at its importer | C#, TypeScript | csharp-security-iac IAC-004 (`deploy/k8s/node-agent/daemonset.yaml`); csharp-security-iac IAC-006 (`deploy/k8s/node-agent/daemonset.yaml`); csharp-security-iac IAC-010 (`deploy/k8s/reminders/deployment.yaml`) |
| 5 | Model-judged accessibility text cards (LA2 alt text, LA5 link text, LA6 labels) are composed only with a compliance framework configured, so the default configuration measures nothing | C#, TypeScript | ts-frontend-a11y A11Y-019 (`src/features/home/HomePage.tsx`); ts-frontend-a11y A11Y-020 (`src/features/home/HomePage.tsx`); csharp-blazor-a11y BA-023 (`src/HarbourLane.Bookings.Web/Components/Pages/Home.razor`) |
| 5 | Dependency hygiene arms missing: npm deprecation not graded, EOL ignores engines.node and nested packages, R8 unused/undeclared blind on TypeScript | TypeScript | ts-security-dependencies DPR-001 (`package.json`); ts-security-dependencies DPR-002 (`package-lock.json`); ts-security-dependencies EOL-001 (`tools/manifest-export/package.json`) |
| 5 | Presence-only runtime checks: X2 checks that a token parameter exists, not that it is forwarded; an injected fetch hides outbound HTTP from P7/X2; Console output is neither a log call nor flagged | C#, TypeScript | csharp-readiness RDY-002 (`src/ParcelTracking.Infrastructure/Persistence/ParcelStore.cs`); csharp-readiness RDY-006 (`src/ParcelTracking.Worker/NotificationDispatcher.cs`); ts-readiness RDY-001 (`apps/tracking-service/src/worker/webhook-dispatcher.ts`) |
| 4 | ADR / documentation conformance is model-judged: absent from contained scans and unreliable in host passes (prose-enforced ADRs, README drift, ADR contradicted by an endpoint) | C# | csharp-architecture ARU-001 (`docs/adr/0003-vertical-slices.md`); csharp-maturity-history ADR-001 (`docs/adr/0004-minimal-api-endpoints.md`); csharp-maturity-history DOC-001 (`None`) |
| 4 | AC6 reads <style> blocks and inline styles only: motion and focus-outline defects in .css / .razor.css files are invisible | C#, TypeScript | ts-frontend-a11y A11Y-014 (`src/styles/loading.css`); ts-frontend-a11y A11Y-015 (`src/styles/search.css`); csharp-blazor-a11y BA-015 (`src/HarbourLane.Bookings.Web/Components/Shared/ToastHost.razor.css`) |
| 3 | Flaky tests: detection is three re-runs (a 1e-4 flake never shows), no time-zone/clock-read rule, the fixed-sleep rule reads C# only | C#, TypeScript | csharp-tests TQ-006 (`tests/Fx.Conversion.UnitTests/Rates/RateTableTests.cs`); ts-readiness FLK-001 (`apps/tracking-service/tests/unit/share-links.test.ts`); ts-readiness FLK-002 (`apps/tracking-service/tests/integration/poller.test.ts`) |
| 2 | IaC / CI checks absent in the pinned rule sets: Ingress without TLS, pull_request_target checking out and building the PR head | C# | csharp-security-iac IAC-013 (`deploy/k8s/api/ingress.yaml`); csharp-security-iac IAC-017 (`.github/workflows/pr-preview.yml`) |

Read across the table:

- **Prefix-less secrets (11).** Across both secrets repositories every vendor-prefixed secret was found and every
  secret without a vendor prefix was missed: punctuated `Password=` values (also in history), credentials inside a
  connection URI, an inline `AuthenticationHeaderValue("Bearer", …)`, an unquoted base64 value in `.env.production`,
  `Authorization:` lines in `.http` files and a signing secret in Vite `define`.
- **Repository-wide posture switches (15).** P7 (resilience), P8 (migrations), C2 (authorization), S1 (validation,
  HSTS, headers), D40 (egress), D42 (admission), P10 (library versioning), P11 (executable specs) and P6 (changelog)
  each credit the whole repository on one qualifying site anywhere, so the one unprotected client, controller, branch,
  table or package is never named. Readiness is the family where this dominates (6 / 29).
- **Injection (21 = 11 + 10).** The TypeScript taint rules need the request object in the same function; a value that
  reaches the sink as a repository/service parameter (the normal shape of a layered service) is invisible. The C# packs
  lack whole sinks (Dapper, EF `FromSqlRaw`, Newtonsoft `TypeNameHandling`, `ContentResult` XSS, `Redirect`, `Regex`
  without a timeout, Blazor `MarkupString`).
- **No TypeScript arm (12 + 5).** Most C# code-health and test rules have no TypeScript counterpart, and DM9–DM11 have
  no TS arm at all (DM6 reads decorators only, DM7 cannot read interface type arguments).
- **Measured but never reported (8).** Info/Recommendation-level per-site rows never reach SARIF (X2 per-method
  CancellationToken rows, outdated packages, R7 unused exports, R3 below its threshold); only an unlocated roll-up
  does, which the harness records as `summary-of-concept`, not as a hit.
- **Location-less and mislocated rows.** Location-less rows were the biggest scoring problem early on (D23 type rows,
  D36 workflow rows, npm results at lockfile line 1, package rows without a file). Subjects, `locationFromMessage` and
  `summaryOfConcept` (contracts 1.2–1.4) resolved them where the row names its site: 18 hits now come by subject and 1
  from the message. Five FNs remain where the row names the file but the wrong site (checkov line 1, trivy pod spec,
  a duplicate-block window starting five lines early, a misplaced dependency reported at its importer).
- **Beyond the reference scanner (19).** Concepts no Watchdog rule detects: business logic in a controller, mutable
  value objects, never-handled domain events, event schema change without upcaster, React index keys / missing hook
  dependencies / state mutation, unassociated form errors, unmanaged modal focus, autoplay media, consent checks,
  unchecked `any` from external data, catch-rethrow and mock dominance.

## Noise — the mechanisms (backlog)

During authoring every unexpected finding got a five-class verdict (all iterations, all repositories: 364
false-positive, 151 opinion-not-fact, 76 redundant, 22 shape-irrelevant, 328 valid — every `valid` one was fixed in
the repository before freeze). The noise was then generalised into **70 new FalsePositive backlog items covering 329
sites** (plus 5 existing items amended); their ids are in `_scans/backlog-filed.json` of the authoring workspace
(`01a1162b…` – `01a11639…`). The ten largest by sites (ties at 8 included):

| Sites | Repos | Dimension | Mechanism | Backlog id |
|---|---|---|---|---|
| 50 | 1 | D23 | D23 'Cross-context type X (A -> B) ... exposed in B's public surface ... couples the contexts' derives a type's bounded context from its PROJECT/assembly, so a context's own Domain types used by its o | `01a1162f-11e8-793e-a411-c3ed552d8ac4` |
| 42 | 4 | M4 | M4 'README/code drift' publishes rows that come straight from the model's reading of the README ('reported by the model that read the README against this repository; no term search was run for this on | `01a1162c-1c81-7e22-96ef-3b9d8c1b2d13` |
| 34 | 1 | D8 | The TS coverage run installs with `npm ci --ignore-scripts`, which skips native-binding install steps (libxmljs2's prebuilt binding); every suite that imports the application then fails to load, and D | `01a1162f-c932-7e86-8930-d460a177a3ac` |
| 19 | 2 | ED3 | ED3 'Event not named in past tense' and DM3 'Integration event couples to a producer-owned domain type' classify HTTP request/response records and contract summary DTOs (types under a *.Contracts name | `01a11630-b850-75db-bd2e-9c55164c5621` |
| 14 | 1 | D21 | D21 (model-judged naming consistency) emits rows whose text concludes 'These are distinct operations ... No inconsistency.: No change needed.' — the model's negative verdicts are published as findings | `01a11632-3b2e-78ce-8895-e0b486f990b4` |
| 10 | 2 | M4 | M4 checks a README feature claim by matching model-chosen phrases ('CSV import functionality in CLI', 'typescript-eslint strict', 'React hooks rules') against file and directory NAMES and manifest tex | `01a1162c-b24b-7a6d-bd9c-35a3f29da90d` |
| 9 | 9 | D5 | D5 'Off the main sequence' publishes a finding for every concrete, stable library (domain core, application layer, contracts) with distance >= 0.7, including rows whose own text says 'the shape a shar | `01a11631-6582-7027-84a0-e70cb9dfbdd2` |
| 9 | 8 | D17 | D17 'AnalyzerSeverityNone' reports a `dotnet_diagnostic.<id>.severity = none` line in .editorconfig as an undocumented, repository-wide suppression ('the only record that it was ever switched off is t | `01a1162b-203d-7da3-a028-602d2c87fbc4` |
| 8 | 2 | D24 | D24 model-judged 'redundant comment' asks to remove grouping headings inside long registration methods ('// Persistence', '// E-mail and reminders') and comments stating a physical purpose the code ca | `01a11632-a98a-76a8-b7a7-92ae4fc0637b` |
| 8 | 2 | R10 | R10 'Duplicated block (7 lines x 2 locations)' / 'with local edits' / 'concentrated across sibling directories' reports 5-10 line parallel accessors, shared call preludes (parse, look up, stop on a mi | `01a11636-72a9-780c-8629-cd48ad0b0718` |
| 8 | 1 | D8 | D8 ('Low coverage: 0.0%') and R4 ('No test reaches this file') report composition roots, process entry points, release scripts and thin browser glue over vendor SDKs as untested; the reachability/cove | `01a11630-3ab0-71e9-a09f-f53c8f7a2bb6` |


The largest is one structural rule (D23 takes each project for a bounded context). Two of the top six are M4, a
model-judged check (the model's reading of the README is published unchecked, and README claims are matched against
file NAMES). The third is an instrument defect in the TypeScript coverage run (`npm ci --ignore-scripts` breaks native
bindings, so D8 reports 44 % where the real coverage is 96.8 %).

## Instrument notes

- **Contained vs host.** The headline is the contained scan: the host has no gitleaks, semgrep, trivy, checkov or
  osv, so tool-backed rows disappear in host passes (IaC 2 / 19 on the host vs 14 / 19 contained; TS injection 2 / 21
  vs 7 / 21; TS dependencies 1 / 13 vs 6 / 13; TS secrets 7 / 17 vs 12 / 17). Model-judged dimensions (D19–D22, D24,
  D25, D26, M4, LA*) are composed **only** in host `--with-llm` passes, which is why 144 bands are unscored in the
  headline and why bench-csharp-maturity-history is 3 / 7 contained but 5 / 7 in its host pass (the ADR and README
  plants). `final-scores.json` carries each repository's last default host pass re-scored with the final harness as
  `hostModelPass`, labelled secondary.
- **The TypeScript sidecar repair.** Host passes ran without the TypeScript/JavaScript code model until the sidecar's
  `node_modules` were installed in the instrument worktree (`ERR_MODULE_NOT_FOUND`). All seven TS repositories with
  model-judged bands and bench-csharp-blazor-a11y (three `wwwroot/js` files) were re-measured from freestanding clones
  of their frozen tags. Result rows did not change anywhere (the blazor SARIFs are byte-identical to the broken-sidecar
  passes); the code model now composes D1/D2/D3/D26/D35/AX* in host passes. One valid-after-freeze finding came out of
  it (bench-ts-security-injection ADR 0003 states no motivation, D20) and is recorded for the next key version.
  Contained headline scans were never affected.
- **Model-judged non-determinism.** On byte-identical SARIF a model-judged score moved (blazor D19 80 → 90); LA6 went
  unmeasured in one WCAG pass when the judge answered a batch short; an M4 false positive of one pass did not recur in
  the next; two ts-baseline passes were byte-identical (cached responses). Bands on model-judged dimensions are
  therefore single observations; where a pass was repeated the results files say whether it agreed with itself.
- **Scan slot contention.** One box-wide slot serialises scans and builds (8 GB heap cap, at most three authoring
  agents), so a scan may wait but never shares the analyzer. Load still reaches dimensions that execute tests: D11
  flaky-test re-runs and D8 coverage run the suites, and a timing flake (FLK-002) failed 2 of 30 runs on a busy machine
  while D11's three re-runs passed. No recorded outcome changed because of contention.
- **Configuration.** Headline = default configuration. Compliance-framework runs (WCAG 2.2, GDPR) are secondary runs
  recorded in `scans[]` with a `configuration` object and never merged (e.g. blazor: 16 / 25 default, 18 / 25 with
  WCAG; ts-frontend-a11y: 12 / 24 and 14 / 24).

## Method lessons

- **Key first, in this order: key → README → code → scan.** Writing the labels before the code and before any scan is
  what keeps the benchmark from selecting on the outcome. Every FN above was re-verified as a real plant and kept;
  no label was dropped because the scanner missed it.
- **`benchmark/` prose steers scanners.** The key, README and journal sit in the scanned tree. A README-drift check
  read every `.json` as a manifest, so a key rationale naming a removed module masked the drift plant; model-judged
  documentation passes read the benchmark README. Rule (docs/AUTHORING.md): describe sites, never tokens; if a result
  changes because of `benchmark/` content, reword the repository — never exclude the directory for one scanner.
- **Scanners report sites in more ways than SARIF locations.** Three contract additions were needed to score what a
  scanner actually found without flattering it: `subject` (package/framework/type rows without a line), 
  `locationFromMessage` (sites named only in the message) and `summaryOfConcept` (an unlocated roll-up is neither a
  hit nor noise). Exact repository-relative paths (1.4) replaced suffix matching in the scorer, and now in the key
  validator too, so a root `CHANGELOG.md` and `packages/x/CHANGELOG.md` are different files on both sides.
- **The taxonomy must be scanner-neutral.** Concepts no rule of the reference scanner maps are legitimate plants
  (19 FNs); a benchmark built only from the reference scanner's rule list would have been blind to them by
  construction.
- **Default configuration is the headline.** A capability that needs an environment variable (the WCAG / GDPR
  frameworks) is "not measured" in the headline and reported as a secondary run.

## What did not reconcile

- The authoring log's estate figure "8/13" does not reproduce from any recorded scan: the final re-score and the
  recorded final contained scans of the five estate repositories agree on **7 / 14** (gateway 0/2, orders 0/2,
  dispatch 3/5, notifier 1/2, web 3/3), and the host passes give 6 / 14.
- The log's "5/7" for maturity-history is its host model pass; the contained headline is 3 / 7.
- bench-ts-security-dependencies: the authoring triage judged MIS-001 a hit (reported at the importing test file);
  the harness scores it an FN at its `package.json` site, and the headline follows the harness (6 / 13, judged 7 / 13).
- Six recorded results-file outcomes differ from the final re-score, each for a harness or key-version reason stated
  in that file's `final` scan entry: domain-events 22 → 24 TP (key v1.1.1 subjects), ts-domain-privacy 4 → 5 (key
  v1.0.1), ts-security-injection 6 → 7 (family `untrusted-data-executed`), csharp-security-injection one row now
  noise instead of uncovered (family `weak-password-hashing`), codehealth and csharp-readiness one X2 roll-up now
  `summary-of-concept` instead of noise.
