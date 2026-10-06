# Watchdog — Phase 1 results (backlog candidates for the owner)

Engine: kennel main 6a05dfb6c, rubric-2026.10.1. Contained scans (gitleaks, semgrep, trivy, osv in the analyzer image)
plus a host-mode model-judged pass for the baseline. Per-finding verdicts: `bench-csharp-*.json` beside this file.
Nothing here was fixed in Watchdog — this is the report.

## bench-csharp-security-secrets (v1.0.0) — secret concepts

| | |
|---|---|
| recall (must-fire found) | **11 / 17** |
| trap resistance | **23 / 24** |
| noise on secret concepts | **1 / 22** results |
| loop | 2 iterations; 3 accidental real defects fixed in the repo (a history copy of a token, Dependabot cooldown, a compose image by tag) |

False negatives (each plant verified real):

1. **Punctuated `Password=` values are invisible to both secret engines** — SEC-005 (`*Settings` class default),
   SEC-006 (`appsettings.Production.json`), SEC-007 (`appsettings.Development.json`), SEC-017 (history only). The one
   alphanumeric password (SEC-004) was caught by gitleaks `generic-api-key`. One blind spot, four misses.
2. **D13 never opens `*.Development.*` / `*.local.*`** — a shared, network-reachable dev database password is a
   real leak (SEC-007).
3. **`new AuthenticationHeaderValue("Bearer", "<token>")`** — the most common C# way to set a bearer token is not
   matched (SEC-013); only header-string shapes are.
4. **Credentials in a connection URI** (`postgres://user:pw@host/db` in a shell script, SEC-014) — missed by D13, D28
   and D29.

Noise / precision:

5. **D13 reports a GUID under a `*Secret*` property name** (`SecretRotationJobId`, TRP-003) — false positive.
6. **D13 deduplicates per (secret type, file) at the first line**, so that false positive swallowed the real signing
   key two lines later (SEC-003): the user is pointed at the wrong line and never sees the real one from D13.
7. **No `SECURITY.md` is NotApplicable, not a low score** (D37) — the absence of a disclosure policy is not measured.

## bench-csharp-baseline-clean (v1.0.0) — the control

| | |
|---|---|
| deterministic results on certified-clean code | 3 (D5 opinion, P6 opinion, D17 false positive) |
| model-judged results | 2 over two passes (D19 valid → repo fixed, M4 false positive) |
| score bands in / out / unscored | 30 in, 1 out (M2), 17 unscored |
| loop | 3 iterations; 2 accidental real defects fixed (CI advisory scan never scheduled, no contributor guidance) |

8. **D17 flags a documented, scoped suppression** — `.editorconfig` switches CA2007 off with the reason on the line
   above and `src/.editorconfig` re-enables it for production code; D17 says "the only record … is this line".
   Now trap TRP-001.
9. **M4 is non-deterministic** — two identical model passes: one produced a README-drift finding (false: test
   projects are documented under Testing), the other did not; M4 moved 100 → 90.
10. **M2 caps a small service at 70 for having 3 ADRs instead of 8** — opinion; a size-relative bar would fit better.
11. **P6 wants ≥ 3 versioned changelog entries** — penalises young projects for being young.
12. **D5 "zone of pain" on a concrete application layer** of a 3-project layered service — heuristic, opinion.

## Off-theme rows seen on the secrets repo (recorded, not scored there)

PF3 ConfigureAwait and P10 public API surface on an ASP.NET Core *service* (shape-irrelevant: library guidance),
PF1 no benchmarks (opinion), DS-0026 no HEALTHCHECK (opinion: orchestrators probe `/health`), D5 on a two-type
contracts assembly (shape-irrelevant), D8 "no collector" (not a code claim).
