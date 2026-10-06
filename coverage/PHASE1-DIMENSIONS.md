# Phase 1 — which dimensions the two first repositories exercise

Scope: `bench-csharp-baseline-clean` and `bench-csharp-security-secrets`, measured by Watchdog rubric
`rubric-2026.10.1`. The authoritative per-dimension rows are in `coverage/matrix.json` (`phase1` field); this file
explains what the instrument actually reads, so plants are visible to it in principle and traps probe it.

Source paths are relative to the `kennel.canine.dev` checkout; line numbers are as of 2026-10-06 (`main` @ 6e577228e).

## 0. How to scan so that the Phase 1 dimensions are actually measured

| Need | Dimensions | Why |
|---|---|---|
| `scan.py --contained` (the analyzer image) | D28 (gitleaks), D29/D32 (semgrep), D30/D43 (osv-scanner/trivy), D31 (trivy config) | None of gitleaks/semgrep/trivy/osv-scanner is installed on the dev host (checked with `which`); they are baked only into the image (`engine/docker/analyzer/Dockerfile:490-511`). D28 is *withheld* when gitleaks is absent (DimensionMethods D28), so a host scan says nothing about it. |
| a second pass with `--with-llm` (host mode only) | D19–D22, D24, D25, M4, ED5, LA3, LA4 (baseline) | model-judged; they abstain offline (`tools/multilang/scan.py` docstring). |
| a .NET tree that builds; tests that run | D8–D11, D15, D17, D18, D23, D39, P9 | abstain build-less (`engine/src/Core/Edition/DimensionEditions.cs:63-77`). |
| a scripted git history | D15, D16, D28 (history pass), D34, D35 | git is the input. |

## 1. `bench-csharp-baseline-clean` — 100 dimensions measured, 54 must stay silent

Every finding concept gets `clean` regions; posture/metric/judged dimensions get `score-band`s.

**Measured (label `clean`, finding kind — 54):** D3 D10 D11 D12 D13 D14 D17 D23 D28 D29 D30 D31 D32 D43 D44 ·
AX1 AX2 AX3 AX4 AX6 AX8 AX9 · GD1 IC1 PF3 · X1–X7 X9 X10 X12–X30 X32 (X8 not applicable; X31 out of scope; there is no X11).
**Measured (`score-band`, + `clean` where the metric also emits located rows — 18 metric):** D1 D2 D4 D5 D6 D8 D9 D15 D16
D18 D26 D27 D34 D35 D39 AX10 P9 PF2.
**Posture (`score-band` — 18):** D36 D37 AX5 C2 M1 M2 M3 P1 P2 P3 P4 P5 P6 P7 P12 PF1 S1 SC1.
**Judged (`score-band`, wide tolerance, `--with-llm` — 10):** D19 D20 D21 D22 D24 D25 ED5 LA3 LA4 M4.

**`not-applicable` (must stay silent on a plain layered web API with no personal data, no markup, no messaging — 54):**
D7 (needs checkable ADRs) · D40–D42 (Kubernetes-gated) · AC1–AC7, LA2, LA5, LA6 (markup) · AX7 (vertical-slice gated) ·
C1, C3, C4, C5, LA1 (personal-data gated: `Compliance/C1/C1Analyzer.cs:95`, `C3/C3Analyzer.cs:101`) · DM1–DM12 (DDD-gated) ·
ED1–ED4, ES1–ES3 (event-driven / event-sourcing gated) · P8 (no database) · P10 (not a library) · P11 (no BDD tool) ·
R1–R11 (frontend JS/TS) · X8 (no Blazor interop). If the baseline grows a domain layer, the DM rows flip to `clean` —
decide before writing the key and record it.

### 1a. Findings ANY small C# repository gets regardless of its code (build the baseline to satisfy them honestly)

Measured, not guessed: a census of 144 small C# scans (150–5,000 production LoC) and 68 small TS scans in the local
sidecars (`~/Hentet/kennel/**/fingerprints.json`, scans since 2026-09-25, rubric 2026.09.15–09.18 — indicative, older
rubric) — share of repos where the row fired, then the code that emits it.

| Row (dimension: title) | Small C# repos | Emitted at | Satisfy honestly by |
|---|---|---|---|
| M2: "No ADRs" / "No architecture diagram/doc" | 134/144 | `Scanner/Maturity/M2/ArchitectureDocsAnalyzer.cs:193`, `:85` | `docs/adr/0001-….md` (+ a second ADR) and `docs/architecture.md` with a Mermaid/C4 diagram |
| SC1: "NuGet dependencies are not locked" | 120/144 | `Scanner/SupplyChain/SC1/SupplyChainHygieneAnalyzer.cs:505` | `RestorePackagesWithLockFile` + committed `packages.lock.json` (or Central Package Management) |
| X2: "Not all async methods take a CancellationToken" | 110/144 | `Scanner/Defects/X2/CancellationPropagationAnalyzer.cs:382` | every async method takes and forwards a `CancellationToken` |
| P3: "No SAST" (or "SAST runs, but gates no merge") | 109/144 | `Scanner/Readiness/P3/SecurityAndPerfToolingAnalyzer.cs:746` (`:733`) | a SAST step (CodeQL/semgrep) in CI **triggered on `pull_request`**, plus Dependabot config and a secret-scan step |
| S1: "No security response headers detected" / "No app-layer HTTPS enforcement detected" / "No inbound model validation detected" | 102/144 | `Scanner/Compliance/S1/S1Analyzer.cs:878-890` (web evidence only) | security-header middleware (CSP, HSTS, nosniff, frame policy), `UseHttpsRedirection`/`UseHsts`, validated request models |
| P2: "Logging is not universal" / "No structured logging" | 100/144 | `Scanner/Readiness/P2/ObservabilityAnalyzer.cs:258`, `ForeignObservability.cs:744-764` | `ILogger<T>` used in every runnable module, health-check endpoint |
| X5: "Nullable reference types not enabled everywhere" / null-forgiving suppressions | 91/144 | `Scanner/Defects/X5/NullableReferenceTypesAnalyzer.cs:1873` | `<Nullable>enable</Nullable>` in `Directory.Build.props`, no `!` |
| M3: "No src/ separation" / "No tests/ separation" / "Inconsistent root namespaces" | 88/144 | `Scanner/Maturity/M3/FolderStructureAnalyzer.cs:103-109`, `:444` | `src/` + `tests/`, one root-namespace prefix |
| P1: "No CI pipeline" / "CI build/test step not evidenced" | 64/144 | `Scanner/Readiness/P1/CicdAnalyzer.cs:201` | `.github/workflows/ci.yml` running `dotnet build` and `dotnet test` |
| C2: "No authorization" | 63/144 | `Scanner/Compliance/C2/C2Analyzer.cs` (N/A without an authz surface, `:42`) | `[Authorize]`/named policies on endpoints, or no endpoints needing them |
| P6: "No changelog" | 31/144 | `Scanner/Readiness/P6/ReleaseHygieneAnalyzer.cs:283` | `CHANGELOG.md` + a `<Version>` |
| M1: "Thin README" (< 120 words) / "No solution README" | 24/144 | `Scanner/Maturity/M1/DocumentationAnalyzer.cs:142`, bar at `:352` | README ≥ 120 words with build/run, testing and architecture **headings** |
| PF1: "No performance benchmarks" · PF2: "No allocation-aware APIs detected" | 22/144 · 14/144 | `Scanner/ModelAware/PF1/BenchmarkDisciplineAnalyzer.cs:144`, `PF2/AllocationHygieneAnalyzer.cs:134` | reward-leaning (neutral floor, never a deduction: `AbsencePolicy.cs` RewardLeaningIds). Do NOT gold-plate: key them as `score-band` at the neutral floor and accept the Recommendation rows as expected posture observations |
| PF3: "Awaits without ConfigureAwait(false)" | 17/144 | `Scanner/ModelAware/PF3/AsyncLatencyHygieneAnalyzer.cs:182` | applies to library code (≥5 awaits); a service is not charged — verify on the first scan |
| P7: "Outbound HTTP without resilience" | 20/144 | `Scanner/Readiness/P7/ResilienceAnalyzer.cs:65` | only if the service calls out: `AddStandardResilienceHandler` / timeouts |
| P12: "Coverage collected but not gated" | 16/144 | P12 analyzer | either don't collect coverage in CI, or gate it with a threshold |
| D9: "No tests found" | 7/144 | `Scanner/Testing/D9/TestDistributionAnalyzer.cs:543` | an xUnit test project with real tests |
| D36 (only once CI exists): "Unpinned build actions" | — | `Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2468` | pin every action by full commit SHA; with no CI at all D36 is NotApplicable (`:2747-2758`) |
| D44: end-of-life target framework | — | `engine/src/Core/Dependencies/ProductEolTable.cs:59` | target **net10.0**: net9.0 is past EOL (2026-05-12) and net8.0 ends 2026-11-10, after which a frozen key would rot |

Silent unless present (no finding when absent): D37 is NotApplicable without SECURITY.md
(`Scanner/SecurityPosture/D37/VulnerabilityDisclosurePolicyAnalyzer.cs:16,202`) — the baseline should **include**
`SECURITY.md` with a contact (→ 10); the secrets repo can omit it (→ NA, the presence/absence variant). P4 is
NotEvidenced (no row) without deploy automation (`Readiness/P4/DeploymentRollbackAnalyzer.cs:44-54`); P5's "No DR/backup
evidence" is raised only around container-volume persistence (`Readiness/P5/DisasterRecoveryAnalyzer.cs:755`).

## 2. `bench-csharp-security-secrets` — D13, D28, D29 (plus the same repo-level posture rows)

Give this repo the baseline's scaffolding (CI pinned by SHA, README, ADRs, lockfile, nullable, `src/`+`tests/`), so
that the only signal is the secrets theme; repo-level rows of concepts the key does not cover are reported as
`uncovered`, never as noise (CONTRACT.md), but any accidental real defect is fixed per the authoring loop.

### 2a. D13 — native in-process scanner (`engine/src/Core/Security/NativeSecretScanner.cs`, wrapped by `engine/src/Scanner/Security/D13/SecretScanningAnalyzer.cs`)

**Which files it opens** (`ScanAsync` :503, `IsExcludedPath` :633, `IsScannableTextFile` :777):
- *Skipped paths:* `/bin/ /obj/ /.git/ /node_modules/ /packages/ /.vs/ /.idea/ /.claude/ /.venv/ /artifacts/` (:248);
  **test paths** — a `test/`/`tests/` segment, a `.Tests`/`.UnitTests`/`.IntegrationTests`/`.Testing`/`.E2E`… project
  segment, `*Test(s).cs`/`*Spec(s).cs` basenames (`Core/Classification/SourceClassifier.cs:71-81`); segments
  `fixtures fixture __fixtures__ testdata testfixtures seeder seeders __mocks__ mocks` (:2113); any `test*cert*`
  directory (:2120); generated paths declared in `.gitattributes`/`.editorconfig`.
- *Binary key material first, by CONTENT not name* (:546-574): a CryptoAPI `PRIVATEKEYBLOB` (e.g. `sn -k` `.snk`) →
  `private-key-blob`; a PKCS#12/JKS container holding a private-key entry → `private-key-store`; both reported at line 1.
  A public-only `.snk` (`sn -p`) and a certificate-only trust store are **not** reported (`PrivateKeyBlobFile.cs`, `KeyStoreFile.cs`).
- *Text extensions only* (:291-302): all analysed source languages (`.cs .vb .fs .java .kt .py .php .rb .ex .exs .go .rs
  .swift .scala .dart .erl` + `.ts/.tsx/.js…`), `.csx .razor .cshtml .json .jsonc .yml .yaml .xml .config .env .ini
  .toml .properties .conf .sh .bash .ps1 .psm1 .bat .cmd .sql .pem .key .crt .cer .txt`, MSBuild
  `.props .targets .csproj .vbproj .fsproj .projitems .shproj .sln .slnx`, extensionless files (`Dockerfile`, `id_rsa`),
  and dotenv variants by name (`.env.production`, `.env.vite.local`; :346). **Not opened:** `.md` (prose), `.http`,
  `.pfx`/`.snk` text, anything > 1 MB (16 MB for `.sql .env .ini .toml .properties .conf .config .yml .yaml`).
- *Skipped by filename marker* (:319, :777-806): names containing `.example. .sample. .template. .dist.
  .development. .local.` — so **`appsettings.Development.json` and `appsettings.local.json` are never read**; dotenv
  templates `.env.example/.sample/.template/.tpl/.dist`; scanner config files (`.gitleaks.toml`, `.secrets.baseline` …).
- *"Declaration files"* — basename (without extension) ending `Constants`, `Constant`, **`Settings`**, `Defaults`
  (:2636). **`appsettings.json` is one.** There the entropy rule is off and the `password=` rule fires only when the
  value carries punctuation other than `_ - .` (:1018, :1023, :1698). `appsettings.Production.json` is *not* a
  declaration file and is scanned fully.

**What it matches** (per line, `ScanLines` :993):
- *Typed rules, no name needed* (:84-131): `AKIA[0-9A-Z]{16}`; `AIza…{35}`; `GOCSPX-…{28}`; `sb_secret_…`;
  PEM `-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----` **with key body** (:2489); Slack `xox[baprs]-…`;
  GitHub `ghp_{36}` / `github_pat_…`; JWT `eyJ….….…` (excused when it grants nothing/forgeable demo); bcrypt
  `$2[abxy]$NN$<53>`; a punctuation-bearing key passphrase of exactly 16/24/32/48/64/128 chars.
- `high-entropy-secret` (:1273): `name = "value"` or `"name": "value"` where name matches
  `secret|token|api[_-]?key|apikey|passw|pwd|access[_-]?key|client[_-]?secret|private[_-]?key`, value ≥ 20 chars, no
  whitespace, not `${…}`/`<…>`/`%…%`/`[…]`/`??`/env-var reference/path/URI-of-words/all-letters/dotted-words/sequential
  run/weak-root, and Shannon entropy ≥ 4.0 bits/char — or ≥ 32-char hex at ≥ 3.0 under a secret name that is not
  `hash|digest|checksum|fingerprint` (:2807-2913).
- `hardcoded-credential` (:1320, :231): `password|passwd|pwd` immediately followed by `=`/`:` (so connection strings
  `Password=…;` qualify; `PasswordHash = …` does not), value starting alphanumeric, ≥ 6 chars, not a dev word
  (`postgres password changeme root admin sa secret test local …`, :241), not a weak root (`password123 changeme
  admin123 letmein qwerty do-not-use …`, :410), length ≥ 12 or entropy ≥ 3.0; not a method call, not a commented line;
  **never in CI pipeline files or compose files** (:2008, :2104).
- `signing-key` (:170, :1339, :1926): property names containing `Secret|IssuerSigningKey|SymmetricSecurityKey|SigningKey|
  JwtKey|HmacKey|TokenSigningKey` with a value ≥ 16 chars; **a GUID-shaped value is reported**; not active in
  declaration-file gating (so `"Jwt": { "SigningKey": "…" }` in `appsettings.json` is seen).
- `hardcoded-crypto-key` (:1574): `Key|IV = Encoding.*.GetBytes("…")` / `Convert.FromBase64String("…")` (≥ 8 chars), plus
  cipher-length key constants in a file that constructs a cipher.
- `http-authorization-credential` / `http-cookie-credential` (:1374): `authorization` `:`/`=` then a quoted
  `Bearer|Basic|Token <≥20 chars, entropy ≥ 4>` — matches JSON/YAML/header strings, **not** C#'s
  `new AuthenticationHeaderValue("Bearer", "…")`; `http-basic-credential`; `credential-file` (a file named
  `password|secret|token|api-key|private-key|access-key[.txt]` holding exactly one token ≥ 8 chars, not under `docs/`, :1535).

**Line-level excuses that silence every rule** (`IsExcusedLine` :1150): the AWS documentation example keys
(`AKIAIOSFODNN7EXAMPLE`, …); `gitleaks:allow` / `codehealth:allow-secret` markers; **any line containing** `change in`,
`change this`, `(change`, `changeme`, `your-`, `your_`, `<your`, `replace-this`, `replace_this`, `example`, `placeholder`,
`dummy`, `sample`, `to be replaced` (:400). After scanning, keyboard-row/ascending-run values (`sk_1234567890abcdef…`)
are dropped (`SecretScanningAnalyzer.cs:102`).

**Reporting:** one finding per (secret type, file) — the fingerprint is line-insensitive
(`SecretScanningAnalyzer.cs:108-114`), so **two AWS keys in one file are ONE result**; title `Leaked secret: <type>`;
every row carries CWE-798 + CWE-259 whatever the type (`SecurityCweMap.cs:36`); score `10 − 5 × distinct` (:120).

### 2b. D28 — gitleaks over history and working tree (`engine/src/Scanner/Security/D28/SecretsHistoryAnalyzer.cs`)

Two `gitleaks detect` passes (full history, then `--no-git` over the tree), merged by (rule, file, line) and by value
fingerprint (DimensionMethods D28). Rules: gitleaks' **defaults** (`useDefault = true`) plus
`engine/rulesets/gitleaks/watchdog-gitleaks.toml` (aws-secret-key, http-cookie/authorization/basic credentials,
password-hash, crypto-key-passphrase, gcp-oauth-client-secret, supabase-secret-key, hardcoded-crypto-key). Title
`Secret: <gitleaks rule>` (`Shared/Scanners/ScanParsers.cs:266`); history rows carry `properties.commitSha` in SARIF.
Dropped paths (`SecretNoiseFilter.IsNoisyPath`, `Shared/Scanners/SecretNoiseFilter.cs:3853`): docs (`.md .mdx
.markdown`), `.resx`…, minified/vendored JS, `bin/obj` copies, test trees (`test tests testdata testfixtures fixtures
__tests__ __fixtures__ spec specs`), test-named files (`*Tests.cs`, `*Test.cs`, `test_*`), placeholder-named files (a
name segment `example sample template dist placeholder fake dummy`), `launchsettings.json`; placeholder VALUES
(`password changeme your-key example sample fake xxxxxxxx …`, :3743). **D28 does not share D13's `.development.`/`.local.`
filename skip or its `*Settings` declaration-file gate** — so `appsettings.Development.json` is read by D28 only.

### 2c. D29 — semgrep, the secret-shaped rules that can fire on a C# repo

From the prebaked registry packs (`p/security-audit`, `p/owasp-top-ten`; contents are whatever semgrep.dev served at
image build — a cached copy at `~/Hentet/kennel/backlog-01a0e0dc-46a0/packs-after/` holds 225 + 560 rules, **no C# secret
rule**) the language-generic ones apply to any file: `generic.secrets.security.detected-username-and-password-in-uri`
and `…detected-stripe-restricted-api-key`. Watchdog's own `engine/rulesets/semgrep/watchdog-sast.yml` adds
`watchdog-credential-in-jwt-payload-csharp` (:15697) and `watchdog-secret-in-argv-csharp` (:22848) plus CI-workflow
secret rules (`watchdog-secret-interpolated-into-run` :10303, `…-promoted-to-job-env` :10390,
`watchdog-static-cloud-credential-in-workflow` :13737). Keep Kubernetes `Secret` manifests out of this repo — they are
D31's `WD-K8S-0002` (`Shared/Scanners/CommittedSecretManifestScan.cs:81`) and belong to `bench-csharp-security-iac`.

### 2d. Plants the instrument can see in principle, and traps that probe it

Planted secrets are generated, revoked-format fakes (random bodies, never `EXAMPLE`, never keyboard runs), placed on
lines with **none** of the excuse words above, outside test/fixture paths, one per (type, file).

| Label | Plant | Expected Watchdog outcome (to verify, never to tune the key) |
|---|---|---|
| must-fire | AWS access key id + 40-char secret in `src/…/Storage/S3Options.cs` constants | D13 `aws-access-key`; D28 `aws-access-token`/`aws-secret-key` |
| must-fire | GitHub PAT in `deploy/publish.ps1` | D13 `github-token`; D28 |
| must-fire | `"Jwt": { "SigningKey": "<48 random chars>" }` in `appsettings.json` | D13 `signing-key` (not declaration-gated) |
| must-fire | `Password=Q7v#…;` (punctuated) connection string in `appsettings.json` | D13 `hardcoded-credential` (punctuation passes the declaration gate) |
| must-fire (probe) | `Password=Rk7Tq2Wm9Lx4;` (alphanumeric) in `appsettings.json` | **D13 FN by design** (declaration-file gate, :1018/:1023); D28 generic rule may catch — record what happens |
| must-fire | `Password=…` in `appsettings.Production.json` | D13 + D28 (not a declaration file) |
| must-fire (probe) | real-looking DB password in `appsettings.Development.json` | **D13 never opens the file**; D28 reads it — a scanner-neutral leak either way |
| must-fire | PEM RSA private key with body at `src/…/Keys/signing.pem`; `sn -k` key pair `src/….snk`; PFX with a private key | D13 `private-key` / `private-key-blob` / `private-key-store` |
| must-fire | `aes.Key = Encoding.UTF8.GetBytes("…32 chars…")` | D13 `hardcoded-crypto-key` |
| must-fire | `"Authorization": "Bearer <token>"` in a committed JSON client config | D13 `http-authorization-credential` |
| must-fire (probe) | `new AuthenticationHeaderValue("Bearer", "<token>")` in C# | D13 regex cannot match this shape — likely FN; D28 generic may catch |
| must-fire | credentials in a URI, `"Orders": "postgres://app:<random pw>@db:5432/orders"` | D29 `detected-username-and-password-in-uri`; D13 silent (no `password=` binding, name not secret-like) |
| must-fire | secret committed in commit N, deleted in N+1 (history only) | D28 with `commitSha` (`secret-in-version-history`); D13 silent (correct) |
| must-fire | key in `.env.production` | D13 (dotenv family by name) + D28 |
| must-fire (probe) | real key in a `//` comment line (`// old key: AKIA…`) | typed rules still fire on comments; the leak is real |
| must-not-fire | `"ApiKey": "YOUR_API_KEY_HERE"`, `"<your-key>"`, `"changeme"`, `"${STRIPE_KEY}"`, `"__CLIENT_SECRET__"` | excused (placeholder hints, non-literal, substitution marker) |
| must-not-fire | `Environment.GetEnvironmentVariable("DB_PASSWORD")`, `configuration["Jwt:SigningKey"]`, `password = secrets.GetPassword()` | not literals / method calls |
| must-not-fire | `appsettings.example.json`, `.env.example` with realistic-format fakes | skipped by name in both scanners |
| must-not-fire | AKIA-format key in `tests/…/FakeCredentials.cs` and in `tests/fixtures/` | test/fixture paths excluded in both |
| must-not-fire | SHA-256 hex as `ExpectedSha256`, `contentHash` in `packages.lock.json`, `TenantId`/`ClientId` GUIDs, base64 icon bytes | not secret-named / entropy rule not reached |
| must-not-fire (probe) | GUID under a `…Secret` property name that is NOT a secret (e.g. `SecretRotationJobId`) | D13 reports GUIDs under `Secret` names (:1926) — possible FP |
| must-not-fire | `AKIAIOSFODNN7EXAMPLE` in a code comment; a public key (`BEGIN PUBLIC KEY`), a `.crt`; a public-only `.snk`; a cert-only trust store | known example / public material |
| must-not-fire | `POSTGRES_PASSWORD: localdev` in `docker-compose.yml`; `Password=postgres` dev connection string | compose files excluded from the password rule; dev-word list |
| must-not-fire | a fake key quoted in `README.md` / `docs/*.md` | prose never opened (D13) / docs path dropped (D28) |

Do **not** use `gitleaks:allow` or `codehealth:allow-secret` markers anywhere: they are scanner-specific suppressions,
and a vendor-neutral benchmark must not carry one scanner's opt-out.
