"""Pins mappings/watchdog.json (contract 1.1) against message shapes taken verbatim from a real Watchdog scan
(bench-csharp-security-secrets, iteration 1): one dimension-level ruleId carries several concepts, so the message
must decide, and hygiene rows on a secret dimension must never land on a secret concept."""
import os
import re
import unittest

from cai_bench.keyfile import load_json
from cai_bench.mapping import Mapping

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
M = Mapping(load_json(os.path.join(ROOT, "mappings", "watchdog.json")))
SECRET = {"hardcoded-credential", "hardcoded-password", "hardcoded-cryptographic-key", "committed-private-key",
          "secret-in-version-history"}
SHA = {"commitSha": "5cd6eab6232d8b88aec74c762c5c8da6f07f8ac1"}

CASES = [
    # (ruleId, message, properties, the secret concepts it must map to)
    ("D13", "Leaked secret: github-token: github-token detected. Treat the value as compromised", {}, {"hardcoded-credential"}),
    ("D13", "Leaked secret: high-entropy-secret: high-entropy-secret detected.", {}, {"hardcoded-credential"}),
    ("D13", "Leaked secret: http-authorization-credential: detected.", {}, {"hardcoded-credential"}),
    ("D13", "Leaked secret: aws-access-key: aws-access-key detected.", {}, {"hardcoded-credential"}),
    ("D13", "Leaked secret: hardcoded-credential: hardcoded-credential detected.", {}, {"hardcoded-password"}),
    ("D13", "Leaked secret: signing-key: signing-key detected.", {}, {"hardcoded-cryptographic-key"}),
    ("D13", "Leaked secret: hardcoded-crypto-key: detected.", {}, {"hardcoded-cryptographic-key"}),
    ("D13", "Leaked secret: private-key-blob: detected.", {}, {"committed-private-key"}),
    ("D13", "Leaked secret: private-key: detected.", {}, {"committed-private-key"}),
    ("D13", "Leaked secret: private-key-store: detected.", {}, {"committed-private-key"}),
    ("D28", "Secret: generic-api-key: gitleaks matched rule 'generic-api-key' here, in git history.", SHA,
     {"hardcoded-credential", "secret-in-version-history"}),
    ("D28", "Secret: aws-access-token: gitleaks matched rule 'aws-access-token' here", SHA,
     {"hardcoded-credential", "secret-in-version-history"}),
    ("D28", "Secret: hardcoded-crypto-key: gitleaks matched rule 'hardcoded-crypto-key' here", SHA,
     {"hardcoded-cryptographic-key", "secret-in-version-history"}),
    ("D28", "Secret: private-key: gitleaks matched rule 'private-key' here", SHA,
     {"committed-private-key", "secret-in-version-history"}),
    ("D28", "High secret: WD-SECRET-0004: `src/x/export-api.pfx` is a PKCS#12 archive that contains a key", {},
     {"committed-private-key"}),
    ("D28", "High secret: WD-SECRET-0001: `x.snk` is a private key store", {}, {"committed-private-key"}),
    ("S1", "Cryptographic key material is a compile-time constant: `Key` is the AEAD cipher key", {},
     {"hardcoded-cryptographic-key"}),
    # hygiene on secret dimensions: no secret concept
    ("D29", "High: dependabot-missing-cooldown: This Dependabot configuration does not set a cooldown period.", {}, set()),
    ("D31", "Medium IaC: WD-COMPOSE-0002: Line 19 runs service `db` from `postgres:17.6-alpine`", {}, set()),
    ("D31", "Low IaC: DS-0026: No HEALTHCHECK defined. Add HEALTHCHECK instruction in your Dockerfile.", {}, set()),
    ("S1", "MD5/SHA1 is constructed here, and both are collision-broken.", {}, set()),
]


# Every multi-concept dimension: real message shapes (verbatim from local Watchdog scans, truncated; a few D7 / D10 rows
# that no local scan carries are written in the engine's own title format) -> the ONE concept they evidence, or none.
DIMENSION_CASES = [
    ('D3', 'ClassTooLong: Kcp: ClassTooLong — 493 significant lines (blank, comment-only and punctuation-only lines excluded), 26 methods. The bar is 400 significant lines', ['god-class']),
    ('D3', 'TooManyMethods: xt: TooManyMethods — 78 methods. The bar is 30 methods; this is 48 over it, 2.60× the bar.', ['god-class']),
    ('D3', 'FileTooLong: pro/apex.ts: FileTooLong — 574 significant lines (blank, comment-only and punctuation-only lines excluded). The bar is 500 significant lines', ['oversized-source-file']),
    ('D3', 'MethodTooLong: Verify.Run: MethodTooLong — Run runs 135 significant lines (blank, comment-only and punctuation-only lines excluded) in one body.', ['long-method']),
    ('D5', 'Unstable project CodeHealth.Core.Cohesion: CodeHealth.Core.Cohesion has instability 0.83 with 5 dependents.', ['unstable-dependency']),
    ('D5', 'Circular dependency: Circular dependency: Billing → Orders → Billing', ['module-dependency-cycle']),
    ('D5', "Off the main sequence: zod: zod: abstractness 0.29, instability 0.00, distance 0.71 — zone of pain — concrete and depended on by 3 project(s), so it's rigid to change.", ['module-off-main-sequence']),
    ('D7', 'Circular dependency: Circular dependency: Billing → Orders → Billing', ['module-dependency-cycle']),
    ('D7', "ADR rule violated: Domain must not reference Infrastructure: src/Domain/Order.cs:12 references `Infrastructure`, which this repository's own ADR forbids", ['layer-dependency-violation']),
    ('D7', "ADR enforcement could be stronger: Use hexagonal ports: ADR 'Use hexagonal ports' is marked enforceable but no analyzer/test was found", ['architecture-rules-unenforced']),
    ('D7', 'ADR parse warning: docs/adr/0003.md: front matter could not be read', []),
    ('D10', "No assertions: Empty: This method's body runs code, and no assertion call was recognised in it.", ['test-without-assertion']),
    ('D10', 'No assertions (empty test): seed: Test method has an empty body — it asserts nothing and exercises no code.', ['test-without-assertion']),
    ('D10', 'Skipped test: testComponentsSchemasArrayOfRefsOfNullableItems: Skipped — throws XCTSkip', ['skipped-test-without-reason']),
    ('D10', 'Fixed-sleep synchronisation: DeadLockTest: This test starts a thread it started and then orders itself against it with `Thread.Sleep(5200)` — a fixed wait, not a signal', ['flaky-test']),
    ('D10', 'Test cannot fail: Parses_all: The assertion sits inside a try whose catch swallows the failure.', []),
    ('D12', 'Vulnerable: Microsoft.NETCore.App: Microsoft.NETCore.App [2.0.0, — ) severity. 2.0.0', ['vulnerable-dependency']),
    ('D12', "Deprecated: xunit: xunit 2.4.1 — Legacy — the publisher's replacement is `xunit.v3`", ['deprecated-dependency']),
    ('D12', 'Dependency pinned to a stale untagged commit: github.com/flynn/go-shlex: Direct dependency `github.com/flynn/go-shlex` is required at `v0.0.0-20150515145356-3f9db97f8568`', ['outdated-dependency']),
    ('D12', 'No Package.resolved committed (Package.swift): Package.swift declares 1 dependency and no `.library` product, so it is an APPLICATION', ['dependencies-not-locked']),
    ('D12', 'Prerelease dependency: StyleCop.Analyzers: StyleCop.Analyzers resolves to 1.2.0-beta.556, a prerelease build.', ['prerelease-dependency']),
    ('PF3', 'Sync-over-async blocking: 121 blocking call(s) on async work (.Wait()/.GetAwaiter().GetResult()) — these waste a thread', ['blocking-on-async-code']),
    ('PF3', 'Awaits without ConfigureAwait(false): Only 0/965 awaits use ConfigureAwait(false).', ['missing-configure-await']),
    ('R2', 'Cyclomatic Complexity: P95 cyclomatic 9 · 0 function(s) > 10 · 0 > 20 (of 34)', []),
    ('R2', 'Complex function render (cyclomatic 19, cognitive 21): render has cyclomatic complexity 19 and cognitive complexity 21; this row is raised above a cyclomatic bar of 10.', ['high-cyclomatic-complexity']),
    ('R8', "Unused dependency 'tslib': Declared in the root package.json but never imported anywhere in that package", ['unused-dependency']),
    ('R8', "Unlisted import 'lodash': Imported but not declared in any reachable package.json", ['undeclared-dependency']),
    ('R8', "Test-only dependency 'rxjs' in production deps: Only test files import it — move it to devDependencies.", ['misplaced-dev-dependency']),
    ('X1', "async void method: Application_UnhandledException: `async void` can't be awaited and its exceptions crash the process", ['async-void-method']),
    ('X1', 'Sync-over-async (deadlock risk): Blocking on a Task with `.Wait()`/`.GetAwaiter().GetResult()` can deadlock', ['blocking-on-async-code']),
    ('X1', '`async` callback passed to `forEach`: `forEach` ignores what its callback returns', []),
    ('X3', 'Swallowed exception (empty catch): An empty catch block silently discards the error — failures vanish with no log and no rethrow.', ['empty-catch-block']),
    ('X3', 'Swallowed exception (caught, then discarded): `catch` takes every exception and records none of it', ['empty-catch-block']),
    ('X3', "Rethrow loses stack trace (`throw ex;`): `throw ex;` resets the exception's stack trace to this line", ['rethrow-resets-stack-trace']),
    ('X3', 'Unguarded deserialized result under a catch list that cannot catch it: `message` is used without ever being checked for null, but `JsonSerializer` returns null', []),
    ('X5', 'Nullable reference types not enabled everywhere: 3/7 NRT-eligible project(s) enable <Nullable>', ['nullable-analysis-disabled']),
    ('X5', "Strict null checking is not enabled everywhere the repository type-checks: This repository commits no tsconfig, so whatever type-checks it uses tsc's own defaults", ['nullable-analysis-disabled']),
    ('X5', 'Null-forgiving operator (`!`) suppressions reduce the NRT score: ~0.1 `!` suppressions per 1k syntax nodes — 1 suppression(s) across the 6761 syntax node(s)', ['null-forgiving-suppression']),
    ('X5', 'Symbol treated as nullable, then dereferenced unguarded: This method contradicts itself about `p`: line 211 writes `p?.Runs`, which says `p` can be null', ['null-dereference']),
    ('X5', 'Null-tolerant access on a value the branch has already proved null: This branch was entered because `member` is null — line 150 says so', []),
    ('S1', 'No security response headers detected: No Content-Security-Policy / X-Frame-Options / X-Content-Type-Options configuration found — defense in depth, even when a', ['security-response-headers']),
    ('S1', 'No app-layer HTTPS enforcement detected: No UseHttpsRedirection/UseHsts and no reverse-proxy signal — transport security is unverified at the app layer. (−2.0 on this card.)', ['https-enforcement']),
    ('S1', 'Secure cookie flags not detected: No CookieSecurePolicy/HttpOnly/SameSite configuration found. (−1.5 on this card; skip if the app sets no cookies.)', ['insecure-cookie-flags']),
    ('S1', 'No inbound model validation detected: No ModelState/[ApiController]/FluentValidation signal — inbound payloads reach handlers unvalidated. (−2.0 on this card.)', ['inbound-input-validation']),
    ('S1', 'Weak cipher: DES / 3DES / RijndaelManaged-bare is deprecated or broken. Use AES-GCM via `Aes.Create()` with explicit key/iv sizes.', ['weak-cryptographic-algorithm']),
    ('S1', 'Ciphertext is encrypted but not authenticated: This type encrypts through `SymmetricAlgorithm`, whose every cipher mode (CBC/ECB/OFB/CFB/CTS) is unauthenticated', ['weak-cryptographic-algorithm']),
    ('S1', 'Weak hash algorithm: MD5/SHA1 is constructed here, and both are collision-broken. If this digest protects anything — a signature, an integrity or tamper check, a credential', ['weak-hash-algorithm']),
    ('S1', 'Cryptographic key material is a compile-time constant: `Key` is the AEAD cipher key and is a compile-time constant, so the secret this operation depends on is published with the source.', ['hardcoded-cryptographic-key']),
    ('S1', 'Cryptographic key material is a compile-time constant: `ENCRYPTION_SYMMETRIC_KEY` is the symmetric cipher key, and its shipped DEFAULT is a compile-time constant — an installation that never overrides it', ['hardcoded-cryptographic-key']),
    ('S1', 'Cryptographic key material is a compile-time constant: The value is the symmetric cipher key and is a compile-time constant, so the secret this operation depends on is published with the source.', ['hardcoded-cryptographic-key']),
    ('S1', "The encryption IV is the same for every message: This encryption's initialisation vector is a compile-time constant, so every message encrypted under the same key gets the same IV.", ['hardcoded-cryptographic-key']),
    ('S1', 'TLS certificate validation disabled: `ServerCertificateCustomValidationCallback` is assigned `DangerousAcceptAnyServerCertificateValidator`, so every TLS peer certificate is accepted', ['improper-certificate-validation']),
    ('S1', 'TLS certificate validation disabled: `rejectUnauthorized: false` is set on a TLS client, so every peer certificate is accepted — including one an attacker presents.', ['improper-certificate-validation']),
    ('S1', 'Token validation disabled: `RequireSignedTokens = false` means the token SIGNATURE is never verified — a token this API accepts need not have been issued by anyone.', ['token-signature-or-expiry-not-validated']),
    ('S1', 'Token validation disabled: `ValidateLifetime = false` means expired tokens keep working indefinitely, so a leaked or revoked token never stops being valid.', ['token-signature-or-expiry-not-validated']),
    ('S1', 'Token validation disabled: `ValidateAudience`, `ValidateIssuer`, `ValidateLifetime` are all set to `false`, which means a token minted for a DIFFERENT relying party is accepted here.', ['token-signature-or-expiry-not-validated']),
    ('S1', 'Token validation disabled: `ValidateAudience`, `ValidateIssuer` are all set to `false`, which means a token minted for a DIFFERENT relying party is accepted here.', []),
    ('S1', 'Token validation disabled: `ValidateAudience = false` means a token minted for a DIFFERENT relying party is accepted here.', []),
    ('S1', 'Third-party script without Subresource Integrity: `https://www.googletagmanager.com/gtag/js?id=G-FG8DDV0GBR` is executed by this page with no Subresou', ['missing-subresource-integrity']),
    ('S1', "Password key derivation is priced too cheaply: This code fixes PBKDF2-SHA-1 at 1,000 iterations. A key-derivation function's only defence is the cost of ONE guess", ['insufficient-password-hashing']),
    ('S1', "Password hashing without a KDF: Identifier 'PasswordHash' looks like a password-hash field/property, but no KDF (PBKDF2 / Argon2 / BCrypt / PasswordHasher) was found anywhere in the source", ['insufficient-password-hashing']),
    ('S1', 'Cryptographic key material is a compile-time constant: `SaltBytes` is the key-derivation salt and is a compile-time constant, so the secret this operation depends on is published with the source.', ['insufficient-password-hashing']),
    ('S1', 'Cryptographic key material is a compile-time constant: The value is the key-derivation salt and is a compile-time constant, so the secret this operation depends on is published with the source.', ['insufficient-password-hashing']),
    ('S1', 'Middleware order: UseAuthorization appears before UseAuthentication — authorization runs without an authenticated principal.', []),
    ('S1', 'OIDC metadata fetched over HTTP: `RequireHttpsMetadata = false` allows the OIDC discovery doc to be fetched over plain HTTP.', ['cleartext-transmission']),
    ('S1', 'Password hash compared with `==`: Password-hash field compared with `==` — use a constant-time compare to avoid timing oracles (CryptographicOperations.FixedTimeEquals).', []),
    ('D17', 'TodoComment: //TODO: Load state from previously suspended application — source code is not a task system: move the work to your tracker', ['technical-debt-marker']),
    ('D17', 'FixmeComment: // FIXME(bartlomieju) — source code is not a task system: move the work to your tracker and leave a reference instead', ['technical-debt-marker']),
    ('D17', 'HackComment: // Hack to remove extra padding in the custom notifications view — a workaround marked in source', ['technical-debt-marker']),
    ('D17', 'TodoComment repeated across 15 files: The identical TodoComment appears in 15 files (15 occurrences) — almost certainly one boilerplate line', ['technical-debt-marker']),
    ('D17', 'Whole file has no live code — 1 debt marker inside it: Every line in this file is a comment or blank — it declares no type, member, using or attribute, so nothing in it reaches the build. Its 1 debt marker (1 FixmeComment) all sit', ['technical-debt-marker']),
    ('D17', 'NoWarnInCsproj: CS1591 — this project generates an XML documentation file as a build output', ['suppressed-diagnostic']),
    ('D17', 'BarePragmaDisable: #pragma warning disable EF1002 — the disable is closed again below, so its scope is not the problem', ['suppressed-diagnostic']),
    ('D17', 'FileScopedPragmaDisable repeated across 15 files: The identical FileScopedPragmaDisable (`#pragma warning disable ADR0032D`) appears in 15 files', ['suppressed-diagnostic']),
    ('D17', 'NoWarnInCsproj — 7 warning codes suppressed in one element: A single <NoWarn> suppresses 7 warning codes (CS1591;CA1305;CA1307;CS8600;CS8602;CS8604;CS8605)', ['suppressed-diagnostic']),
    ('D17', 'AnalyzerSeverityNone: UAC1005 — this rule is switched off for every file the section matches', ['suppressed-diagnostic']),
    ('D17', 'BareSuppressMessage: SuppressMessage — the suppression records no reason', ['suppressed-diagnostic']),
    ('D17', 'DisabledAnalyzers: EnableNETAnalyzers — this does not switch a rule off, it stops the analyzers running for the whole project', ['suppressed-diagnostic']),
    ('D17', 'DuplicateNoWarn: NoWarn CA2200 is listed more than once for the same build configuration — remove the duplicate.', ['suppressed-diagnostic']),
    ('D17', 'CommentedOutCode: 5 consecutive commented-code lines', ['commented-out-code']),
    ('D17', 'Whole file has no live code — 1 debt marker inside it: Every line in this file is a comment or blank — it declares no type, member, using or attribute, so nothing in it reaches the build. Its 1 debt marker (1 CommentedOutCode) all sit', ['commented-out-code']),
    ('D17', 'EmptyCatchBlock: empty catch block — the error is discarded with nothing recorded, so a failure here leaves no trace anywhere.', ['empty-catch-block']),
    ('D17', 'WriteOnlyPrivateField: private CancellationToken cancellationToken — assigned 1 time(s), read never', ['unused-code']),
    ('D17', "Dead code: StateMachineUtility: NamedType StateMachineUtility — Roslyn's SymbolFinder walked every project the solution loads", ['unused-code']),
    ('D17', 'ObsoleteWithoutCallers: [Obsolete] PopulateFlags', ['unused-code']),
    ('D17', 'DeadPreprocessorBranch: #if DEBUG_MODEL — no definition of that symbol was found anywhere this analysis looks', ['unreachable-code']),
    ('D17', 'ObsoleteWithCallers: [Obsolete] .ctor', ['obsolete-symbol-still-used']),
    ('D17', 'DiscardedPureResult: typeStr.Remove(0, 5); — strings are immutable, so this call cannot change the text it was called on', []),
    ('D17', 'DemotedWarningsAsErrors: TreatWarningsAsErrors — this repository turns the warnings-are-errors gate ON in a scope above this line', []),
    ('IC1', 'Fake-async — async method never awaits: `Batch` is declared `async` but never awaits anything, so it runs synchronously while pretending to be asynchronous.', ['incomplete-implementation']),
    ('IC1', 'Hollow method — returns a constant without doing the work: `AfterEdit` looks like it should compute a result but its body just returns a constant — a ', ['incomplete-implementation']),
    ('IC1', 'Empty method body — does nothing with its inputs: `Apply` takes parameters but its body is empty — it accepts inputs and does nothing.', ['incomplete-implementation']),
    ('IC1', 'Skeleton type — most members are unfinished: `IConfigurationPresentationFactory` has 3 unfinished members out of 6 declared members', ['incomplete-implementation']),
    ('IC1', "Member throws NotSupportedException: `Read`'s body only throws NotSupportedException — sometimes a deliberate contract, often an unfinished stub. Confirm it's intentional.", ['incomplete-implementation']),
    ('IC1', "Empty method body: `Forget` has an empty body — confirm it's an intentional no-op and not an unfinished method.", ['incomplete-implementation']),
    ('IC1', 'Dead branch — condition is always false: A branch guarded by a literal `false` can never execute — left-over disabled code. Remove it or restore the real condition.', ['unreachable-code']),
    ('IC1', 'Unfinished stub — throws NotImplementedException: `CreateMemberTypeConfigurationResponseModel` is a shipped member whose body only throws — and it is ', ['not-implemented-placeholder']),
    ('IC1', 'Placeholder data left in code: A placeholder value ("john doe") is still in shipped code — sample/mock data that was never replaced with the real thing.', ['not-implemented-placeholder']),
    ('IC1', 'Commented-out code: A line of code has been commented out rather than removed — dead weight that rots and confuses. Delete it (version control remembers).', ['commented-out-code']),
    ('IC1', 'Disabled test: A test is skipped/ignored — coverage that looks present but never runs. Re-enable it or delete it so the green run means something.', ['skipped-test-without-reason']),
    ('IC1', 'Skipped test marks a known-real bug: A test is skipped with reason "Flaky: Marten projection timing — likely affected by Plan 11 outbox removal" — the behavior', []),
    ('D31', "High IaC: DS-0002: Image user should not be 'root'. Specify at least 1 USER command in Dockerfile with non-root user as argument.", ['container-excessive-privilege']),
    ('D31', "Medium IaC: KSV-0001: Can elevate its own privileges. Container 'mongo' of StatefulSet 'content-db' should set 'securityContext.allowPrivilegeEscalation' to false.", ['container-excessive-privilege']),
    ('D31', "High IaC: WD-COMPOSE-0001: Line 171 bind-mounts `/var/run/docker.sock` — the container runtime's CONTROL SOCKET — into this service.", ['container-excessive-privilege']),
    ('D31', 'Medium IaC: CKV_K8S_20: Containers should not run with allowPrivilegeEscalation', ['container-excessive-privilege']),
    ('D31', "Low IaC: KSV-0011: CPU not limited. Container 'app' of Pod 'secure-pod' should set 'resources.limits.cpu'.", ['container-missing-resource-limits']),
    ('D31', 'Medium IaC: CKV_K8S_13: Memory limits should be set', ['container-missing-resource-limits']),
    ('D31', "Low IaC: KSV-0015: CPU requests not specified. Container 'app' of Pod 'secure-pod' should set 'resources.requests.cpu'.", ['iac-misconfiguration']),
    ('D31', "Medium IaC: WD-DOCKER-0003: Line 2 builds this stage `FROM ubuntu:jammy` — a tag, which is a POINTER the image's publisher can move at any time", ['mutable-image-reference']),
    ('D31', "Medium IaC: DS-0001: ':latest' tag used. Specify a tag in the 'FROM' statement for image 'ruby'.", ['mutable-image-reference']),
    ('D31', 'Medium IaC: WD-COMPOSE-0002: Line 20 runs service `neo4j` from `neo4j:5.23-community`, pulled from a registry by a TAG', ['mutable-image-reference']),
    ('D31', 'Medium IaC: CKV_K8S_43: Image should use digest', ['mutable-image-reference']),
    ('D31', 'High IaC: WD-DOCKER-0001: Line 7 downloads `https://github.com/jwilder/dockerize/releases/download/v0.6.1/dockerize-linux-amd64-v0.6.1.tar.gz`, unpacks it', ['download-without-integrity-check']),
    ('D31', "High IaC: WD-DOCKER-0014: Line 21 fetches a signing key over the network and installs it as a package manager's trust anchor", ['download-without-integrity-check']),
    ('D31', 'Critical IaC: DS-0031: Secrets passed via `build-args` or envs or copied secret files. Possible exposure of secret env "ARG_BASED_PASSWORD" in ENV.', ['hardcoded-credential']),
    ('D31', 'High IaC: WD-K8S-0002: This `kind: Secret` manifest commits its secret material as literal values in the file: `SECRET_KEY` (line 11)', ['hardcoded-credential']),
    ('D31', "High IaC: KSV-0109: ConfigMap with secrets. ConfigMap 'app-config' in 'microservices-app' namespace stores secrets in key(s) or value(s)", ['hardcoded-credential']),
    ('D31', 'Low IaC: DS-0026: No HEALTHCHECK defined. Add HEALTHCHECK instruction in your Dockerfile.', ['iac-misconfiguration']),
    ('D31', 'High IaC: AWS-0086: aws_s3_bucket.state: S3 Access block should block public ACL. No public access block so not blocking public acls.', ['iac-misconfiguration']),
    ('D31', 'Medium IaC: KSV-0125: Restrict container images to trusted registries. Container filebeat in deployment filebeat (namespace: microservices-app)', ['iac-misconfiguration']),
    ('D31', "Medium IaC: KSV-01010: ConfigMap with sensitive content. ConfigMap 'app-config' in 'microservices-app' namespace stores sensitive contents", ['iac-misconfiguration']),
    ('D31', 'Medium IaC: WD-K8S-0004: This pod spec sets neither `automountServiceAccountToken` nor `serviceAccountName`.', ['iac-misconfiguration']),
    ('D31', 'High IaC: WD-DOCKER-0002: Line 18 generates an SSH private key at `/home/disco/.ssh/id_dsa` during the build', ['iac-misconfiguration']),
    ('D31', 'Medium IaC: WD-DOCKER-0004: Line 15 runs `npm install -g` on `yarn` without pinning a version', ['iac-misconfiguration']),
    ('D31', "Medium IaC: DS-0013: 'RUN cd ...' to change directory. RUN should not be used to change directory", []),
    ('D31', "High IaC: DS-0029: 'apt-get' missing '--no-install-recommends'. '--no-install-recommends' flag is missed", []),
    ('D31', "Medium IaC: CKV_DOCKER_9: Ensure that APT isn't used", []),
    ('D31', "High IaC: DS-0022: Deprecated MAINTAINER used. MAINTAINER should not be used: 'MAINTAINER gijs@pythonic.nl'.", []),
    ('D36', 'No SBOM: No SBOM generation or committed SBOM found — produce one with what your ecosystem ships', ['build-provenance-and-signing']),
    ('D36', 'No build provenance: No SLSA provenance generation or build attestation found in CI — nothing binds a released artifact to the build that produced it', ['build-provenance-and-signing']),
    ('D36', 'No artifact signing: No artifact signing found in CI — sign your released artifacts with whatever your ecosystem ships', ['build-provenance-and-signing']),
    ('D36', 'No checksums published for release artifacts: The release uploads downloadable files but publishes no digest for them (release_macos.yml)', ['build-provenance-and-signing']),
    ('D36', "Packages are published outside CI: `package.json` wires up this project's release as the `release:publish` script, `package.json` runs `npm publish`, and NOTHIN", ['build-provenance-and-signing']),
    ('D36', 'Unpinned build actions: CI references GitHub Actions by a floating ref (@main / @tag) rather than a pinned commit SHA, weakening build integrity.', ['unpinned-ci-action']),
    ('D36', 'CI runs a third-party container image from a mutable tag: A `run:` step executes `', ['mutable-image-reference']),
    ('D36', 'CI installs an unverified third-party binary: A `run:` step downloads `erlang/rebar3` from the network and puts it into the build', ['download-without-integrity-check']),
    ('D36', 'No dependency advisory monitoring: Nothing in this repository re-checks its pinned dependencies when an advisory is published: no Dependabot or Renovate configu', ['security-tooling-in-ci']),
    ('D36', 'Secret exported as workflow-level env: 4 workflow-level `env:` entries interpolate a secret (build-images.yml:31 (SCW_NAMESPACE); ci.yml:16 (TURBO_TOKEN)', ['ci-secret-exposure']),
    ('D36', "Workflow token permissions not restricted: No workflow declares a `permissions:` block, so every job runs with the repository's default GITHUB_TOKEN scope", ['ci-token-excessive-permissions']),
    ('D36', 'Secret passed as a command-line argument: 2 CI command(s) pass a credential in the command line (as an argument of its own, or attached to an option as `--flag=', ['secret-in-process-arguments']),
    ('D36', 'Release publish has no approval gate: 1 workflow(s) publish a package to a registry with no point at which a person is asked to approve the run', []),
    ('D36', 'Dependency source pinned to a moving git ref: 2 Cargo dependencies resolve from a git remote at a MOVING ref rather than a registry version or a pinned commit', []),
    ('D29', 'Medium: potential-dos-via-decompression-bomb: Detected a possible denial-of-service via a zip bomb attack. By limiting the max bytes read, you can mit', []),
    ('D29', 'High: watchdog-electron-node-integration-ts: This Electron window enables `nodeIntegration` and turns `contextIsolation` off in the same `webPreferenc', []),
    ('D29', 'Medium: watchdog-unbound-identifier-assigned-js: This statement writes to the bare identifier `using`, and this file binds no `using` that the write c', []),
    ('D29', 'High: insecure-use-string-copy-fn: Finding triggers whenever there is a strcpy or strncpy used. This is an issue because strcpy does not affirm the si', []),
    ('D29', 'Medium: watchdog-identifier-read-out-of-scope-js: `languageList` is read here and is bound nowhere this line can see — this file declares `languageLis', []),
    ('D29', 'High: watchdog-prototype-lookup-request-key-js: A value read straight out of this request -- `req.params`, `req.query` or `req.body` -- is used as the', []),
    ('D29', "High: watchdog-secret-env-nonsecret-fallback-ts: This reads the application's secret from the environment and, when that variable is unset or empty, s", []),
    ('D29', 'High: watchdog-postmessage-embedded-frame-unverified-sender-ts: This page posts to `window.parent`, so it runs as an embedded frame with a counterpart', []),
    ('D29', 'Medium: insecure-file-permissions: These permissions `16877` are widely permissive and grant access to more people than may be necessary. A good defau', []),
    ('D29', 'Medium: watchdog-shell-quoted-argument-in-argv-exec-ruby: This is the multi-argument (argv) form of a Ruby exec call, so NO shell runs: Ruby hands the', []),
    ('D29', 'High: watchdog-unpinned-package-install-in-run: This CI step installs a third-party package by name with no version, so what lands on the runner is wh', []),
    ('D29', "Medium: request-data-write: Found user-controlled request data passed into '.write(...)'. This could be dangerous if a malicious actor is able to cont", []),
    ('D29', 'Medium: WD-RUBY-ARGUMENT-MUTATED-0001: `parse_args` (line 389) destructively mutates `args`, an object its CALLER owns: this line calls `args.shift`, ', []),
    ('D29', "Low: wildcard-cors: CORS policy allows any origin (using wildcard '*'). This is insecure and should be avoided.", []),
    ('D29', 'Low: avoid_hardcoded_config_DEBUG: Hardcoded variable `DEBUG` detected. Set this by using FLASK_DEBUG environment variable. This is a semgrep security', []),
    ('D29', "High: secrets-inherit: This workflow uses `secrets: inherit` to pass all of the calling workflow's secrets to a reusable workflow. This violates the p", ['ci-secret-exposure']),
    ('D29', 'High: run-shell-injection: Using variable interpolation `${{...}}` with a workflow input in a `run:` step could allow an attacker to inject their own ', ['ci-workflow-injection']),
    ('D29', "Medium: react-insecure-request: Unencrypted request over HTTP detected. Change the URL's scheme on this line to https and confirm the host serves it. ", ['cleartext-transmission']),
    ('D29', 'High: watchdog-assembled-code-string-evaluated-ts: This call evaluates a code string that was ASSEMBLED at runtime -- a value is spliced into JavaScri', ['code-injection']),
    ('D29', 'High: detect-child-process: Detected calls to child_process from a function argument `pid`. This could lead to a command injection if the input is use', ['command-injection']),
    ('D29', 'Medium: allow-privilege-escalation-no-securitycontext: In Kubernetes, each pod runs in its own isolated environment with its own set of security polic', ['container-excessive-privilege']),
    ('D29', 'Medium: react-dangerouslysetinnerhtml: Detection of dangerouslySetInnerHTML from non-constant definition. This can inadvertently expose users to cross', ['cross-site-scripting']),
    ('D29', 'High: dependabot-missing-cooldown: This Dependabot configuration does not set a cooldown period. Newly published packages can be malicious or unstable', ['dependency-release-cooldown-missing']),
    ('D29', 'High: watchdog-unverified-download-in-run: This CI step downloads a file over the network and then treats what came back as CODE — it unpacks it, mark', ['download-without-integrity-check']),
    ('D29', 'Medium: watchdog-eol-node-runtime-in-workflow: This workflow installs a Node.js major version that has reached END OF LIFE, so every job in it - inclu', ['end-of-life-platform']),
    ('D29', 'High: watchdog-secret-env-literal-fallback-ts: This reads a credential from the environment and, when the variable is unset or empty, silently substit', ['hardcoded-credential']),
    ('D29', 'High: session-hardcoded-secret: A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets', ['hardcoded-cryptographic-key']),
    ('D29', 'Medium: storage-use-secure-tls-policy: Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2. Azure Storage uses TLS ', ['iac-misconfiguration']),
    ('D29', 'Medium: ssl-mode-no-verify: Detected SSL that will accept an unverified connection. This makes the connections susceptible to man-in-the-middle attack', ['improper-certificate-validation']),
    ('D29', 'Low: cookie-session-no-secure: Default session middleware settings: `secure` not set. It ensures the browser only sends the cookie over HTTPS. This is', ['insecure-cookie-flags']),
    ('D29', 'High: go-unsafe-deserialization-interface: Deserializing into `interface{}` allows arbitrary data structures and types, which can lead to security vul', ['insecure-deserialization']),
    ('D29', 'Medium: math-random-used: `math/rand` is not cryptographically secure — its stream is reproducible from its seed and predictable from observed output ', ['insecure-randomness']),
    ('D29', 'Medium: mass-assignment: Mass assignment or Autobinding vulnerability in code allows an attacker to execute over-posting attacks, which could create a', ['mass-assignment']),
    ('D29', "Medium: missing-or-broken-authorization: Anonymous access shouldn't be allowed unless explicit by design. Access control checks are missing and potent", ['missing-authorization']),
    ('D29', 'High: watchdog-mutable-job-container-image: This job runs inside a third-party CONTAINER image named by a mutable reference. This is strictly wider th', ['mutable-image-reference']),
    ('D29', 'Medium: open-redirect: The application redirects to a URL specified by user-supplied input `req` that is not validated. This could redirect users to m', ['open-redirect']),
    ('D29', 'Medium: path-join-resolve-traversal: Possible writing outside of the destination, make sure that the target path is nested in the intended destination', ['path-traversal']),
    ('D29', 'High: watchdog-secret-in-argv-csharp: A credential is placed in the ARGUMENT VECTOR of an external command. Argv is not private: on Linux any local pr', ['secret-in-process-arguments']),
    ('D29', 'High: watchdog-credential-written-to-log-ts: A value whose name identifies it as a credential -- an access code, password, API key or token -- is pass', ['sensitive-data-in-logs']),
    ('D29', 'High: watchdog-card-verification-value-in-claims-csharp: The card verification value is written into a claims container this application persists. PCI', ['sensitive-data-in-token-payload']),
    ('D29', 'High: watchdog-ssrf-js: A value read straight out of this request -- `req.query`, `req.body` or `req.params` -- becomes the WHOLE destination of an ou', ['server-side-request-forgery']),
    ('D29', "Medium: watchdog-error-swallowed-as-success-go: This handler tests an error and converts it into success: the enclosing function's contract is to retu", ['silent-error-fallback']),
    ('D29', 'High: watchdog-quoted-identifier-interpolation-not-doubled-csharp: A schema-qualified SQL identifier is assembled here by writing a value straight int', ['sql-injection']),
    ('D29', 'High: java-jwt-decode-without-verify: Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise th', ['token-signature-or-expiry-not-validated']),
    ('D29', 'High: github-actions-mutable-action-tag: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed b', ['unpinned-ci-action']),
    ('D29', "Medium: watchdog-accessor-mutates-shared-state-go: This method's name promises a read, and it writes. The assignment target is reached THROUGH a field", ['unsynchronized-shared-state']),
    ('D29', 'Medium: WD-RUBY-DUPLICATE-METHOD-0001: `-` is defined twice in this class body — here, and again at line 154. Ruby evaluates a class body top to botto', ['unused-code']),
    ('D29', 'Medium: insufficient-rsa-key-size: The RSA key size 512 is insufficent by NIST standards. It is recommended to use a key length of 2048 or higher.', ['weak-cryptographic-algorithm']),
    ('D29', 'Medium: insecure-hash-algorithm-md5: Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not sui', ['weak-hash-algorithm']),
    ('D29', 'Medium: watchdog-xmldocument-dtd-entity-expansion-csharp: Loading this `XmlDocument` hands the document to a reader that opens with DTD processing ena', ['xml-external-entity']),
    ('D32', 'High: watchdog-sensitive-personal-data-in-log: Special-category or directly-identifying personal data appears to be written to a log or console sink. ', ['sensitive-data-in-logs']),
    ('D32', 'Medium: watchdog-personal-data-in-url: Personal data appears to be placed in a URL or query string. URLs are recorded in server and proxy access logs,', ['sensitive-data-in-url']),
    ("SC1", "Go module dependencies are not locked: There is a go.mod but no go.sum — module versions aren't pinned", ["dependencies-not-locked"]),
    ("SC1", "NuGet dependencies are not locked: No packages.lock.json and no central package management", ["dependencies-not-locked"]),
]

DOC = load_json(os.path.join(ROOT, "mappings", "watchdog.json"))
MATRIX = load_json(os.path.join(ROOT, "coverage", "matrix.json"))
MULTI = sorted(r["id"] for r in MATRIX["rows"] if r["status"] == "in-scope" and len(r["concepts"]) > 1)


def _dims_of_rule(rx):
    return set(re.findall(r"[A-Z]+[0-9]+", rx))


class WatchdogMapping(unittest.TestCase):
    def test_real_messages_map_to_the_right_secret_concepts(self):
        for rule, msg, props, want in CASES:
            with self.subTest(rule=rule, msg=msg[:40]):
                self.assertEqual(set(M.concepts_of(rule, msg, props)) & SECRET, want)

    def test_rotate_roll_up_is_ignored(self):
        self.assertIsNotNone(M.ignored("D28", "Rotate the exposed credentials — git history can't be un-committed: …"))
        self.assertIsNone(M.ignored("D28", "Secret: generic-api-key: …"))

    def test_secret_concepts_are_one_family(self):
        self.assertEqual({M.family_of(c) for c in SECRET - {"secret-in-version-history"}}, {"hardcoded-secret"})
        self.assertIsNone(M.family_of("secret-in-version-history"))


    def test_every_multi_concept_dimension_lands_each_message_on_one_concept_or_none(self):
        for rule, msg, want in DIMENSION_CASES:
            with self.subTest(rule=rule, msg=msg[:60]):
                self.assertEqual(sorted(M.concepts_of(rule, msg, {})), want)

    def test_cases_cover_every_multi_concept_dimension(self):
        self.assertEqual(len(MULTI), 20)
        self.assertEqual(sorted(set(MULTI) - {r for r, _, w in DIMENSION_CASES if w} - {r for r, *_ in CASES}), [])

    def test_no_multi_concept_dimension_keeps_a_bare_ruleid_rule(self):
        # a plain dimension-id rule would offer every result of the dimension to the concept, whatever its title
        for cid, spec in DOC["concepts"].items():
            for r in spec["rules"]:
                if isinstance(r, str):
                    self.assertEqual(_dims_of_rule(r) & set(MULTI), set(), cid)
                else:
                    self.assertTrue(r.get("messages") or r.get("properties"), (cid, r["rule"]))
                    self.assertTrue(r.get("source"), (cid, r["rule"]))

    def test_unknown_title_on_a_discriminated_dimension_maps_to_no_concept(self):
        for d in MULTI + ["SC1"]:
            with self.subTest(dimension=d):
                self.assertEqual(M.concepts_of(d, "Some future title: with a detail", {}), [])

    def test_off_concept_cases_are_documented_with_a_source(self):
        offs = [(_dims_of_rule(o["rule"]), re.compile(o["message"], re.I)) for o in DOC["offConcept"]]
        self.assertTrue(all(o.get("source") for o in DOC["offConcept"]))
        for rule, msg, want in DIMENSION_CASES:
            documented = any(rule in ds and rx.search(msg) for ds, rx in offs)
            with self.subTest(rule=rule, msg=msg[:60]):
                self.assertEqual(documented, not want)

    def test_unevidenced_pairs_have_no_rule_but_keep_the_dimension(self):
        for u in DOC["unevidenced"]:
            spec = DOC["concepts"][u["concept"]]
            self.assertIn(u["dimension"], spec["dimensions"])
            self.assertFalse(any(u["dimension"] in _dims_of_rule(r if isinstance(r, str) else r["rule"]) for r in spec["rules"]), u)


if __name__ == "__main__":
    unittest.main()
