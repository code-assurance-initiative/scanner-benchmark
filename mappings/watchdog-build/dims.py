# Per-dimension curation. Keys:
#  k   kind: finding | posture | metric | judged | runtime
#  c   concepts (taxonomy ids)
#  cs, ts  C#/TypeScript relevance: yes | partial | no
#  lb  language basis (why)
#  r   thematic repos (beyond the baseline-clean repos, which are added automatically)
#  b   baseline override: None (auto) | "na:<why>" -> baseline gets not-applicable
#  loc metric with located findings (adds must-fire / clean)
#  req extra requirements to measure
#  oos out-of-scope reason
CB, CS = "bench-csharp-baseline-clean", "bench-csharp-security-secrets"
CI, CD, CX = "bench-csharp-security-injection", "bench-csharp-security-dependencies", "bench-csharp-security-iac"
CH, CA, CE = "bench-csharp-codehealth", "bench-csharp-architecture", "bench-csharp-domain-events"
CR, CM, CT = "bench-csharp-readiness", "bench-csharp-maturity-history", "bench-csharp-tests"
TB, TS, TI = "bench-ts-baseline-clean", "bench-ts-security-secrets", "bench-ts-security-injection"
TD, TA, TH = "bench-ts-security-dependencies", "bench-ts-frontend-a11y", "bench-ts-codehealth"
EST = "estate-<company>-<service>"

M = "dimension-language-matrix.json"
LLM = "--with-llm pass (model-judged; abstains offline)"
CONT = "contained scan (external scanner baked in the analyzer image)"
BUILD = "a .NET tree that builds (abstains build-less: DimensionEditions.WithheldNotSelfSufficient)"
TESTRUN = "build + test execution"
GIT = "scripted git history"
RUNTIME_OOS = "runtime card: needs the application BOOTED in the no-coupling sandbox (scan.py --runtime-evidence, nested dockerd); v1 does not boot, so the card is not built"
DDD = "na:DDD-gated (no domain layer in the baseline service)"
EVT = "na:event-driven gated (baseline has no messaging)"
ESG = "na:event-sourcing gated (baseline has no event store)"
K8S = "na:Kubernetes-workload gated (baseline ships no k8s manifests)"

D = {
 "D1":  dict(k="metric", c=["high-cyclomatic-complexity"], cs="yes", ts="yes", lb=M, r=[CH, TH], loc=True),
 "D2":  dict(k="metric", c=["high-cognitive-complexity"], cs="yes", ts="yes", lb=M, r=[CH, TH], loc=True),
 "D3":  dict(k="finding", c=["god-class", "oversized-source-file", "long-method"], cs="yes", ts="yes", lb="assessed: matrix 'unknown'; measured on 28/28 local TS scans (DimensionMethods: per logical type)", r=[CH, TH]),
 "D4":  dict(k="metric", c=["duplicated-code"], cs="yes", ts="no", lb=M + " (Ts not-supported; R10 is the TS clone dimension)", r=[CH], loc=True),
 "D5":  dict(k="metric", c=["module-dependency-cycle", "unstable-dependency", "layer-dependency-violation", "module-off-main-sequence"], cs="yes", ts="partial", lb="assessed: .csproj reference graph (DimensionMethods); TS only via workspace packages", r=[CA], loc=True),
 "D6":  dict(k="metric", c=["low-class-cohesion"], cs="yes", ts="yes", lb=M, r=[CH, TH], loc=True),
 "D7":  dict(k="finding", c=["architecture-rules-unenforced", "layer-dependency-violation", "module-dependency-cycle"], cs="yes", ts="no", lb="assessed: Roslyn per checkable ADR (DimensionMethods)", r=[CA], b="na:no checkable ADR in the baseline (D7 needs ADRs with enforcement fields)"),
 "D8":  dict(k="metric", c=["test-coverage"], cs="yes", ts="yes", lb="assessed: coverlet/Cobertura/lcov (DimensionMethods)", r=[CT], req=[TESTRUN]),
 "D9":  dict(k="metric", c=["test-pyramid-distribution"], cs="yes", ts="yes", lb="assessed: test projects/frameworks; measured on 24 local TS scans", r=[CT], req=[TESTRUN]),
 "D10": dict(k="finding", c=["test-without-assertion", "skipped-test-without-reason", "excessive-mocking", "flaky-test", "test-failure-swallowed"], cs="yes", ts="yes", lb="assessed: Roslyn per test; measured on 19 local TS scans", r=[CT, TH], req=[TESTRUN]),
 "D11": dict(k="finding", c=["flaky-test"], cs="yes", ts="yes", lb="assessed: re-runs the suite (DimensionMethods)", r=[CT], req=[TESTRUN]),
 "D12": dict(k="finding", c=["vulnerable-dependency", "outdated-dependency", "deprecated-dependency", "prerelease-dependency", "dependencies-not-locked"], cs="yes", ts="yes", lb=M, r=[CD, TD], req=["package restore (dotnet list package / npm metadata)"]),
 "D13": dict(k="finding", c=["hardcoded-credential", "hardcoded-password", "hardcoded-cryptographic-key", "committed-private-key"], cs="yes", ts="yes", lb=M + " (agnostic)", r=[CS, TS]),
 "D14": dict(k="finding", c=["license-policy-violation"], cs="yes", ts="yes", lb=M, r=[CD, TD], req=["package restore"]),
 "D15": dict(k="metric", c=["churn-complexity-hotspot"], cs="yes", ts="yes", lb="assessed: git x Roslyn/JS/Razor complexity (DimensionMethods)", r=[CM, EST], loc=True, req=[GIT, BUILD]),
 "D16": dict(k="metric", c=["knowledge-concentration"], cs="yes", ts="yes", lb="assessed: git authorship, language-neutral", r=[CM, EST], req=[GIT]),
 "D17": dict(k="finding", c=["technical-debt-marker", "suppressed-diagnostic", "commented-out-code", "empty-catch-block", "unused-code", "unreachable-code", "obsolete-symbol-still-used"], cs="yes", ts="yes", lb="assessed: Roslyn markers; measured on 28 local TS scans", r=[CH, TH], req=[BUILD]),
 "D18": dict(k="metric", c=["solution-structure"], cs="yes", ts="no", lb="assessed: .sln/.slnx structure (never measured on local TS scans)", r=[CA], req=[BUILD]),
 "D19": dict(k="judged", c=["documentation-quality"], cs="yes", ts="yes", lb="language-neutral (docs)", r=[CM], req=[LLM]),
 "D20": dict(k="judged", c=["adr-quality"], cs="yes", ts="yes", lb="language-neutral (ADRs)", r=[CM], req=[LLM]),
 "D21": dict(k="judged", c=["inconsistent-naming"], cs="yes", ts="yes", lb="assessed: symbol sample", r=[CH, TH], req=[LLM]),
 "D22": dict(k="judged", c=["internal-api-inconsistency"], cs="yes", ts="partial", lb="assessed: IsPackable/.Contracts public surface (C#-shaped)", r=[CA], req=[LLM]),
 "D23": dict(k="finding", c=["boundary-type-leakage"], cs="yes", ts="partial", lb="assessed: Roslyn structural classification", r=[CA], req=[BUILD]),
 "D24": dict(k="judged", c=["low-value-comments"], cs="yes", ts="yes", lb="language-neutral (comment sample)", r=[CH, TH], req=[LLM]),
 "D25": dict(k="judged", c=["adr-conformance"], cs="yes", ts="yes", lb="language-neutral (ADRs vs structure)", r=[CM], req=[LLM]),
 "D26": dict(k="metric", c=["oversized-module"], cs="yes", ts="yes", lb="assessed: per-project size; measured on 24 local TS scans", r=[CA], loc=True),
 "D27": dict(k="metric", c=["call-indirection"], cs="yes", ts="partial", lb="assessed: symbol-resolved call sample (C#-centred)", r=[CA]),
 "D28": dict(k="finding", c=["hardcoded-credential", "hardcoded-password", "hardcoded-cryptographic-key", "committed-private-key", "secret-in-version-history"], cs="yes", ts="yes", lb=M + " (agnostic)", r=[CS, TS], req=[CONT + ": gitleaks", GIT]),
 "D29": dict(k="finding", c=["sql-injection", "nosql-injection", "command-injection", "code-injection", "path-traversal", "xml-external-entity", "insecure-deserialization", "cross-site-scripting", "regex-denial-of-service", "ldap-injection", "xpath-injection", "server-side-request-forgery", "open-redirect", "weak-cryptographic-algorithm", "weak-hash-algorithm", "insecure-randomness", "missing-authorization", "mass-assignment", "error-information-exposure", "improper-certificate-validation", "token-signature-or-expiry-not-validated", "hardcoded-password", "hardcoded-cryptographic-key", "hardcoded-credential", "sensitive-data-in-logs", "ci-workflow-injection", "ci-secret-exposure", "unpinned-ci-action", "download-without-integrity-check", "end-of-life-platform", "insecure-cookie-flags", "iac-misconfiguration", "container-excessive-privilege", "mutable-image-reference", "unbounded-allocation-from-untrusted-length", "unsynchronized-shared-state", "unreachable-code", "unused-code", "silent-error-fallback", "redundant-condition-operand", "missing-subresource-integrity", "secret-in-process-arguments", "cleartext-transmission", "dependency-release-cooldown-missing", "sensitive-data-in-token-payload", "log-injection", "prototype-pollution", "container-security-context-missing", "host-path-mount", "container-privilege-escalation-allowed", "container-runs-as-root", "container-confinement-profile-unset", "privileged-container", "overly-permissive-rbac"], cs="yes", ts="yes", lb=M, r=[CI, TI, CS, TS, CX], req=[CONT + ": semgrep"]),
 "D30": dict(k="finding", c=["vulnerable-dependency"], cs="yes", ts="yes", lb=M, r=[CD, TD], req=[CONT + ": osv-scanner/trivy"]),
 "D31": dict(k="finding", c=["container-excessive-privilege", "container-missing-resource-limits", "mutable-image-reference", "download-without-integrity-check", "hardcoded-credential", "iac-misconfiguration", "improper-certificate-validation", "container-runs-as-root", "privileged-container", "host-namespace-sharing", "host-path-mount", "container-privilege-escalation-allowed", "container-excess-capabilities", "container-writable-root-filesystem", "container-confinement-profile-unset", "container-security-context-missing", "missing-health-probes", "missing-image-healthcheck", "automounted-service-account-token", "overly-permissive-rbac", "image-not-from-allowed-registry", "container-missing-resource-requests"], cs="yes", ts="yes", lb=M + " (agnostic)", r=[CX], req=[CONT + ": trivy config"]),
 "D32": dict(k="finding", c=["sensitive-data-in-logs", "sensitive-data-in-url", "sensitive-data-in-browser-storage"], cs="yes", ts="yes", lb=M + "; engine/rulesets/semgrep/gdpr.yml languages include csharp and typescript", r=[CI, TI], req=[CONT + ": semgrep"]),
 "D34": dict(k="metric", c=["knowledge-freshness"], cs="yes", ts="yes", lb="assessed: git authorship, language-neutral", r=[CM, EST], loc=True, req=[GIT]),
 "D35": dict(k="metric", c=["change-coupling"], cs="yes", ts="yes", lb="assessed: git co-change, language-neutral", r=[CM, EST], loc=True, req=[GIT + " (>=10 revisions per file, >=5 shared commits)"]),
 "D36": dict(k="posture", c=["build-provenance-and-signing", "unpinned-ci-action", "mutable-image-reference", "download-without-integrity-check", "security-tooling-in-ci", "dependencies-not-locked", "ci-secret-exposure", "ci-token-excessive-permissions", "secret-in-process-arguments"], cs="yes", ts="yes", lb="language-neutral (CI files)", r=[CD, TD]),
 "D37": dict(k="posture", c=["vulnerability-disclosure-policy"], cs="yes", ts="yes", lb="language-neutral (SECURITY.md/security.txt)", r=[CR]),
 "D39": dict(k="metric", c=["compiled-code-size"], cs="yes", ts="no", lb="assessed: IL from BUILT .NET assemblies (Mono.Cecil); never measured on local TS scans", r=[CH], loc=True, req=[BUILD + " (deep run compiles the target)"]),
 "D40": dict(k="posture", c=["network-egress-policy"], cs="yes", ts="yes", lb="language-agnostic YAML (DimensionMethods)", r=[CX], b=K8S),
 "D41": dict(k="posture", c=["workload-syscall-confinement"], cs="yes", ts="yes", lb="language-agnostic YAML", r=[CX], b=K8S),
 "D42": dict(k="posture", c=["runtime-threat-detection-and-admission"], cs="yes", ts="yes", lb="language-agnostic YAML", r=[CX], b=K8S),
 "D43": dict(k="finding", c=["malicious-dependency"], cs="yes", ts="yes", lb=M, r=[CD, TD], req=[CONT + ": osv-scanner"]),
 "D44": dict(k="finding", c=["end-of-life-platform"], cs="yes", ts="yes", lb=M, r=[CD, TD]),
 # ---- accessibility ----
 "AC1": dict(k="finding", c=["missing-text-alternative"], cs="yes", ts="yes", lb=M + " (declared)", r=[TA], b="na:baseline is an API with no markup"),
 "AC2": dict(k="finding", c=["form-control-without-label"], cs="yes", ts="yes", lb=M + " (declared)", r=[TA], b="na:baseline is an API with no markup"),
 "AC3": dict(k="finding", c=["page-structure-violation"], cs="yes", ts="yes", lb=M + " (declared)", r=[TA], b="na:baseline is an API with no markup"),
 "AC4": dict(k="finding", c=["non-keyboard-accessible-interaction"], cs="yes", ts="yes", lb=M + " (declared)", r=[TA], b="na:baseline is an API with no markup"),
 "AC5": dict(k="finding", c=["invalid-aria-usage"], cs="yes", ts="yes", lb=M + " (declared)", r=[TA], b="na:baseline is an API with no markup"),
 "AC6": dict(k="finding", c=["visual-and-motion-safety"], cs="yes", ts="yes", lb=M + " (declared)", r=[TA], b="na:baseline is an API with no markup"),
 "AC7": dict(k="posture", c=["accessibility-checks-in-ci"], cs="yes", ts="yes", lb=M + " (declared)", r=[TA], b="na:baseline is an API with no markup"),
 # ---- static architecture ----
 "AX1": dict(k="finding", c=["captive-dependency"], cs="yes", ts="no", lb="assessed: Roslyn DI registrations (AddSingleton/Scoped/Transient)", r=[CA]),
 "AX2": dict(k="finding", c=["unsynchronized-shared-state"], cs="yes", ts="no", lb="assessed: Roslyn singleton field mutation", r=[CA]),
 "AX3": dict(k="finding", c=["module-dependency-cycle"], cs="yes", ts="partial", lb="assessed: .csproj reference DFS; measured on 65 local TS scans (no TS finding observed)", r=[CA]),
 "AX4": dict(k="finding", c=["layer-dependency-violation"], cs="yes", ts="partial", lb="assessed: project-reference graph name segments", r=[CA]),
 "AX5": dict(k="posture", c=["architecture-style-fit"], cs="yes", ts="partial", lb="assessed: Roslyn + csproj style detection", r=[CA]),
 "AX6": dict(k="finding", c=["fat-interface"], cs="yes", ts="yes", lb="DimensionMethods names a TypeScript arm", r=[CA, TH]),
 "AX7": dict(k="finding", c=["cross-slice-coupling"], cs="yes", ts="partial", lb="assessed: vertical-slice gated namespaces", r=[CA], b="na:vertical-slice gated (baseline is layered)"),
 "AX8": dict(k="finding", c=["production-depends-on-test-code"], cs="yes", ts="no", lb="assessed: csproj graph", r=[CT]),
 "AX9": dict(k="finding", c=["query-with-side-effects"], cs="yes", ts="no", lb="assessed: Roslyn CQRS handler classification", r=[CA]),
 "AX10": dict(k="metric", c=["business-logic-share"], cs="yes", ts="yes", lb="assessed: CodeRoleClassifier; measured on 123/123 local TS scans", r=[CA]),
 # ---- runtime evidence tier ----
 "AXA1": dict(k="runtime", c=["unauthenticated-reachable-endpoint"], cs="yes", ts="yes", lb="runtime, language-neutral", oos=RUNTIME_OOS),
 "AXB1": dict(k="runtime", c=["reproducible-boot"], cs="yes", ts="yes", lb="runtime tier, language-neutral", oos="runtime-tier card: built only when the Runtime Evidence module is switched on (scan.py --runtime-evidence; without it AXB1/AXB2/AXR1 build no card at all — scan.py docstring); v1 does not enable the module"),
 "AXB2": dict(k="runtime", c=["reproducible-boot"], cs="yes", ts="yes", lb="runtime tier, language-neutral", oos=RUNTIME_OOS),
 "AXH1": dict(k="runtime", c=["security-response-headers"], cs="yes", ts="yes", lb="runtime", oos=RUNTIME_OOS),
 "AXI1": dict(k="runtime", c=["container-excessive-privilege"], cs="yes", ts="yes", lb="runtime", oos=RUNTIME_OOS),
 "AXK1": dict(k="runtime", c=["insecure-cookie-flags"], cs="yes", ts="yes", lb="runtime", oos=RUNTIME_OOS),
 "AXO1": dict(k="runtime", c=["undocumented-api-endpoint"], cs="yes", ts="yes", lb="runtime", oos=RUNTIME_OOS),
 "AXP1": dict(k="runtime", c=["third-party-data-flow"], cs="yes", ts="yes", lb="runtime", oos=RUNTIME_OOS),
 "AXR1": dict(k="runtime", c=["missing-text-alternative", "form-control-without-label", "visual-and-motion-safety", "non-keyboard-accessible-interaction"], cs="yes", ts="yes", lb="runtime", oos=RUNTIME_OOS + " (headless browser over rendered surfaces)"),
 "AXS1": dict(k="runtime", c=["unexpected-exposed-port"], cs="yes", ts="yes", lb="runtime", oos=RUNTIME_OOS),
 # ---- compliance posture ----
 "C1": dict(k="posture", c=["data-encryption-controls"], cs="yes", ts="partial", lb="assessed: Roslyn + filesystem (EF column encryption, key vault, KDF)", r=[CI], b="na:gated by personal-data presence (C1Analyzer.cs:95 NotApplicableNoPii); baseline holds no personal data"),
 "C2": dict(k="posture", c=["authorization-enforcement"], cs="yes", ts="partial", lb="assessed: Roslyn [Authorize]/policies", r=[CI]),
 "C3": dict(k="posture", c=["audit-trail"], cs="yes", ts="partial", lb="assessed: Roslyn audit mechanisms", r=[CE], b="na:gated by personal-data presence (C3Analyzer.cs:101); baseline holds no personal data"),
 "C4": dict(k="posture", c=["data-retention-policy"], cs="yes", ts="partial", lb="assessed: Roslyn, gated by PII presence", r=[CE], b="na:gated by PII presence (baseline holds no personal data)"),
 "C5": dict(k="posture", c=["data-subject-rights"], cs="yes", ts="partial", lb="assessed: Roslyn, gated by PII presence", r=[CE], b="na:gated by PII presence (baseline holds no personal data)"),
 # ---- domain modelling (DDD-gated) ----
 "DM1": dict(k="finding", c=["cross-aggregate-object-reference"], cs="yes", ts="partial", lb="assessed: Roslyn DDD-gated; measured on 28 local TS scans, never fired", r=[CE], b=DDD),
 "DM2": dict(k="finding", c=["primitive-entity-identifier"], cs="yes", ts="partial", lb="assessed: Roslyn DDD-gated", r=[CE], b=DDD),
 "DM3": dict(k="finding", c=["integration-event-leaks-domain-type"], cs="yes", ts="no", lb="assessed: Roslyn DDD-gated", r=[CE], b=DDD),
 "DM4": dict(k="finding", c=["anemic-domain-model"], cs="yes", ts="yes", lb="assessed: measured on 27 local TS scans (fired on 26)", r=[CE, TH], b=DDD),
 "DM5": dict(k="finding", c=["publicly-mutable-entity-state"], cs="yes", ts="yes", lb="assessed: measured on 33 local TS scans", r=[CE, TH], b=DDD),
 "DM6": dict(k="finding", c=["domain-depends-on-infrastructure"], cs="yes", ts="yes", lb="assessed: measured on 21 local TS scans", r=[CE], b=DDD),
 "DM7": dict(k="finding", c=["repository-for-non-aggregate"], cs="yes", ts="partial", lb="assessed: Roslyn DDD-gated (C#/VB arm for IQueryable)", r=[CE], b=DDD),
 "DM8": dict(k="judged", c=["primitive-obsession"], cs="yes", ts="no", lb="assessed: Roslyn DDD-gated + model", r=[CE], b=DDD, req=[LLM]),
 "DM9": dict(k="finding", c=["scattered-domain-rule"], cs="yes", ts="partial", lb="assessed: neutral body surface + Roslyn", r=[CE], b=DDD),
 "DM10": dict(k="finding", c=["multi-aggregate-transaction"], cs="yes", ts="partial", lb="assessed: neutral body surface", r=[CE], b=DDD),
 "DM11": dict(k="finding", c=["constructible-invalid-entity"], cs="yes", ts="partial", lb="assessed: neutral surface", r=[CE], b=DDD),
 "DM12": dict(k="finding", c=["ambient-nondeterminism-in-domain"], cs="yes", ts="no", lb="DimensionMethods: 'C#/VB only'", r=[CE], b=DDD),
 # ---- event-driven / sourcing ----
 "ED1": dict(k="finding", c=["synchronous-remote-call-in-event-handler"], cs="yes", ts="no", lb="assessed: Roslyn semantic, event-driven gated", r=[CE], b=EVT),
 "ED2": dict(k="finding", c=["command-with-multiple-handlers"], cs="yes", ts="no", lb="assessed: Roslyn, event-driven gated", r=[CE], b=EVT),
 "ED3": dict(k="finding", c=["event-not-named-in-past-tense"], cs="yes", ts="no", lb="assessed: Roslyn, event-driven gated", r=[CE], b=EVT),
 "ED4": dict(k="finding", c=["dual-write-without-outbox"], cs="yes", ts="no", lb="assessed: Roslyn semantic, event-driven gated", r=[CE], b=EVT),
 "ED5": dict(k="judged", c=["non-idempotent-message-handler"], cs="yes", ts="no", lb="assessed: Roslyn heuristic + model", r=[CE], req=[LLM]),
 "ES1": dict(k="finding", c=["nondeterministic-event-fold"], cs="yes", ts="no", lb="assessed: Roslyn, event-sourcing gated", r=[CE], b=ESG),
 "ES2": dict(k="finding", c=["mutable-persisted-event"], cs="yes", ts="no", lb="assessed: Roslyn, event-sourcing gated", r=[CE], b=ESG),
 "ES3": dict(k="judged", c=["personal-data-in-event-store"], cs="yes", ts="no", lb="assessed: Roslyn, event-sourcing gated + model", r=[CE], b=ESG, req=[LLM]),
 # ---- incompleteness ----
 "GD1": dict(k="finding", c=["not-implemented-placeholder"], cs="yes", ts="no", lb="assessed: Roslyn NotImplementedException/placeholders", r=[CH]),
 "IC1": dict(k="finding", c=["incomplete-implementation", "unreachable-code", "not-implemented-placeholder", "commented-out-code", "suppressed-diagnostic", "skipped-test-without-reason"], cs="yes", ts="partial", lb="assessed: Roslyn code shape", r=[CH]),
 # ---- model-judged advisory ----
 "LA1": dict(k="judged", c=["personal-data-inventory"], cs="yes", ts="no", lb="assessed: Roslyn GDPR-gated heuristic + model", r=[CE], b="na:GDPR-gated (baseline holds no personal data)", req=[LLM]),
 "LA2": dict(k="judged", c=["alt-text-quality"], cs="yes", ts="yes", lb="markup scan, language-neutral", r=[TA], b="na:baseline is an API with no markup", req=[LLM]),
 "LA3": dict(k="judged", c=["vulnerability-disclosure-policy-quality"], cs="yes", ts="yes", lb="language-neutral (SECURITY.md)", r=[CR], req=[LLM]),
 "LA4": dict(k="judged", c=["environment-separation"], cs="yes", ts="yes", lb="language-neutral (environment config)", r=[CX], req=[LLM]),
 "LA5": dict(k="judged", c=["link-and-button-text-quality"], cs="yes", ts="yes", lb="markup scan, language-neutral", r=[TA], b="na:baseline is an API with no markup", req=[LLM]),
 "LA6": dict(k="judged", c=["heading-and-label-text-quality"], cs="yes", ts="yes", lb="markup scan, language-neutral", r=[TA], b="na:baseline is an API with no markup", req=[LLM]),
 # ---- maturity ----
 "M1": dict(k="posture", c=["readme-quality"], cs="yes", ts="yes", lb="language-neutral (filesystem)", r=[CM]),
 "M2": dict(k="posture", c=["architecture-documentation"], cs="yes", ts="yes", lb="language-neutral (filesystem)", r=[CM]),
 "M3": dict(k="posture", c=["folder-structure"], cs="yes", ts="yes", lb="language-neutral (filesystem + RootNamespace)", r=[CA]),
 "M4": dict(k="judged", c=["documentation-accuracy"], cs="yes", ts="yes", lb="language-neutral (README vs projects)", r=[CM], req=[LLM]),
 # ---- readiness ----
 "P1": dict(k="posture", c=["ci-build-and-test-pipeline"], cs="yes", ts="yes", lb="language-neutral (CI files)", r=[CR]),
 "P2": dict(k="posture", c=["observability"], cs="yes", ts="yes", lb="assessed: Roslyn + foreign-language walk (ForeignObservability.cs)", r=[CR]),
 "P3": dict(k="posture", c=["security-tooling-in-ci"], cs="yes", ts="yes", lb="language-neutral (CI files)", r=[CR]),
 "P4": dict(k="posture", c=["deployment-rollback-safety"], cs="yes", ts="yes", lb="language-neutral (manifests)", r=[CX]),
 "P5": dict(k="posture", c=["disaster-recovery-evidence"], cs="yes", ts="yes", lb="language-neutral (IaC/docs)", r=[CX]),
 "P6": dict(k="posture", c=["release-hygiene"], cs="yes", ts="yes", lb="language-neutral (changelog, tags)", r=[CR]),
 "P7": dict(k="posture", c=["outbound-http-resilience"], cs="yes", ts="yes", lb="DimensionMethods names .NET and JS/TS arms", r=[CR]),
 "P8": dict(k="posture", c=["versioned-schema-migrations"], cs="yes", ts="yes", lb="DimensionMethods names EF Core and Prisma/TypeORM/Knex arms", r=[CR], b="na:baseline has no database"),
 "P9": dict(k="metric", c=["domain-vs-controller-coverage"], cs="yes", ts="no", lb="assessed: Roslyn + test execution", r=[CT], req=[TESTRUN]),
 "P10": dict(k="posture", c=["library-api-versioning"], cs="yes", ts="yes", lb="DimensionMethods names .NET and npm arms", r=[CR], b="na:baseline is a service, not a published library"),
 "P11": dict(k="posture", c=["executable-specifications"], cs="yes", ts="yes", lb="language-neutral (Gherkin/SpecFlow presence)", r=[CT], b="na:no BDD tool referenced (P11 gates on one)"),
 "P12": dict(k="posture", c=["ci-test-gate-integrity"], cs="yes", ts="yes", lb="language-neutral (CI files vs test inventory)", r=[CT]),
 # ---- performance ----
 "PF1": dict(k="posture", c=["benchmark-discipline"], cs="yes", ts="yes", lb="DimensionMethods names .NET and tinybench/vitest-bench arms", r=[CR]),
 "PF2": dict(k="metric", c=["allocation-awareness"], cs="yes", ts="partial", lb="assessed: .NET + Go/JVM arms (no TS arm named)", r=[CH]),
 "PF3": dict(k="finding", c=["blocking-on-async-code", "missing-configure-await"], cs="yes", ts="yes", lb="DimensionMethods names a TS/JS arm (model-read off .NET)", r=[CH, TH]),
 # ---- frontend (R*) ----
 "R1": dict(k="metric", c=["untyped-javascript-share"], cs="no", ts="yes", lb="frontend JS/TS file inventory", r=[TH, TA]),
 "R2": dict(k="finding", c=["high-cyclomatic-complexity", "high-cognitive-complexity"], cs="no", ts="yes", lb="frontend function scanner", r=[TH]),
 "R3": dict(k="finding", c=["oversized-source-file"], cs="no", ts="yes", lb="frontend source tree", r=[TH, TA]),
 "R4": dict(k="metric", c=["test-coverage"], cs="no", ts="yes", lb="frontend import-graph reachability from tests", r=[TH]),
 "R5": dict(k="posture", c=["outdated-dependency"], cs="no", ts="yes", lb="npm manifest/registry metadata", r=[TD]),
 "R6": dict(k="posture", c=["frontend-tooling-scripts"], cs="no", ts="yes", lb="package.json scripts", r=[TH]),
 "R7": dict(k="finding", c=["unused-code"], cs="no", ts="yes", lb="JS/TS module-graph reachability", r=[TH]),
 "R8": dict(k="finding", c=["unused-dependency", "undeclared-dependency", "misplaced-dev-dependency"], cs="no", ts="yes", lb="npm manifest + import graph", r=[TD]),
 "R9": dict(k="finding", c=["module-dependency-cycle"], cs="no", ts="yes", lb="JS/TS import graph", r=[TH]),
 "R10": dict(k="metric", c=["duplicated-code"], cs="no", ts="yes", lb="D4 clone algorithm over JS/TS tokens", r=[TH], loc=True),
 "R11": dict(k="finding", c=["layer-dependency-violation"], cs="no", ts="yes", lb="frontend layout + cross-package deep imports", r=[TH]),
 # ---- web security posture / supply chain ----
 "S1": dict(k="posture", c=["security-response-headers", "https-enforcement", "insecure-cookie-flags", "inbound-input-validation", "weak-cryptographic-algorithm", "weak-hash-algorithm", "hardcoded-cryptographic-key", "improper-certificate-validation", "token-signature-or-expiry-not-validated", "sensitive-data-in-url", "sensitive-data-in-logs", "missing-subresource-integrity", "insufficient-password-hashing", "cleartext-transmission"], cs="yes", ts="yes", lb="DimensionMethods: .NET arm, and JS/TS when the repo has no .NET source", r=[CI, TI]),
 "SC1": dict(k="posture", c=["dependencies-not-locked"], cs="yes", ts="yes", lb="language-neutral (manifests)", r=[CD, TD]),
 # ---- correctness (X) ----
 "X1": dict(k="finding", c=["blocking-on-async-code", "async-void-method"], cs="yes", ts="no", lb="assessed: Roslyn .Wait()/GetResult()/async void", r=[CH]),
 "X2": dict(k="finding", c=["missing-cancellation-propagation"], cs="yes", ts="yes", lb="DimensionMethods: TS arm when no .NET source", r=[CH, TH]),
 "X3": dict(k="finding", c=["empty-catch-block", "pointless-catch-rethrow", "rethrow-resets-stack-trace"], cs="yes", ts="no", lb="assessed: Roslyn catch clauses", r=[CH]),
 "X4": dict(k="finding", c=["non-structured-log-message"], cs="yes", ts="yes", lb="DimensionMethods: TS arm when no .NET source", r=[CH, TH]),
 "X5": dict(k="finding", c=["nullable-analysis-disabled", "null-forgiving-suppression", "null-dereference"], cs="yes", ts="yes", lb="assessed: NRT per project; TS strict-null arm observed on local TS scans", r=[CH, TH]),
 "X6": dict(k="finding", c=["hand-rolled-structured-format-parsing"], cs="yes", ts="yes", lb="DimensionMethods: C# and, with no C# project, JS/TS", r=[CH, TH]),
 "X7": dict(k="finding", c=["silent-error-fallback"], cs="yes", ts="no", lb="DimensionMethods: C# (Roslyn) and Python only", r=[CH]),
 "X8": dict(k="finding", c=["js-interop-contract-mismatch"], cs="yes", ts="no", lb="assessed: Blazor/JS interop (C# calling JS)", r=[CH], b="na:no Blazor/JS interop in the baseline"),
 "X9": dict(k="finding", c=["redundant-condition-operand"], cs="yes", ts="partial", lb="assessed: Roslyn (C# receiver proved string)", r=[CH]),
 "X10": dict(k="finding", c=["duplicated-code"], cs="yes", ts="partial", lb="assessed: Roslyn chain hashing", r=[CH]),
 "X12": dict(k="finding", c=["unreachable-code"], cs="yes", ts="no", lb="assessed: Roslyn syntax + semantics", r=[CH]),
 "X13": dict(k="finding", c=["undrained-child-process-stream"], cs="yes", ts="yes", lb="DimensionMethods: TS child_process arm when no .NET source", r=[CH, TH]),
 "X14": dict(k="finding", c=["server-side-request-forgery"], cs="yes", ts="no", lb="assessed: Roslyn syntax + semantics", r=[CI]),
 "X15": dict(k="finding", c=["unbounded-allocation-from-untrusted-length"], cs="yes", ts="no", lb="assessed: Roslyn BinaryReader", r=[CI]),
 "X16": dict(k="finding", c=["unbounded-truncation-loop"], cs="yes", ts="yes", lb="DimensionMethods: TS arm when no .NET source", r=[CH, TH]),
 "X17": dict(k="finding", c=["uncontrolled-recursion"], cs="yes", ts="yes", lb="DimensionMethods: TS arm when no .NET source", r=[CI, TI]),
 "X18": dict(k="finding", c=["improper-resource-disposal"], cs="yes", ts="yes", lb="DimensionMethods: TS arm when no .NET source", r=[CH, TH]),
 "X19": dict(k="finding", c=["unrestored-process-global-state"], cs="yes", ts="yes", lb="DimensionMethods: TS arm when no .NET source", r=[CH, TH]),
 "X20": dict(k="finding", c=["argument-guard-tests-wrong-condition"], cs="yes", ts="no", lb="assessed: Roslyn syntax", r=[CH]),
 "X21": dict(k="finding", c=["side-effect-in-conditional-guard"], cs="yes", ts="no", lb="assessed: Roslyn syntax", r=[CH]),
 "X22": dict(k="finding", c=["lock-release-state-mismatch"], cs="yes", ts="no", lb="assessed: Roslyn syntax", r=[CH]),
 "X23": dict(k="finding", c=["unguarded-expensive-debug-logging"], cs="yes", ts="yes", lb="DimensionMethods: TS arm when no .NET source", r=[CH, TH]),
 "X24": dict(k="finding", c=["cross-site-scripting"], cs="yes", ts="yes", lb="DimensionMethods: Roslyn OpenXml/System.Xml taint; TS arm when no .NET source", r=[CI, TI]),
 "X25": dict(k="finding", c=["inert-configuration-option"], cs="yes", ts="yes", lb="DimensionMethods: TS arm when no .NET source", r=[CH, TH]),
 "X26": dict(k="finding", c=["unsynchronized-callback-handoff"], cs="yes", ts="no", lb="assessed: Roslyn syntax", r=[CH]),
 "X27": dict(k="finding", c=["collection-modified-during-enumeration"], cs="yes", ts="no", lb="assessed: Roslyn syntax + semantics", r=[CH]),
 "X28": dict(k="finding", c=["index-access-outside-bounds-guard"], cs="yes", ts="no", lb="assessed: Roslyn syntax", r=[CH]),
 "X29": dict(k="finding", c=["loop-decision-on-fixed-element"], cs="yes", ts="yes", lb="DimensionMethods: TS arm when no .NET source", r=[CH, TH]),
 "X30": dict(k="finding", c=["contradictory-support-guard"], cs="yes", ts="no", lb="assessed: Roslyn syntax", r=[CH]),
 "X31": dict(k="finding", c=["test-only-api-in-production-code"], cs="no", ts="no", lb="DimensionMethods: the Erlang sidecar's preprocessed forms", oos="language-gated: Erlang only (reads the Erlang sidecar's -export attributes); no C# or TypeScript arm exists"),
 "X32": dict(k="finding", c=["type-lookup-by-simple-name"], cs="yes", ts="no", lb="assessed: Roslyn syntax (GetAssemblies/GetTypes)", r=[CH]),
}

# Contract 1.2 `scoreDimensions`: for a concept whose `dimensions` (finding attribution) include a dimension whose SCORE
# does not measure the concept, the dimensions a score-band entry of the concept may take its score from. Concepts not
# listed take their score from all of `dimensions`. Audited against every score-band concept in the frozen keys
# (2026-10-07); kept on `dimensions` after the audit: high-cyclomatic-complexity (D1, and R2 whose rows are raised on the
# cyclomatic bar alone), test-coverage (D8 measured, R4 static reachability: both measure coverage),
# security-response-headers (AXH1 observes the headers; S1 checks them statically), and every single-dimension concept.
SCORE_DIMS = {
    # D12's score is dominated by vulnerable/outdated/deprecated packages and D36's by provenance, signing and pinned
    # actions/images; SC1 is the dimension whose score measures lockfiles (reproducible, pinned dependency restore).
    "dependencies-not-locked": ["SC1"],
    # D36 is supply-chain provenance & signing; P3 is the posture that scores SAST/secret/dependency scanning in CI.
    "security-tooling-in-ci": ["P3"],
    # R2 raises a row only on the cyclomatic bar (discrim.py, ComplexityDimensionBuilder.cs:18), so its score never
    # measures cognitive complexity.
    "high-cognitive-complexity": ["D2"],
    # X10 reports one exact-duplicate predicate at a time; its score is not a duplication measure. D4 (C#) and R10
    # (JS/TS) are the clone metrics.
    "duplicated-code": ["D4", "R10"],
}

# Which C# repo themes are Phase 1
PHASE = {CB: 1, CS: 1, CI: 2, CD: 2, CX: 2, CH: 2, CA: 2, CE: 2, CR: 2, CM: 2, CT: 2,
         TB: 3, TS: 3, TI: 3, TD: 3, TA: 3, TH: 3, EST: 4}
