# Authoring a benchmark repository

The loop (plan §"The authoring loop"): **answer key first** → implement → scan with a reference scanner → judge every
unexpected finding (five classes) → fix the repository only where the scanner is right → re-scan until the repository
holds exactly what its key says → freeze (tag `v<keyVersion>`, sha256 of the key in `registry.json`).

## Every repository

- `benchmark/answer-key.json` — validated by `python3 -m cai_bench validate --key … --taxonomy taxonomy.json`.
- `benchmark/README.md` — theme; a table of every plant and every trap with *why* it is (not) a defect; what is
  certified clean; what the repository deliberately does not cover.
- `benchmark/journal.md` — dated entries: key written; each scan (scanner + version, counts, every unexpected finding
  with its verdict and reason, what changed); every key change with its reason.
- `LICENSE` (MIT), a real `README.md` for the code itself (what the service does, build, run, test, architecture
  headings), no product branding of any scanner vendor anywhere in code, docs or config.

## Craft

- One theme per repository, small (a few hundred to ~2k LoC), idiomatic, realistic: code a reviewer would believe
  came from a competent team. No filler, no comments that announce a plant ("// BUG: …", "// trap") — the key and
  `benchmark/README.md` explain; the code does not.
- Labels are about TRUTH, never about one scanner's behaviour: a `must-fire` is a real defect a careful human reviewer
  would flag; a `must-not-fire` is a site a careless rule would flag but a careful reviewer would not. Knowing how a
  scanner works may suggest *where* to probe; it never decides a label.
- Never put a scanner-specific suppression in a repository (`gitleaks:allow`, `// NOSONAR`, `#pragma warning disable`
  for a planted site, `nosemgrep`, `codehealth:allow-secret`, …).
- Planted secrets: generated with a CSPRNG in a real format; they authenticate nothing. Never `EXAMPLE`, never
  keyboard runs, never an excuse word (`example sample dummy placeholder changeme your_ …`) on a planted line unless
  the site is a trap.
- Lines in the key are 1-based and inclusive. Re-check every `lines` entry after each edit of a file.
- Dependency, licence, vulnerability and end-of-life entries carry a `subject` (contract 1.2): the exact package id
  (`Newtonsoft.Json`, `@angular/core`) or framework moniker (`net6.0`) a scanner names when it reports the package
  without a site. Use the full id, never a prefix or segment of it, and never the same subject on a plant and a trap
  of one concept.
- Name the most precise concept that is true of the site. `container-excessive-privilege` and `iac-misconfiguration`
  are umbrellas (contract 1.3 `parent`): use `privileged-container`, `host-namespace-sharing`, `missing-health-probes`,
  … and keep an umbrella only for a defect none of its children names, or in a `clean` list (where it certifies the
  region clean of every child too). A coarse concept lets an unrelated finding on the same lines score the plant.

## C# conventions (shared by every C# repository)

- `net10.0`, `<Nullable>enable</Nullable>`, `<ImplicitUsings>enable</ImplicitUsings>`, `TreatWarningsAsErrors`,
  `Directory.Build.props`, Central Package Management (`Directory.Packages.props`) **and** lock files
  (`RestorePackagesWithLockFile` + committed `packages.lock.json`), current non-deprecated packages (xunit.v3).
- `src/` + `tests/`, one root namespace prefix, `.editorconfig`, `global.json` pinning the SDK major.
- `.github/workflows/ci.yml`: `pull_request` + `push` triggers, `dotnet build` + `dotnet test`, every action pinned
  by full commit SHA (with the version in a trailing comment), least-privilege `permissions:`; a CodeQL workflow on
  `pull_request`; `.github/dependabot.yml`.
- `SECURITY.md` with a contact, `CHANGELOG.md` + `<Version>`, `docs/architecture.md` with a Mermaid diagram,
  `docs/adr/0001-…md` (+ more where real decisions exist), README ≥ 120 words with Build/Run, Testing and
  Architecture headings.
- Web APIs: `UseHttpsRedirection` + `UseHsts`, security response headers (CSP, HSTS, `X-Content-Type-Options`,
  frame policy), validated request models, `[Authorize]`/named policies on every non-public endpoint, `ILogger<T>`
  in every runnable module, a health-check endpoint, every async method takes and forwards a `CancellationToken`,
  no `!` null-forgiving operators.
- Tests: xUnit v3, real assertions, unit + integration (`WebApplicationFactory`) projects under `tests/`.
- Build and test locally (`dotnet build -c Release && dotnet test -c Release`) before every push. Never run two
  builds at once on the box: wrap every dotnet build/test/restore in `flock -o ~/RiderProjects/cai-bench/.build.lock …` (`-o`: MSBuild worker
  processes must not inherit the lock), and keep `TMPDIR` short (a long path breaks the test runner socket).

## The benchmark files are inside what a scanner reads

`benchmark/answer-key.json`, `benchmark/README.md` and the journal sit in the scanned tree. A scanner may read them as
evidence (seen in Phase 2: a README-drift check treated every `.json` file as a manifest, so a key rationale that named
a removed module masked the drift plant). Keep key and README prose free of identifiers that could change a scanner's
judgement of the code (removed feature names, secret values, rule ids that look like configuration); describe the site,
not the token. If a scan result changes because of `benchmark/` content, treat it as a defect of the repository and
reword — never ask the scanner to exclude the directory (that would be scanner-specific configuration).
