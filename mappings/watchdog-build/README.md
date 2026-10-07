# Generator for the Watchdog-derived files

`build.py` regenerates `taxonomy.json`, `mappings/watchdog.json` and `coverage/matrix.json` from a Watchdog engine
checkout (rubric catalog, dimension-language matrix, edition and absence lists), plus the hand-curated tables in
`concepts.py` (the neutral concepts) and `dims.py` (per-dimension scope, repos, labels and reasons).

    WATCHDOG_SOURCE=/path/to/engine-checkout python3 mappings/watchdog-build/build.py
    python3 coverage/render_matrix.py --check

The curated tables are the source of truth for human judgement; the engine checkout supplies only facts
(ids, names, lenses, editions). Other scanners get their own mapping file and need none of this.

`discrim.py` holds the contract 1.1 message discriminators: for every dimension that maps to more than one concept
(and SC1), the finding-title regexes that send each result to exactly one concept, the `off` titles that denote
none, and the engine source line of every title format. `build.py` refuses to build if an in-scope multi-concept
dimension has no entry, or if an entry's concepts differ from `dims.py`. To re-check against fresh scans, collect
`(ruleId, message.text)` from local `report.sarif` files and confirm each distinct message of a discriminated
dimension maps to one concept or one `offConcept` regex (tests/test_watchdog_mapping.py pins real shapes).

Contract 1.3 additions, also in `discrim.py`: the D31 table is built from rule-id lists — `CEP_ALL` (the pre-split
`container-excessive-privilege` ids), the other concepts' lists, `D31_PRECISE` (each precise concept, its umbrella, its
ids and why) and `D31_SPLIT` (ids whose detail decides between concepts). Import-time assertions keep the children a
partition of their umbrella's pre-split ids, so a key written against an umbrella scores as before; `build.py` copies
each taxonomy `parent` into the mapping and checks a child is mapped on no dimension its umbrella is not.
`LOCATION_FROM_MESSAGE` becomes the mapping's `locationFromMessage` (D36 workflow rows that name their site only in the
message). `FAMILY` holds the families (`hardcoded-secret`, `weak-password-hashing`).

Contract 1.4 additions. `concepts.py` may define concepts no Watchdog dimension maps: they must be listed in
`UNMAPPED` (reason) with the census behind the "no rule" in `UNMAPPED_CENSUS`; `build.py` refuses any other concept no
dimension maps, emits each as `rules: []`, `dimensions: []` plus a mapping-level `unmapped` entry, and lists it in the
matrix's `beyondReference` with the repositories that label it (frozen keys) or plan to (`dims.BEYOND_PLAN`).
`discrim.py` adds the AC6 table (focus-outline-removed / motion-without-reduced-motion under the umbrella
visual-and-motion-safety), the family `untrusted-data-executed` and `SUMMARY_OF_CONCEPT` (→ mapping
`summaryOfConcept`). The matrix's per-repository labels are read from the FROZEN keys: every repository in
`registry.json` at its latest tag, sha256-checked against the registry, through `cai_bench/units.py` from the first
source that has it: materialised units in `BENCH_UNITS_DIR`, the training set's bundles in `BENCH_SET_DIR` (default:
a `training-set-2026` checkout next to this repository), or legacy clones in `BENCH_WORKSPACE` (default: the directory
holding this repository); planned labels from `dims.py` remain only for repositories not
frozen yet. `build.py` prints the frozen coverage gaps per language.

    WATCHDOG_SOURCE=/path/to/engine-checkout BENCH_SET_DIR=/path/to/training-set-2026 python3 mappings/watchdog-build/build.py

Contract 1.5 additions. `concepts.py` `FILE_SCOPE` (concept -> why its defect is a whole class, file or module) sets
the taxonomy's `"matchScope": "file"` — a taxonomy property, read by the scorer from `taxonomy.json`, not mapping
knowledge. `discrim.py` `SITES_FROM_MESSAGE` becomes the mapping's `sitesFromMessage`: the clone-group site lists of
D4, R10 and X10 rows (census and engine source in the table); `build.py` allows it for duplication concepts only.
The engine checkout must be at the mapping's rubric (`rubric-2026.10.1`): the frozen mapping and matrix reproduce from
the catalog snapshot of kennel `7730bae242^` with the other inputs at `162b41f657`.
