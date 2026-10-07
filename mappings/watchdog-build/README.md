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
