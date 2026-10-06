# Generator for the Watchdog-derived files

`build.py` regenerates `taxonomy.json`, `mappings/watchdog.json` and `coverage/matrix.json` from a Watchdog engine
checkout (rubric catalog, dimension-language matrix, edition and absence lists), plus the hand-curated tables in
`concepts.py` (the neutral concepts) and `dims.py` (per-dimension scope, repos, labels and reasons).

    WATCHDOG_SOURCE=/path/to/engine-checkout python3 mappings/watchdog-build/build.py
    python3 coverage/render_matrix.py --check

The curated tables are the source of truth for human judgement; the engine checkout supplies only facts
(ids, names, lenses, editions). Other scanners get their own mapping file and need none of this.
