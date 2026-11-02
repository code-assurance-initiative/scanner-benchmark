# Benchmark challenge 2026-q4: registration is open

Any code scanner can be measured on a sealed holdout of small synthetic repositories whose answer keys say exactly
which defects are planted and which look-alikes are traps. The result is recall, trap resistance and noise per
dimension, with 95 % intervals — published for every engine that takes part, including any that do badly.

> **This window is a pilot.** It rehearses the procedure in public. Its holdout was authored before the qualification protocol was published, so its results qualify no engine; they are published in full all the same.

| | Date |
|---|---|
| Registration closes | 2026-11-30 |
| Window opens (engines are run) | 2026-12-07 |
| Holdout, answer keys and all results revealed | 2026-12-21 |

**How to take part:** open a [register-engine](https://github.com/code-assurance-initiative/scanner-benchmark/issues/new?template=register-engine.yml)
issue before 2026-11-30: the engine as a container image by digest, its configuration, and its
mapping from rule ids to the benchmark's concepts. What the container must do is in
[docs/CHALLENGE-RUN.md](https://github.com/code-assurance-initiative/scanner-benchmark/blob/main/docs/CHALLENGE-RUN.md). Nothing you submit can change after
registration closes, and every engine gets one run.

The holdout (holdout-2026-q4) was sealed in public before this announcement: its hashes are in
[registry.json](https://github.com/code-assurance-initiative/scanner-benchmark/blob/main/registry.json), so anyone can check at reveal that what was scored
is what was sealed. The scheme: [ENGINE-QUALIFICATION.md](https://github.com/code-assurance-initiative/CodeAssuranceIndex/blob/main/docs/ENGINE-QUALIFICATION.md).
