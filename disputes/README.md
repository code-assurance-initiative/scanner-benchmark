# Disputing an answer key

An answer key can be wrong: a plant that is not a defect, or not where the key says; a trap that is in fact a defect.
This is how such an entry is disputed, decided, corrected and recorded. It is the process of
[CAI proposal 0001](https://github.com/code-assurance-initiative/CodeAssuranceIndex/blob/main/docs/proposals/0001-answer-key-dispute-path.md),
adopted by
[CAI decision 0001](https://github.com/code-assurance-initiative/CodeAssuranceIndex/blob/main/docs/decisions/0001-adopt-the-answer-key-dispute-path.md)
on 2026-10-16. A change to this process is a new proposal there, not an edit here.

It sits under the [integrity rules](../README.md#integrity-rules) and changes none of them: a frozen key is never
edited, a correction is a new key version, and nothing is selected on the outcome.

## Who may file, and when

| Set | Who | Window |
|---|---|---|
| Holdout, after reveal | anyone | 30 days from reveal ([CHALLENGE-RUN.md](../docs/CHALLENGE-RUN.md) step 4) |
| Holdout, a scanner's own published verdict | the scanner's owner | 30 days from the publication of that verdict, even if the reveal window has closed |
| Training set | anyone | any time while the set is current |

A dispute is about **one entry of one key version**. A scanner owner disputing after its verdict names the verdict
(the publication id) the entry was scored in. A sealed holdout cannot be disputed: its keys are not published.

## What a dispute carries

File it with the [`dispute-key` issue form](../.github/ISSUE_TEMPLATE/dispute-key.yml). Everything is stated in the
issue text itself, never as a link alone, so the dispute can be read and decided from the issue even if a link dies:

1. the set, unit, tag, key version and `keySha256` of the disputed key, and the entry id;
2. the direction: `must-fire-not-a-defect` (a plant that is not a defect, or not where the key says) or
   `must-not-fire-is-a-defect` (a trap that is in fact a defect);
3. the scanner evidence, if any: rule id, location and message of the result (or the statement that no result was
   emitted within the key's line tolerance), with the engine version and configuration label;
4. the argument, and the **independent evidence** it rests on: the code at the frozen tag (quoted, with lines), the
   concept's definition in [`taxonomy.json`](../taxonomy.json) applied to that code, the repository's own history,
   the authoring journal;
5. the claimant, their affiliation, and a conflict declaration (which scanner they own or work for, if any).

**A scanner's output is never evidence that a key is wrong.** It is the reason a dispute is filed, not a reason it is
upheld. A dispute whose only support is "our scanner disagrees" is closed as not evidenced.

## Who decides

The adjudicator is **neither the claimant, nor anyone affiliated with the claimant's scanner, nor the entry's author**
(the labeller named in the unit's journal, or the coordinator where the journal names nobody). The coordinator assigns
the adjudicator and records the assignment, and any recusal, on the issue. Where the coordinator authored the entry,
the adjudicator is a second maintainer or an external reviewer. The adjudicator is named in the decision.

**Today that rule bites hard, and it is meant to.** The coordinator also maintains CCA (formerly Watchdog), a scanner measured here,
and the current keys were authored under the coordinator. So a dispute filed by CCA, or about any entry the
coordinator labelled, needs a second maintainer or an external reviewer, and there is no second maintainer yet. Such a
dispute stays open and visible until one is found, past the 14-day target if it must. The target is not met by
relaxing the recusal.

## Outcomes

- **Key upheld (the scanner is wrong).** The entry stands. A journal entry in the unit's `benchmark/journal.md`
  records the dispute and the reason. No number changes.
- **Key corrected.** The unit gets a new key version (`v1.0.0` to `v1.1.0`): a new tag, a new registry entry in
  [`registry.json`](../registry.json) with its own `keySha256`, and a journal entry with the reason and the evidence.
  The frozen tag and hash of the old version are never edited. The change is one of: `relabel` (a plant is a trap, or
  the reverse), `relocate` (right defect, wrong site), `remove` (not a defect and not a useful trap). A training-set
  correction is released when the dispute is decided and re-bundled into the set as
  [AUTHORING.md](../docs/AUTHORING.md) describes; corrections are not held back for a batched set release.
- **Not evidenced / withdrawn.** Closed with the reason.

A decision is due **within 14 days of filing**.

## The ledger

Every decision, whatever its outcome, is appended to [`ledger.json`](ledger.json), so a reader can count disputes per
scanner and per outcome. The ledger is **append-only**: an entry is never edited, moved or removed. A decision that
turns out to be wrong is corrected by a later dispute and a later entry. A `corrected` entry lands in the same commit
as the new key version's registry entry.

| Field | |
|---|---|
| `case` | the dispute issue (URL) |
| `filed`, `date` | the filing date and the decision date, `YYYY-MM-DD` |
| `set`, `unit`, `entryId` | the disputed entry |
| `keyVersion`, `keySha256` | the key version disputed and its registered sha256 |
| `publication` | the verdict a post-verdict dispute names, else `null` |
| `outcome` | `upheld`, `corrected`, `not-evidenced` or `withdrawn` |
| `newKeyVersion`, `op`, `to` | `corrected` only: the new key version (later than `keyVersion`), the change (`relabel`, `relocate`, `remove`) and, for a relabel, the new label (`must-fire` or `must-not-fire`) |
| `claimant`, `claimantScanner` | who filed, and the scanner they own or work for (`null` if none) |
| `labeller`, `adjudicator` | the entry's author and who decided; never the same person, never the claimant |
| `evidence` | the evidence the decision rests on, and the reason |
| `journal` | `upheld` and `corrected`: the journal entry that records it |

Key versions are plain `MAJOR.MINOR.PATCH`. A version with build metadata (`1.0.0+wd.1`) is one scanner's own copy of
a key, never a CAI key version, and the ledger refuses it.

`python3 -m tools.disputes validate` checks every entry's shape and compares the ledger against every committed version
of it, so an edit is caught even if it was committed; it runs in the harness's tests (`tests/test_disputes.py`) on every
push. `python3 -m tools.disputes stats` prints the counts per scanner and outcome.

## Re-scoring, without rewriting what was published

- Every recorded result under `results/<scanner>/` that was scored against the old key version is re-scored against
  the new one, for **every** scanner, not only the claimant's. The harness scores from the stored SARIF, so this is a
  re-score, not a re-run.
- The re-scored result is published as a **new record beside the original**, stating the key version it was scored
  against and the record it was re-scored from. The original is never edited or removed.
- On the Code Assurance Index, where a publication can be neither withdrawn nor replaced, the re-score is published as
  an **erratum record** that references the original publication and carries both figures and the key versions
  behind them. Headline figures thereafter cite their key version. *The Index's erratum record type is not built yet;
  [decision 0001](https://github.com/code-assurance-initiative/CodeAssuranceIndex/blob/main/docs/decisions/0001-adopt-the-answer-key-dispute-path.md#what-did-not-take-effect-yet)
  names it as follow-up.*
- A holdout's pre-registered content commitment covers the units and keys as sealed. The figure measured at reveal
  remains the pre-registered measurement. A post-dispute figure is labelled as such ("re-scored against key v1.1.0
  after dispute <id>"), so both numbers are visible and both are verifiable.

## Guarding against the obvious abuse

- **Never select on the outcome** applies to disputes too: an entry is never relabelled, moved or removed because
  scanners miss it or fire on it; only because independent evidence shows the label is wrong.
- Dispute statistics are published per scanner (filed, upheld, corrected), so a scanner owner who disputes every
  entry it misses is visible as one.
- A correction re-scores every scanner, so a correction cannot help the claimant alone.
