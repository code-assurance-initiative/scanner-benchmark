"""The answer-key dispute ledger (disputes/ledger.json): every entry carries what a reader needs to audit it, a
correction names the key version it created, and the ledger is only ever appended to.

The process is CAI decision 0001 (CodeAssuranceIndex docs/decisions/0001-adopt-the-answer-key-dispute-path.md); the
ledger is where its decisions become countable, so an entry that can be edited or dropped later would make the counts
per scanner say whatever the last editor wanted.
"""
import copy
import json
import os
import subprocess
import tempfile
import unittest

from tools import disputes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CORRECTED = {
    "case": "https://github.com/code-assurance-initiative/scanner-benchmark/issues/1",
    "filed": "2026-10-16", "date": "2026-10-20",
    "set": "training-set-2026", "unit": "bench-csharp-tests", "entryId": "TQ-001",
    "keyVersion": "1.0.0", "keySha256": "a" * 64, "publication": None,
    "outcome": "corrected", "newKeyVersion": "1.1.0", "op": "relabel", "to": "must-not-fire",
    "claimant": "A. Claimant", "claimantScanner": "some-scanner", "labeller": "B. Labeller",
    "adjudicator": "C. Adjudicator",
    "evidence": "The site at v1.0.0 (lines 10-14) validates its input before use; the concept requires it does not.",
    "journal": "benchmark/journal.md at v1.1.0, entry 2026-10-20",
}


def entry(**changes):
    e = copy.deepcopy(CORRECTED)
    for k, v in changes.items():
        if v is disputes.ABSENT:
            e.pop(k, None)
        else:
            e[k] = v
    return e


UPHELD = entry(outcome="upheld", newKeyVersion=disputes.ABSENT, op=disputes.ABSENT, to=disputes.ABSENT)


def has(problems, *words):
    return any(all(w in p for w in words) for p in problems)


class PublishedLedger(unittest.TestCase):
    def test_the_published_ledger_is_well_formed(self):
        with open(os.path.join(ROOT, "disputes", "ledger.json")) as f:
            self.assertEqual(disputes.validate(json.load(f)), [])

    def test_the_published_ledger_has_only_been_appended_to(self):
        # Against every committed version of the file, oldest first, then the working copy. Needs full history: a
        # shallow clone is reported, never treated as "nothing to compare" (CI checks out with fetch-depth 0).
        self.assertEqual(disputes.history_problems(ROOT), [])


class Shape(unittest.TestCase):
    def test_a_complete_correction_and_a_complete_upheld_entry_pass(self):
        self.assertEqual(disputes.validate([CORRECTED, UPHELD]), [])

    def test_the_ledger_is_a_list(self):
        self.assertTrue(has(disputes.validate({"entries": []}), "array"))

    def test_every_required_field_is_reported_when_missing(self):
        for field in disputes.REQUIRED:
            with self.subTest(field=field):
                self.assertTrue(has(disputes.validate([entry(**{field: disputes.ABSENT})]), field),
                                f"a ledger entry without {field} was accepted")

    def test_an_unknown_outcome_is_reported(self):
        self.assertTrue(has(disputes.validate([entry(outcome="overturned")]), "outcome"))

    def test_a_correction_must_name_its_new_key_version(self):
        self.assertTrue(has(disputes.validate([entry(newKeyVersion=disputes.ABSENT)]), "newKeyVersion"))
        self.assertTrue(has(disputes.validate([entry(newKeyVersion=None)]), "newKeyVersion"))

    def test_a_correction_new_version_must_be_later_than_the_disputed_one(self):
        self.assertTrue(has(disputes.validate([entry(newKeyVersion="1.0.0")]), "newKeyVersion", "later"))
        self.assertTrue(has(disputes.validate([entry(newKeyVersion="0.9.0")]), "newKeyVersion", "later"))

    def test_a_version_local_to_one_scanner_is_not_a_cai_key_version(self):
        # Proposal 0001 §3: a "+<scanner>.N" version is one scanner's own amendment and never a CAI number.
        self.assertTrue(has(disputes.validate([entry(newKeyVersion="1.0.0+wd.1")]), "newKeyVersion"))
        self.assertTrue(has(disputes.validate([entry(keyVersion="1.0.0+wd.1")]), "keyVersion"))

    def test_a_correction_states_what_changed(self):
        self.assertTrue(has(disputes.validate([entry(op="rewrite")]), "op"))
        self.assertTrue(has(disputes.validate([entry(op="relabel", to=disputes.ABSENT)]), "to"))
        self.assertEqual(disputes.validate([entry(op="remove", to=disputes.ABSENT)]), [])

    def test_an_entry_that_changed_no_key_names_no_new_version(self):
        self.assertTrue(has(disputes.validate([dict(UPHELD, newKeyVersion="1.1.0")]), "newKeyVersion"))

    def test_upheld_and_corrected_entries_cite_the_journal_entry(self):
        self.assertTrue(has(disputes.validate([dict(UPHELD, journal="")]), "journal"))
        withdrawn = dict(UPHELD, outcome="withdrawn", journal=None)
        self.assertEqual(disputes.validate([withdrawn]), [])

    def test_the_adjudicator_is_neither_the_claimant_nor_the_labeller(self):
        self.assertTrue(has(disputes.validate([entry(adjudicator="A. Claimant")]), "adjudicator", "claimant"))
        self.assertTrue(has(disputes.validate([entry(adjudicator="B. Labeller")]), "adjudicator", "labeller"))

    def test_dates_are_iso_and_a_decision_does_not_precede_its_filing(self):
        self.assertTrue(has(disputes.validate([entry(date="20 Oct 2026")]), "date"))
        self.assertTrue(has(disputes.validate([entry(date="2026-10-15")]), "date", "filed"))

    def test_the_disputed_key_is_named_by_its_hash(self):
        self.assertTrue(has(disputes.validate([entry(keySha256="abc")]), "keySha256"))


class AppendOnly(unittest.TestCase):
    def test_appending_passes(self):
        self.assertEqual(disputes.append_only([CORRECTED], [CORRECTED, UPHELD]), [])

    def test_editing_removing_or_reordering_an_entry_is_reported(self):
        self.assertTrue(disputes.append_only([CORRECTED], [entry(outcome="upheld")]))
        self.assertTrue(disputes.append_only([CORRECTED, UPHELD], [CORRECTED]))
        self.assertTrue(disputes.append_only([CORRECTED, UPHELD], [UPHELD, CORRECTED]))

    def test_reformatting_the_file_is_not_an_edit(self):
        self.assertEqual(disputes.append_only(json.loads(json.dumps([CORRECTED], indent=4)), [CORRECTED]), [])


class History(unittest.TestCase):
    def _repo(self, d, *versions):
        os.makedirs(os.path.join(d, "disputes"))
        g = ["git", "-C", d]
        subprocess.run(g + ["init", "-q"], check=True)
        for v in versions:
            self._write(d, v)
            subprocess.run(g + ["add", "."], check=True)
            subprocess.run(g + ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"], check=True)

    def _write(self, d, ledger):
        with open(os.path.join(d, "disputes", "ledger.json"), "w") as f:
            json.dump(ledger, f)

    def test_a_history_of_appends_passes(self):
        with tempfile.TemporaryDirectory() as d:
            self._repo(d, [], [CORRECTED], [CORRECTED, UPHELD])
            self.assertEqual(disputes.history_problems(d), [])

    def test_an_entry_dropped_in_the_working_copy_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            self._repo(d, [], [CORRECTED])
            self._write(d, [])
            self.assertTrue(disputes.history_problems(d))

    def test_an_entry_edited_in_a_later_commit_is_reported(self):
        # Committing the edit does not launder it: every committed version is compared with the one after it.
        with tempfile.TemporaryDirectory() as d:
            self._repo(d, [CORRECTED], [entry(evidence="something else")], [entry(evidence="something else"), UPHELD])
            self.assertTrue(has(disputes.history_problems(d), "edited"))

    def test_a_shallow_clone_is_reported_not_passed(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src")
            self._repo(src, [], [CORRECTED])
            dst = os.path.join(d, "dst")
            subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + src, dst], check=True)
            self.assertTrue(has(disputes.history_problems(dst), "shallow"))


class Stats(unittest.TestCase):
    def test_disputes_are_counted_per_scanner_and_outcome(self):
        none = dict(UPHELD, claimantScanner=None, outcome="not-evidenced", journal=None)
        self.assertEqual(disputes.stats([CORRECTED, UPHELD, none]), {
            "some-scanner": {"filed": 2, "upheld": 1, "corrected": 1, "not-evidenced": 0, "withdrawn": 0},
            "(no scanner)": {"filed": 1, "upheld": 0, "corrected": 0, "not-evidenced": 1, "withdrawn": 0},
        })


if __name__ == "__main__":
    unittest.main()
