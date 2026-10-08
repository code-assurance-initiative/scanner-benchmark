import datetime
import json
import os
import tempfile
import unittest

from tools import challenge

WINDOW = {
    "id": "2026-q4",
    "holdout": "holdout-2026-q4",
    "pilot": True,
    "announceOn": "2026-11-02",
    "registrationClosesOn": "2026-11-30",
    "opensOn": "2026-12-01",
    "revealOn": "2026-12-15",
}


def day(s):
    return datetime.date.fromisoformat(s)


class Due(unittest.TestCase):
    def test_nothing_is_due_before_the_announcement(self):
        self.assertEqual(challenge.due([WINDOW], day("2026-11-01")), [])

    def test_each_milestone_is_due_on_its_own_day_once_the_earlier_ones_are_done(self):
        done = set()
        for today, action in (("2026-11-02", "announce"), ("2026-11-30", "close-registration"),
                              ("2026-12-01", "open"), ("2026-12-15", "reveal")):
            self.assertEqual(challenge.due([WINDOW], day(today), done=done), [(action, "2026-q4")])
            done.add((action, "2026-q4"))

    def test_a_missed_day_is_caught_up_once_its_record_is_absent(self):
        # The workflow can miss a day (an outage). An action whose day has passed and that has not been recorded is
        # still due; one that has been recorded is not.
        self.assertIn(("announce", "2026-q4"), challenge.due([WINDOW], day("2026-11-05"), done=set()))
        self.assertNotIn(("announce", "2026-q4"), challenge.due([WINDOW], day("2026-11-05"), done={("announce", "2026-q4")}))


class Calendar(unittest.TestCase):
    def test_the_published_calendar_is_valid(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "challenge", "calendar.json")) as f:
            problems = challenge.validate(json.load(f))
        self.assertEqual(problems, [])

    def test_milestones_out_of_order_are_reported(self):
        bad = dict(WINDOW, opensOn="2026-11-20")
        self.assertTrue(any("order" in p for p in challenge.validate({"windows": [bad]})))

    def test_an_announcement_less_than_30_days_before_opening_is_reported(self):
        bad = dict(WINDOW, announceOn="2026-11-15")
        self.assertTrue(any("30 days" in p for p in challenge.validate({"windows": [bad]})))


class Announcement(unittest.TestCase):
    def test_it_states_the_dates_and_how_to_register_and_says_pilot(self):
        text = challenge.announcement(WINDOW, repo="code-assurance-initiative/scanner-benchmark")
        for needle in ("2026-11-30", "2026-12-01", "2026-12-15", "register-engine", "pilot"):
            self.assertIn(needle, text)

    def test_the_linkedin_text_fits_and_links_back(self):
        text = challenge.linkedin(WINDOW, repo="code-assurance-initiative/scanner-benchmark")
        self.assertLessEqual(len(text), 1300)
        self.assertIn("https://github.com/code-assurance-initiative/scanner-benchmark", text)


if __name__ == "__main__":
    unittest.main()
