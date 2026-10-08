"""The quarterly benchmark challenge: which milestone is due today, and the texts that announce a window.

Read by .github/workflows/challenge.yml every day. Each milestone is done once and recorded in
challenge/state.json, so a day the workflow missed is caught up the next time it runs.

    python3 -m tools.challenge due [--today YYYY-MM-DD]          # print due actions, one per line: <action> <window>
    python3 -m tools.challenge render <window> --out DIR           # write announcement.md and linkedin.txt
    python3 -m tools.challenge record <action> <window>            # mark an action done in challenge/state.json
    python3 -m tools.challenge validate                            # check challenge/calendar.json
"""
import argparse
import datetime
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CALENDAR = os.path.join(ROOT, "challenge", "calendar.json")
STATE = os.path.join(ROOT, "challenge", "state.json")

# The order a window moves through, with the calendar field that dates each step.
MILESTONES = [
    ("announce", "announceOn"),
    ("close-registration", "registrationClosesOn"),
    ("open", "opensOn"),
    ("reveal", "revealOn"),
]
MIN_NOTICE_DAYS = 30


def _date(s):
    return datetime.date.fromisoformat(s)


def validate(calendar):
    """Every problem with a calendar, as sentences. Empty when it is usable."""
    problems = []
    seen = set()
    for w in calendar.get("windows", []):
        wid = w.get("id", "?")
        if wid in seen:
            problems.append(f"{wid}: the id is used twice")
        seen.add(wid)
        missing = [f for _, f in MILESTONES if f not in w]
        if missing:
            problems.append(f"{wid}: missing {', '.join(missing)}")
            continue
        dates = [_date(w[f]) for _, f in MILESTONES]
        if dates != sorted(dates) or len(set(dates)) != len(dates):
            problems.append(f"{wid}: the milestones are not in order (announce < close < open < reveal)")
        if (_date(w["opensOn"]) - _date(w["announceOn"])).days < MIN_NOTICE_DAYS:
            problems.append(f"{wid}: the announcement must come at least {MIN_NOTICE_DAYS} days before the window opens")
    return problems


def due(windows, today, done=None):
    """The actions whose day has come and that are not yet recorded as done, in calendar order. A day the workflow
    missed is therefore caught up on the next run, and an action is never done twice."""
    done = set() if done is None else done
    return [(action, w["id"]) for w in windows for action, field in MILESTONES
            if _date(w[field]) <= today and (action, w["id"]) not in done]


def announcement(w, repo):
    pilot = (
        "\n> **This window is a pilot.** It rehearses the procedure in public. Its holdout was authored before the "
        "qualification protocol was published, so its results qualify no engine; they are published in full all the "
        "same.\n" if w.get("pilot") else ""
    )
    return f"""# Benchmark challenge {w['id']}: registration is open

Any code scanner can be measured on a sealed holdout of small synthetic repositories whose answer keys say exactly
which defects are planted and which look-alikes are traps. The result is recall, trap resistance and noise per
dimension, with 95 % intervals — published for every engine that takes part, including any that do badly.
{pilot}
| | Date |
|---|---|
| Registration closes | {w['registrationClosesOn']} |
| Window opens (engines are run) | {w['opensOn']} |
| Holdout, answer keys and all results revealed | {w['revealOn']} |

**How to take part:** open a [register-engine](https://github.com/{repo}/issues/new?template=register-engine.yml)
issue before {w['registrationClosesOn']}: the engine as a container image by digest, its configuration, and its
mapping from rule ids to the benchmark's concepts. What the container must do is in
[docs/CHALLENGE-RUN.md](https://github.com/{repo}/blob/main/docs/CHALLENGE-RUN.md). Nothing you submit can change after
registration closes, and every engine gets one run.

The holdout ({w['holdout']}) was sealed in public before this announcement: its hashes are in
[registry.json](https://github.com/{repo}/blob/main/registry.json), so anyone can check at reveal that what was scored
is what was sealed. The scheme: [ENGINE-QUALIFICATION.md](https://github.com/code-assurance-initiative/CodeAssuranceIndex/blob/main/docs/ENGINE-QUALIFICATION.md).
"""


def linkedin(w, repo):
    pilot = " (a public pilot of the procedure)" if w.get("pilot") else ""
    return (
        f"Benchmark challenge {w['id']}{pilot}: registration is open until {w['registrationClosesOn']}.\n\n"
        "Bring any code scanner. It runs once, offline, on a sealed holdout of synthetic repositories where the answer "
        "keys say exactly which defects are planted and which look-alikes are traps. We publish recall, trap "
        "resistance and noise per dimension for every engine — the good results and the bad.\n\n"
        f"Window opens {w['opensOn']}. Everything is revealed {w['revealOn']}, and the holdout's hashes are already "
        "public, so anyone can check that what was scored is what was sealed.\n\n"
        f"How to register: https://github.com/{repo}\n\n#CodeAssuranceIndex #OpenStandard #StaticAnalysis"
    )


def _load(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tools.challenge")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("due")
    d.add_argument("--today")
    r = sub.add_parser("render")
    r.add_argument("window")
    r.add_argument("--out", required=True)
    r.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "code-assurance-initiative/scanner-benchmark"))
    rec = sub.add_parser("record")
    rec.add_argument("action")
    rec.add_argument("window")
    sub.add_parser("validate")
    a = ap.parse_args(argv)

    calendar = _load(CALENDAR, {"windows": []})
    if a.cmd == "validate":
        problems = validate(calendar)
        for p in problems:
            print(p, file=sys.stderr)
        return 1 if problems else 0
    if a.cmd == "due":
        today = _date(a.today) if a.today else datetime.date.today()
        done = {tuple(x) for x in _load(STATE, {"done": []})["done"]}
        for action, wid in due(calendar["windows"], today, done=done):
            print(action, wid)
        return 0
    if a.cmd == "render":
        w = next(x for x in calendar["windows"] if x["id"] == a.window)
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "announcement.md"), "w") as f:
            f.write(announcement(w, a.repo))
        with open(os.path.join(a.out, "linkedin.txt"), "w") as f:
            f.write(linkedin(w, a.repo))
        return 0
    if a.cmd == "record":
        state = _load(STATE, {"done": []})
        entry = [a.action, a.window]
        if entry not in state["done"]:
            state["done"].append(entry)
        with open(STATE, "w") as f:
            json.dump(state, f, indent=2)
            f.write("\n")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
