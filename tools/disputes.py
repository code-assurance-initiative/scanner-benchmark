"""The answer-key dispute ledger, disputes/ledger.json: its shape, its append-only history, and its counts.

The process is CAI decision 0001 (CodeAssuranceIndex docs/decisions/0001-adopt-the-answer-key-dispute-path.md),
described in disputes/README.md. Every decided dispute, whatever its outcome, is one entry appended to the ledger.

    python3 -m tools.disputes validate      # shape of every entry + append-only against git history; exit 1 + problems
    python3 -m tools.disputes stats         # disputes per claimant scanner and outcome, as JSON

Why append-only is checked against git history and not against a stored count or hash: a stored count or hash sits
in the same commit as the ledger, so an edit and a matching update of the stored value land together and the check
passes. The history cannot be rewritten that way on main, and every committed version is compared with the next, so
committing an edit does not launder it.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join("disputes", "ledger.json")

ABSENT = object()  # marks a field removed from an entry (tests); never a value in a ledger

OUTCOMES = ("upheld", "corrected", "not-evidenced", "withdrawn")
OPS = ("relabel", "relocate", "remove")
# A relabel turns a plant into a trap or a trap into a plant (proposal 0001 §2.4); anything else is a new entry,
# authored and frozen, not a dispute outcome.
RELABEL_TO = ("must-fire", "must-not-fire")

# Required in every entry. `claimantScanner` and `publication` may be null but must be present, so a reader can tell
# "no scanner" from "nobody recorded it".
REQUIRED = ("case", "filed", "date", "set", "unit", "entryId", "keyVersion", "keySha256", "outcome",
            "claimant", "claimantScanner", "labeller", "adjudicator", "evidence")
NULLABLE = ("claimantScanner", "publication")

# Plain MAJOR.MINOR.PATCH. A version with build metadata (Watchdog's "1.0.0+wd.1") belongs to one scanner's own copy
# of the keys and is never a CAI key version (proposal 0001 §3), so it is refused rather than compared.
VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _version(v):
    m = VERSION.match(v) if isinstance(v, str) else None
    return tuple(int(x) for x in m.groups()) if m else None


def _date(v):
    try:
        return datetime.date.fromisoformat(v) if isinstance(v, str) and len(v) == 10 else None
    except ValueError:
        return None


def _text(v):
    return isinstance(v, str) and v.strip() != ""


def validate(ledger):
    """Every problem with a ledger, as sentences. Empty when it is well formed."""
    if not isinstance(ledger, list):
        return ["the ledger must be a JSON array of entries"]
    problems = []
    for i, e in enumerate(ledger):
        where = f"entry {i} ({e.get('case', '?')})" if isinstance(e, dict) else f"entry {i}"
        if not isinstance(e, dict):
            problems.append(f"{where}: must be an object")
            continue
        for f in REQUIRED:
            if f not in e:
                problems.append(f"{where}: {f} is missing")
            elif f not in NULLABLE and not _text(e[f]):
                problems.append(f"{where}: {f} must be a non-empty string")
        for f in NULLABLE:
            if f in e and e[f] is not None and not _text(e[f]):
                problems.append(f"{where}: {f} must be a non-empty string or null")

        filed, decided = _date(e.get("filed")), _date(e.get("date"))
        if "filed" in e and filed is None:
            problems.append(f"{where}: filed must be an ISO date (YYYY-MM-DD)")
        if "date" in e and decided is None:
            problems.append(f"{where}: date must be an ISO date (YYYY-MM-DD)")
        if filed and decided and decided < filed:
            problems.append(f"{where}: date (the decision) precedes filed")
        if "keyVersion" in e and _version(e["keyVersion"]) is None:
            problems.append(f"{where}: keyVersion must be a CAI key version MAJOR.MINOR.PATCH")
        if "keySha256" in e and not (isinstance(e["keySha256"], str) and SHA256.match(e["keySha256"])):
            problems.append(f"{where}: keySha256 must be the 64-hex sha256 of the disputed key")

        # The recusal rule (proposal 0001 §2.3), as far as names can show it. Affiliation with the claimant's scanner
        # is not visible in a name; the decision on the issue records that part.
        adj = e.get("adjudicator")
        if _text(adj) and adj == e.get("claimant"):
            problems.append(f"{where}: the adjudicator is the claimant")
        if _text(adj) and adj == e.get("labeller"):
            problems.append(f"{where}: the adjudicator is the labeller of the entry")

        outcome = e.get("outcome")
        if "outcome" in e and outcome not in OUTCOMES:
            problems.append(f"{where}: outcome must be one of {', '.join(OUTCOMES)}")
        if outcome in ("upheld", "corrected") and not _text(e.get("journal")):
            problems.append(f"{where}: an {outcome} entry cites the journal entry that records it (journal)")
        if outcome == "corrected":
            new, old = _version(e.get("newKeyVersion")), _version(e.get("keyVersion"))
            if new is None:
                problems.append(f"{where}: a corrected entry names its new key version (newKeyVersion MAJOR.MINOR.PATCH)")
            elif old is not None and new <= old:
                problems.append(f"{where}: newKeyVersion {e['newKeyVersion']} must be later than keyVersion {e['keyVersion']}")
            if e.get("op") not in OPS:
                problems.append(f"{where}: a corrected entry states its op, one of {', '.join(OPS)}")
            if e.get("op") == "relabel" and e.get("to") not in RELABEL_TO:
                problems.append(f"{where}: a relabel states the new label in to, one of {', '.join(RELABEL_TO)}")
        elif outcome in OUTCOMES:
            for f in ("newKeyVersion", "op", "to"):
                if e.get(f) is not None:
                    problems.append(f"{where}: an {outcome} entry changed no key, so it has no {f}")
    return problems


def append_only(older, newer):
    """Problems if `newer` is not `older` with entries appended. Compares parsed JSON, so reformatting is not an edit."""
    if not isinstance(older, list) or not isinstance(newer, list):
        return ["the ledger is not a JSON array in both versions"]
    if len(newer) < len(older):
        return [f"the ledger shrank from {len(older)} to {len(newer)} entries: an entry was removed"]
    return [f"entry {i} was edited or moved: the ledger is append-only"
            for i, (a, b) in enumerate(zip(older, newer)) if a != b]


def _git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)


def history_problems(root=ROOT):
    """Compare every committed version of the ledger with the next, and the last with the working copy."""
    shallow = _git(root, "rev-parse", "--is-shallow-repository")
    if shallow.returncode != 0:
        return [f"cannot read the git history of {root}: {shallow.stderr.strip()}"]
    if shallow.stdout.strip() == "true":
        # A shallow clone shows one commit, against which any edit looks like the first version. Refuse rather than
        # pass: CI must check out with fetch-depth 0.
        return ["the clone is shallow, so the ledger's history cannot be checked: fetch the full history"]
    shas = _git(root, "log", "--reverse", "--format=%H", "--", LEDGER).stdout.split()
    versions = []
    for sha in shas:
        shown = _git(root, "show", f"{sha}:{LEDGER}")
        if shown.returncode != 0:
            return [f"commit {sha[:12]} deleted {LEDGER}: the ledger is append-only"]
        try:
            versions.append((sha[:12], json.loads(shown.stdout)))
        except json.JSONDecodeError as ex:
            return [f"commit {sha[:12]}: {LEDGER} is not JSON ({ex})"]
    path = os.path.join(root, LEDGER)
    if os.path.exists(path):
        with open(path) as f:
            versions.append(("working copy", json.load(f)))
    elif versions:
        return [f"{LEDGER} is missing from the working copy: the ledger is append-only"]
    problems = []
    for (prev_name, prev), (name, cur) in zip(versions, versions[1:]):
        problems += [f"{name} against {prev_name}: {p}" for p in append_only(prev, cur)]
    return problems


def stats(ledger):
    """{claimant scanner: {filed, upheld, corrected, not-evidenced, withdrawn}} — proposal 0001 §2.6."""
    out = {}
    for e in ledger:
        row = out.setdefault(e.get("claimantScanner") or "(no scanner)", dict.fromkeys(("filed",) + OUTCOMES, 0))
        row["filed"] += 1
        if e.get("outcome") in OUTCOMES:
            row[e["outcome"]] += 1
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tools.disputes")
    ap.add_argument("cmd", choices=["validate", "stats"])
    a = ap.parse_args(argv)
    with open(os.path.join(ROOT, LEDGER)) as f:
        ledger = json.load(f)
    if a.cmd == "validate":
        problems = validate(ledger) + history_problems(ROOT)
        for p in problems:
            print(p, file=sys.stderr)
        return 1 if problems else 0
    json.dump(stats(ledger), sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
