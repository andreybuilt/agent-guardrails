"""The adversarial battery, run against the cases in tests/fixtures/.

The cases used to live in the production file. They are data, not logic, and keeping
them there meant every reader of the classifier scrolled past a hundred string literals
to reach it. They now live in tests/fixtures/bash_approver_cases.json and this module
runs them, so `hooks/bash-approver.py --selftest` is still the one command that proves
the hook, and `./tests/run-all.sh` still calls exactly that.

The fixture stores the home directory as the token {HOME}, expanded here. Four cases
target the user's own home, and writing the expanded value into the file would put a
real username into the repository, which the suite's own leak sweep refuses.

Output format is unchanged, including the summary line, because CI and the README quote
it.
"""
from __future__ import annotations

import json
import os
import sys

from .policy import DECISION_ALLOW, decide, promotable

_PKG = os.path.dirname(os.path.abspath(__file__))
_CASE_CANDIDATES = (
    os.path.join(os.path.dirname(os.path.dirname(_PKG)), "tests", "fixtures",
                 "bash_approver_cases.json"),          # running from a checkout
    os.path.join(_PKG, "fixtures", "bash_approver_cases.json"),   # bundled alongside
)


def case_file() -> str:
    override = os.getenv("BASH_APPROVER_CASES", "").strip()
    if override:
        return override
    for c in _CASE_CANDIDATES:
        if os.path.isfile(c):
            return c
    raise FileNotFoundError(
        "battery fixtures not found. Looked in:\n  " + "\n  ".join(_CASE_CANDIDATES) +
        "\nThe battery ships in tests/, which the flat hook install does not copy. "
        "Run --selftest from a checkout, or point BASH_APPROVER_CASES at the file.")


def load_cases(path: str | None = None):
    """-> (envelope_cases, decision_cases) as lists of (command, expected)."""
    data = json.load(open(path or case_file()))
    home = os.path.expanduser("~")
    token = data.get("home_token", "{HOME}")
    exp = lambda s: s.replace(token, home)
    envelope = [(exp(c["command"]), c["promotable"]) for c in data["envelope"]]
    decisions = [(exp(c["command"]), c["expect"]) for c in data["decisions"]]
    return envelope, decisions


def run_selftest(path: str | None = None) -> int:
    try:
        envelope, decisions = load_cases(path)
    except FileNotFoundError as e:
        print(e)
        return 1
    passed = failed = 0
    wrong_allow = 0
    for cmd, want in envelope:
        got = promotable(cmd)
        ok = got == want
        passed += ok
        failed += (not ok)
        if not ok and got:
            wrong_allow += 1
        print(f"  [{'ok  ' if ok else 'FAIL'}] envelope want={want} got={got}  {cmd}")
    for cmd, want in decisions:
        got, reason = decide(cmd)
        ok = got == want
        passed += ok
        failed += (not ok)
        if not ok and got == DECISION_ALLOW:
            wrong_allow += 1
        mark = "ok  " if ok else "FAIL"
        disp = cmd.replace("\n", "\\n")
        print(f"  [{mark}] want={want:5} got={got:5}  {disp}")
        if not ok:
            print(f"         reason: {reason}")
    print(f"\n{passed}/{passed+failed} passed, {failed} failed"
          f"{'  ⚠️ %d WRONG-ALLOW' % wrong_allow if wrong_allow else '  (zero wrong-allow)'}")
    return 1 if failed else 0


if __name__ == "__main__":       # pragma: no cover
    sys.exit(run_selftest())
