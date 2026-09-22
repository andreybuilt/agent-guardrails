#!/usr/bin/env python3
"""bash-approver: Claude Code PreToolUse (Bash) auto-approver. HARDENED (v2).

WHY: cut permission-prompt friction ("auto mode cannot determine safety") without
blanket-allowing. Read-only / side-effect-free commands auto-ALLOW; genuinely
catastrophic ones DENY; everything else falls through to the normal prompt (ASK).
An optional local model can promote gray commands to allow (fail-closed, off by default).

SECURITY MODEL: a wrong ALLOW is the only unacceptable outcome (a wrong ASK is mere
friction). Every ambiguity collapses toward ASK.

THIS FILE IS THE ENTRY POINT ONLY. It reads the host's JSON, calls decide(), and writes
the host's JSON back. The decision logic lives in the `bash_approver` package:

    segmentation    quote-aware splitting, redirect classification, preflight
    command_model   env/wrapper/sudo peeling to the program that actually runs
    destructive     catastrophe detection, the only layer that says DENY
    policy          the allow/ask/deny rules and the model-promotion envelope
    model_promoter  the optional local model, fail-closed
    decision_log    append-only telemetry

The package is found next to this file after the documented install, or in ../src when
running from a checkout. Standard library only, no third-party imports anywhere.

CONTRACT (Claude Code PreToolUse):
  stdin  = tool-call JSON ({tool_name, tool_input:{command}, ...})
  stdout = {"hookSpecificOutput":{"hookEventName":"PreToolUse",
            "permissionDecision":"allow|deny|ask","permissionDecisionReason":"..."}}
  allow/deny emit JSON; ask exits 0 silently (normal flow). Composes with guard-find.sh
  (never ALLOWs a destructive find, so guard-find still denies it).

Config (env): BASH_APPROVER_MODEL="ollama:MODEL@HOST:PORT" (gray→allow promoter, off=default);
              BASH_APPROVER_LOG=/path.jsonl (append decisions for tuning).
Run `bash-approver.py --selftest` for the battery.
"""
from __future__ import annotations

import json
import os
import sys

# Never leave a __pycache__ behind. A .pyc embeds the absolute source path, which puts a
# real username into any tree this is copied into, and the pre-publish leak sweep in
# tests/run-all.sh scans file contents including binaries. Set before the first import
# of the package, or the first run writes the files this is meant to prevent.
sys.dont_write_bytecode = True

_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (_HERE, os.path.join(os.path.dirname(_HERE), "src")):
    # After the documented install the package sits beside this file; in a checkout it is
    # in ../src. Probe for the package itself rather than trusting either layout.
    if os.path.isdir(os.path.join(_candidate, "bash_approver")):
        if _candidate not in sys.path:
            sys.path.insert(0, _candidate)
        break
else:  # pragma: no cover - only reachable from a broken install
    sys.stderr.write(
        "bash-approver: cannot find the bash_approver package next to %s or in ../src. "
        "Re-run the install from the README quick start.\n" % _HERE)
    sys.exit(0)  # exit 0 = ASK: a broken install must not block the user

from bash_approver.decision_log import log_decision          # noqa: E402
from bash_approver.model_promoter import model_promote       # noqa: E402
from bash_approver.policy import (                           # noqa: E402
    DECISION_ALLOW,
    DECISION_ASK,
    DECISION_DENY,
    decide,
    promotable,
)

# Back-compat aliases. The private names were this file's public surface for anything
# that imported it directly, and the split should not break such a caller.
_promotable = promotable


def _emit(decision: str, reason: str):
    if decision == DECISION_ASK:
        sys.exit(0)
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": f"bash-approver: {reason}",
    }}))
    sys.exit(0)


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        sys.exit(0)
    if data.get("tool_name") not in (None, "Bash"):
        sys.exit(0)
    command = (data.get("tool_input") or {}).get("command", "")

    decision, reason = decide(command)
    # model may ONLY promote ask→allow, ONLY within the promotion envelope, and never
    # overrides a deny. The envelope guard means a model false-SAFE can't leak a
    # network/package/service/file command through.
    if decision == DECISION_ASK and promotable(command) and model_promote(command):
        decision, reason = DECISION_ALLOW, "local model judged side-effect-free (within promote envelope)"

    log_decision(command, decision, reason)
    _emit(decision, reason)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        from bash_approver.selftest import run_selftest
        sys.exit(run_selftest())
    main()
