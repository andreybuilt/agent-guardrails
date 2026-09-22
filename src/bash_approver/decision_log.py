"""Append-only decision telemetry, for tuning the safe-lists against real traffic.

The record shape is deliberately unchanged by the module split: {cmd, decision, reason},
one JSON object per line. Anything already reading BASH_APPROVER_LOG keeps working.

Writing never affects the decision. A full disk, a bad path or a permission error is
swallowed, because a hook that fails to log must still answer the host.

Config: BASH_APPROVER_LOG=/path.jsonl (unset = no telemetry)
"""
from __future__ import annotations

import json
import os


def log_decision(command: str, decision: str, reason: str) -> bool:
    """Append one decision record. Returns True if it was written, for tests."""
    path = os.getenv("BASH_APPROVER_LOG", "").strip()
    if not path:
        return False
    try:
        with open(path, "a") as fh:
            fh.write(json.dumps({"cmd": command, "decision": decision,
                                 "reason": reason}) + "\n")
        return True
    except Exception:
        return False
