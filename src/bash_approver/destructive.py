"""Catastrophic-operation detection. The only layer that is allowed to say DENY.

It is separate from policy on purpose. policy answers "is this known to be safe", and a
safe-list that answers no just falls through to a human. This answers "is this going to
destroy the machine", and nothing downstream gets a vote: decide() runs these checks
FIRST, on every segment, both before and after prefix-stripping, so a wrapper cannot
hide the target.

Two shapes, because two kinds of catastrophe exist:

  argv-level   base-gated, needs the resolved argv (rm, dd, mkfs, chmod/chown -R)
  regex-level  spans segments and pipes, so no single argv can see it
               (fork bomb, curl | sh, redirect to a raw disk)
"""
from __future__ import annotations

import os
import re

from .command_model import base_name

PROTECTED = {"/", "/*", "~", "~/", "$HOME", "*", "/Users", "/home", os.path.expanduser("~"),
             "/etc", "/var", "/usr", "/bin", "/sbin", "/opt", "/System",
             "/Library", "/private", "/boot"}

# `of=` is the write side. Reading a raw device was never the trigger, but a sink is not a
# device: of=/dev/null and of=/dev/stdout write nowhere.
DD_SINKS = ("of=/dev/null", "of=/dev/stdout", "of=/dev/stderr", "of=/dev/tty", "of=/dev/zero")


def is_catastrophic_argv(argv):
    """base-gated catastrophe checks on a resolved argv. Returns reason or None."""
    if not argv:
        return None
    base = base_name(argv[0])

    if base == "rm":
        recursive = any(a in ("-r", "-R", "-rf", "-fr", "-Rf", "-fR", "--recursive")
                        or (a.startswith("-") and not a.startswith("--")
                            and ("r" in a.lower()))
                        for a in argv[1:])
        targets = [a for a in argv[1:] if not a.startswith("-")]
        if "--no-preserve-root" in argv:
            return "rm --no-preserve-root"
        if recursive and any(t in PROTECTED or t.rstrip("/") in PROTECTED for t in targets):
            return f"recursive rm of a protected path ({', '.join(targets)})"

    # The rule always checked which SIDE the device was on: only `of=` counts, so reading a raw
    # device was never the trigger. What it did not do was distinguish a raw device from a sink.
    # `of=/dev/null` and `of=/dev/stdout` write nowhere, and blocking them is the over-block this
    # repository documents. Corrected 2026-09-07, after a review pointed out that the README
    # described this rule as ignoring the side, which it never did.
    if base == "dd" and any(a.startswith("of=/dev/") for a in argv) \
       and not any(a in DD_SINKS for a in argv):
        return "dd writing to a raw device"

    if re.match(r"mkfs(\.|$)", base) or base in ("newfs", "diskutil"):
        if base == "diskutil" and not any(a in ("eraseDisk", "eraseVolume",
                                                "partitionDisk", "reformat") for a in argv):
            return None
        return f"{base} (format/erase filesystem)"

    if base in ("chmod", "chown"):
        recursive = any(a == "-R" or a == "--recursive"
                        or (a.startswith("-") and not a.startswith("--") and "R" in a)
                        for a in argv)
        targets = [a for a in argv[1:] if not a.startswith("-")]
        if recursive and any(t == "/" or t.rstrip("/") in PROTECTED for t in targets):
            return f"recursive {base} on a protected path"

    return None


def is_catastrophic_regex(raw: str):
    """whole-command regex catastrophe checks (span across segments/pipes)."""
    flat = raw.replace(" ", "")
    if re.search(r":\s*\(\s*\)\s*\{.*\|.*&\s*\}\s*;", raw) or ":(){:|:&};:" in flat:
        return "fork bomb"
    if re.search(r"\b(curl|wget|fetch)\b", raw) and re.search(r"\|\s*(sudo\s+)?(ba|z|k|c)?sh\b", raw):
        return "piping a network download into a shell"
    if re.search(r">\s*/dev/(sd|disk|rdisk|nvme|hd)", raw):
        return "redirect to a raw disk device"
    return None
