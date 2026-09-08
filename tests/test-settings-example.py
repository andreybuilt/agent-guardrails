#!/usr/bin/env python3
"""Assert settings.example.json wires every shipped hook at the event it declares.

This exists because the example wired orphan-tooling-guard.py under PreToolUse when it is a
Stop hook, and omitted guard-git.py entirely. Both are silent failures for anyone following
the install instructions: a hook at the wrong event never sees the payload it inspects, and a
hook nobody wires does nothing at all. Neither shows up as an error.

The source of truth is each hook's own docstring, not this file and not the README.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fail = []

shipped = sorted(f for f in os.listdir(os.path.join(ROOT, "hooks"))
                 if f.endswith((".py", ".sh")))

# What each hook says about itself, read from its first 40 lines.
declared = {}
for f in shipped:
    head = open(os.path.join(ROOT, "hooks", f), encoding="utf-8",
                errors="replace").read(4000)
    m = re.search(r"\b(PreToolUse|Stop)\b", head)
    declared[f] = m.group(1) if m else None
    if declared[f] is None:
        fail.append("%s declares no event in its header" % f)

cfg = json.load(open(os.path.join(ROOT, "settings.example.json")))
wired = {}
for event, entries in cfg.get("hooks", {}).items():
    for entry in entries:
        for hook in entry.get("hooks", []):
            wired[hook["command"].rsplit("/", 1)[-1]] = event

for f in shipped:
    if f not in wired:
        fail.append("%s is shipped but not wired in settings.example.json" % f)
    elif declared[f] and wired[f] != declared[f]:
        fail.append("%s declares %s but the example wires it under %s"
                    % (f, declared[f], wired[f]))

for f in wired:
    if f not in shipped:
        fail.append("the example wires %s, which this repository does not ship" % f)

for line in fail:
    print("  [FAIL] %s" % line)
if not fail:
    print("  ok    %d hooks, each wired at the event it declares" % len(shipped))
sys.exit(1 if fail else 0)
