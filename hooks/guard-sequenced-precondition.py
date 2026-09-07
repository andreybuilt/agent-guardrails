#!/usr/bin/env python3
# guard-sequenced-precondition.py — PreToolUse guard (Bash).
#
# Blocks the two shell shapes that silently defeat a caller-side precondition check.
#
# THE PATTERN. Plenty of tooling documents a guard as a CALLER-side convention:
#
#     precondition-check ... || exit 1
#     # ...then the real work
#
# A caller who instead writes
#
#     precondition-check ... ; real-work
#
# gets no guard at all. The refusal prints, exit 1 is returned, and the `;` runs the work
# regardless. The check ran, returned the correct answer, and was wired to nothing.
#
# This is not hypothetical. In the incident that produced this hook, a distributed-lock
# acquire was REFUSED because another worker held the lock, and the file sync on the same
# line ran anyway — writing to a host that was already being written to.
#
# Piping the check is the same failure by another route: in `check ... | tail -2`, `$?`
# becomes tail's status, so a refusal reads as success.
#
# BLOCKS:
#   1. `<precondition> ...` terminated by `;` or a newline with more work after it
#   2. `<precondition> ...` piped into anything (exit status destroyed)
#
# ALLOWS:
#   - `<precondition> ... || exit 1`   the documented guard, correctly wired
#   - `<precondition> ... && work`     work gated on success
#   - `<precondition> ...` alone       result surfaces before the next tool call
#   - a structural form that takes the work as an argument, leaving no gap to defeat
#
# CONFIGURE: set GUARD_PRECONDITION_RE to a Python regex matching your own check command.
# The default matches `lease.sh acquire`.
#
# Contract: tool-call JSON on stdin; exit 0 = allow, exit 2 = block (stderr shown to the agent).

import json
import os
import re
import sys

# The precondition command this guard protects. Override for your own tool, e.g.
#   GUARD_PRECONDITION_RE='mylock\\s+take\\b'
PRECONDITION = re.compile(
    os.environ.get("GUARD_PRECONDITION_RE", r"lease\.sh\s+acquire\b"))


def split_top_level(cmd: str):
    """Yield (index, operator) for shell operators outside quotes.

    Not a full parser — it tracks single/double quotes and backslash escapes, which is
    enough to keep operators inside quoted strings from being mistaken for real ones.
    """
    i, n = 0, len(cmd)
    squote = dquote = False
    while i < n:
        c = cmd[i]
        if c == '\\' and not squote:
            i += 2
            continue
        if c == "'" and not dquote:
            squote = not squote
        elif c == '"' and not squote:
            dquote = not dquote
        elif not squote and not dquote:
            if cmd.startswith('&&', i):
                yield i, '&&'
                i += 2
                continue
            if cmd.startswith('||', i):
                yield i, '||'
                i += 2
                continue
            if c == '|':
                yield i, '|'
            elif c == ';':
                yield i, ';'
            elif c == '\n':
                yield i, '\n'
        i += 1


HEREDOC = re.compile(r'<<-?\s*(["\']?)([A-Za-z_][A-Za-z0-9_]*)\1')
INTERPRETER = re.compile(r'\b(ssh|bash|sh|zsh|dash)\b')


def strip_heredocs(cmd: str) -> str:
    """Blank out heredoc BODIES so text merely being written isn't read as a command.

    Writing documentation about the unsafe form (a runbook, a policy file, this file's own
    comments) must not trip the guard — a guard that blocks doc edits gets switched off.

    Exception: if the line opening the heredoc invokes a shell or ssh, the body really is
    executed, so it is left in place and scanned.
    """
    out = list(cmd)
    for m in HEREDOC.finditer(cmd):
        delim = m.group(2)
        line_start = cmd.rfind('\n', 0, m.start()) + 1
        line_end = cmd.find('\n', m.end())
        if line_end == -1:
            continue
        opener = cmd[line_start:line_end]
        if INTERPRETER.search(opener):
            continue                                  # body is executed — keep scanning it
        end = re.search(r'(?m)^\s*%s\s*$' % re.escape(delim), cmd[line_end:])
        stop = line_end + (end.start() if end else len(cmd) - line_end)
        for i in range(line_end, stop):
            if out[i] != '\n':
                out[i] = ' '
    return ''.join(out)


def verdict(raw: str):
    """Return None if fine, else a reason string."""
    cmd = strip_heredocs(raw)
    for m in PRECONDITION.finditer(cmd):
        start = m.end()
        term = None
        for idx, op in split_top_level(cmd):
            if idx >= start:
                term = (idx, op)
                break
        if term is None:
            continue                                  # acquire is the last thing — fine
        idx, op = term
        if op in ('&&', '||'):
            continue                                  # correctly gated
        if op == '|':
            return ("piped into another command, which destroys its exit status — a refusal "
                    "then reads as success")
        # ';' or newline: only a problem if real work follows
        rest = cmd[idx + 1:]
        rest = re.sub(r'(?m)^\s*#.*$', '', rest).strip()
        if rest:
            return ("followed by `;` (or a newline) and more commands — the work runs even "
                    "when the lease is REFUSED")
    return None


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    cmd = (payload.get('tool_input') or {}).get('command') or ''
    if not cmd:
        sys.exit(0)

    reason = verdict(cmd)
    if reason:
        sys.stderr.write(
            "guard-lease: blocked — `lease.sh acquire` is {}.\n\n"
            "A lease you did not verify is not a lease. Use the form that has no gap:\n\n"
            "    <precondition-tool> with <args...> -- <command...>\n\n"
            "It acquires, runs the command, and releases on every exit path; if the acquire "
            "is refused the command never runs, and the exit code is the command's.\n"
            "If you truly want the two-step form, gate it: `acquire ... || exit 1`, or run "
            "the acquire as its own call and read the result before doing the work.\n"
            .format(reason))
        sys.exit(2)
    sys.exit(0)


if __name__ == '__main__':
    main()
