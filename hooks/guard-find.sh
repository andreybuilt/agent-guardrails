#!/usr/bin/env bash
# guard-find.sh: Claude Code PreToolUse guard (Bash).
#
# Blocks any `find` invocation that carries a DESTRUCTIVE action primary:
#   -delete, -exec, -execdir, -ok, -okdir, -fprint, -fprintf, -fls
# These turn a read-only `find` sweep into file deletion, arbitrary command
# execution per match, or arbitrary file writes.
#
# Why a hook and not a permission rule: Claude Code permission rules match on
# command PREFIX only, so they cannot express "find, but only with -delete".
# The colon-form Bash(find:*) would block ALL find. A PreToolUse hook can
# inspect the real command string and block only the dangerous shape.
#
# Contract: reads the tool-call JSON on stdin; exit 0 = allow, exit 2 = block
# (stderr is surfaced to Claude as the reason). Deliberately does NOT match the
# safe read-only test -executable.
#
# In production since 2026-07-11.

cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null)
[ -z "$cmd" ] && exit 0

# Three things have to be true at once, and each one is a defect this hook already shipped.
#
# 1. A quoted FLAG is the same flag. `find . '-delete'` ran freely until 2026-09-07 because the
#    match required whitespace in front of the flag and a quote is not whitespace.
# 2. A quoted SENTENCE is not a command. An earlier version blocked a report that quoted the
#    flag in order to describe it. A guard that blocks writing about a hazard teaches people
#    to stop writing about it.
# 3. The word has to be in COMMAND POSITION. "we blocked a find carrying -delete" inside a heredoc
#    is prose, and scanning the whole string cannot tell it from an invocation.
#
# So: drop quoted spans that contain whitespace (those are sentences), unquote the ones that
# do not (those are arguments), then look only at what follows an invocation.

norm=$(printf '%s' "$cmd" | python3 -c '
import re,sys
s=sys.stdin.read()
def q(m):
    inner=m.group(2)
    return " " if re.search(r"\s", inner) else inner
sys.stdout.write(re.sub(r"([\x27\"])(.*?)\1", q, s, flags=re.S))')

# Command position: start of string, or after a separator, optionally behind sudo/env/nice.
INVOKE=$(printf '%s' "$norm" | grep -Eo '(^|[;&|(]|&&|\|\|)[[:space:]]*(sudo[[:space:]]+|env[[:space:]]+|nice[[:space:]]+)*g?find([[:space:]]|$).*' | head -1)
[ -z "$INVOKE" ] && exit 0

if printf '%s' "$INVOKE" | grep -Eq '(^|[[:space:]])(-delete|-execdir|-exec|-okdir|-ok|-fprintf|-fprint|-fls)([[:space:]]|$)'; then
  echo "guard-find: blocked a 'find' command using a destructive action flag. These can delete files or run arbitrary commands per match. If this is truly intended, run that specific step yourself outside the agent." >&2
  exit 2
fi

exit 0
