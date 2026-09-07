#!/usr/bin/env bash
# guard-find.sh — Claude Code PreToolUse guard (Bash).
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

# Require an actual `find` invocation AND a destructive primary (as a whole token).
if printf '%s' "$cmd" | grep -Eqw 'find' \
   && printf '%s' "$cmd" | grep -Eq '(^|[[:space:]])(-delete|-execdir|-exec|-okdir|-ok|-fprintf|-fprint|-fls)([[:space:]]|$)'; then
  echo "guard-find: blocked a 'find' command using a destructive action flag (-delete / -exec / -ok / -fprint / -fls). These can delete files or run arbitrary commands per match. If this is truly intended, run that specific step yourself outside the agent." >&2
  exit 2
fi

exit 0
