#!/usr/bin/env bash
# Matrix for guard-find.sh. Both directions: destructive shapes it must refuse, and
# benign shapes it must allow, including prose that merely names the flag. That last
# class is not padding: an earlier version blocked a report describing the hazard.
set -u
HOOK="$(cd "$(dirname "$0")/.." && pwd)/hooks/guard-find.sh"
pass=0; fail=0
run() {
  local want="$1" label="$2" cmd="$3" got
  printf '{"tool_name":"Bash","tool_input":{"command":%s}}' \
    "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$cmd")" \
    | bash "$HOOK" >/dev/null 2>&1
  [ $? -eq 2 ] && got=deny || got=allow
  if [ "$got" = "$want" ]; then printf '  [ok  ] want=%-5s got=%-5s %s\n' "$want" "$got" "$label"; pass=$((pass+1))
  else printf '  [FAIL] want=%-5s got=%-5s %s\n' "$want" "$got" "$label"; fail=$((fail+1)); fi
}
run deny  "bare destructive flag"                                    'find . -name '\''*.py'\'' -delete'
run deny  "SINGLE-QUOTED flag (the 2026-09-07 bypass)"               'find . -name '\''*.py'\'' '\''-delete'\'''
run deny  "double-quoted flag"                                       'find . -name "*.py" "-delete"'
run deny  "g-prefixed binary"                                        'gfind . -delete'
run deny  "sudo prefix"                                              'sudo find /tmp -delete'
run deny  "exec form"                                                'find . -type f -exec rm {} \\;'
run deny  "after a pipeline separator"                               'ls ; find . -delete'
run allow "read-only sweep"                                          'find . -name '\''*.py'\'''
run allow "-executable is a test, not an action"                     'find . -executable'
run allow "PROSE that quotes the flag (the documented false positive)" 'echo '\''the guard blocks find when it carries -delete'\'''
run allow "a report body mentioning both words"                      'cat >> report.md <<'\''EOT'\''\nwe blocked a find carrying -delete today\nEOT'
run allow "grep for the flag in a file"                              'grep -n -- '\''-delete'\'' notes.md'
run allow "an unrelated command"                                     'ls -la /tmp'

echo
if [ "$fail" -eq 0 ]; then echo "  $pass/$((pass+fail)) passed  (guard-find matrix)"; exit 0
else echo "  $pass passed, $fail FAILED  (guard-find matrix)"; exit 1; fi
