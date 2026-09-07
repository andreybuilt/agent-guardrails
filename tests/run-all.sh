#!/usr/bin/env bash
# Run every check this repository ships. Exits non-zero on the first failure.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0

echo "== syntax =="
for f in hooks/*.py; do
  python3 -m py_compile "$f" && echo "  ok    $f" || { echo "  FAIL  $f"; fail=1; }
done
for f in hooks/*.sh; do
  bash -n "$f" && echo "  ok    $f" || { echo "  FAIL  $f"; fail=1; }
done
rm -rf hooks/__pycache__

echo
echo "== bash-approver adversarial battery =="
if python3 hooks/bash-approver.py --selftest; then
  echo "  battery passed"
else
  echo "  BATTERY FAILED"; fail=1
fi

echo
echo "== guard-find matrix =="
if ./tests/test-guard-find.sh; then
  echo "  guard-find matrix passed"
else
  echo "  GUARD-FIND MATRIX FAILED"; fail=1
fi

echo
echo "== guard-git matrix =="
if ./tests/test-guard-git.sh; then
  echo "  guard-git matrix passed"
else
  echo "  GUARD-GIT MATRIX FAILED"; fail=1
fi

echo
echo "== no leaked identifiers =="
# Built at run time so this file never itself contains a real identifier, and so a fork
# checks ITS author's name rather than ours. Override with GUARD_LEAK_RE to add your own.
LEAK_RE="${GUARD_LEAK_RE:-$(id -un)|@gmail\.|@icloud\.|10\.10\.|${HOME}}"
if grep -rniE "$LEAK_RE" . --exclude-dir=.git 2>/dev/null; then
  echo "  FAIL: identifier found above"; fail=1
else
  echo "  ok    none found"
fi

echo
[ "$fail" -eq 0 ] && echo "ALL CHECKS PASSED" || echo "FAILURES ABOVE"
exit "$fail"
