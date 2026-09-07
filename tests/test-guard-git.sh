#!/usr/bin/env bash
# Matrix for guard-git.py. Every row is proved in BOTH directions: a case that must be
# refused, and the wrongly-satisfied twin that must pass. Rows 7-9 are the two false
# positives the hook's own header records; they exist so a "tightening" that reintroduces
# them fails here instead of in someone's working tree.
set -u
HOOK="$(cd "$(dirname "$0")/.." && pwd)/hooks/guard-git.py"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0

mkrepo() {                      # mkrepo <name> -> path, one commit on main
  local d="$TMP/$1"; mkdir -p "$d"; git -C "$d" init -q -b main
  git -C "$d" config user.email t@t; git -C "$d" config user.name t
  echo base > "$d/tracked.txt"; git -C "$d" add -A; git -C "$d" commit -qm base; echo "$d"
}

run() {                         # run <want deny|allow> <label> <command>
  local want="$1" label="$2" cmd="$3" got
  printf '{"tool_name":"Bash","tool_input":{"command":%s}}' \
    "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$cmd")" \
    | python3 "$HOOK" >/dev/null 2>&1
  [ $? -eq 2 ] && got=deny || got=allow
  if [ "$got" = "$want" ]; then printf '  [ok  ] want=%-5s got=%-5s %s\n' "$want" "$got" "$label"; pass=$((pass+1))
  else printf '  [FAIL] want=%-5s got=%-5s %s\n' "$want" "$got" "$label"; fail=$((fail+1)); fi
}

CLEAN=$(mkrepo clean)
DIRTY=$(mkrepo dirty);      echo changed > "$DIRTY/tracked.txt"
UNTRK=$(mkrepo untracked);  echo new > "$UNTRK/newfile.txt"
AHEAD=$(mkrepo ahead);      git -C "$AHEAD" checkout -qb feature; echo x > "$AHEAD/f.txt"
                            git -C "$AHEAD" add -A; git -C "$AHEAD" commit -qm ahead; git -C "$AHEAD" checkout -q main
MERGED=$(mkrepo merged);    git -C "$MERGED" branch merged-branch

echo "== guard-git: must refuse =="
run deny  "push --force"                       "git push --force origin main"
run deny  "push --force-with-lease"            "git push --force-with-lease origin main"
run deny  "push -f short flag"                 "git push -f origin main"
run deny  "reset --hard with tracked changes"  "git -C $DIRTY reset --hard"
run deny  "clean -fd with untracked present"   "git -C $UNTRK clean -fd"
run deny  "branch -D holding unmerged commits" "git -C $AHEAD branch -D feature"

echo "== guard-git: must ALLOW (the wrongly-satisfied twins) =="
run allow "reset --hard on a clean repo"       "git -C $CLEAN reset --hard"
run allow "reset --hard, only UNTRACKED files" "git -C $UNTRK reset --hard"
run allow "clean -fd, only TRACKED changes"    "git -C $DIRTY clean -fd"
run allow "branch -D on a merged branch"       "git -C $MERGED branch -D merged-branch"
run allow "quoted mention in a commit message" "git commit -m \"removed the worktree with --force\""
run allow "quoted mention in echo"             "echo 'git push --force'"
run allow "an ordinary git command"            "git -C $DIRTY status"

echo
if [ "$fail" -eq 0 ]; then echo "  $pass/$((pass+fail)) passed  (guard-git matrix)"; exit 0
else echo "  $pass passed, $fail FAILED  (guard-git matrix)"; exit 1; fi
