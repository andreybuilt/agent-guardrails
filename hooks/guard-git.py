#!/usr/bin/env python3
"""guard-git.py: PreToolUse hook. Block the four git operations that can destroy work
that exists in only one place, and ONLY when work would actually be lost.

WHY THIS AND NOT A DENY RULE
2026-08-19: 62 commits stranded on 8 branches. That loss was a git command, not a disk fault.
But denying `git worktree remove` outright is what left an orchestrator lane stuck in five
consecutive permission blocks on a worktree that was provably empty (0 uncommitted, 0 commits
off main). A guard that blocks safe work trains people to route around it. So this checks the
REPOSITORY, not the command string, and gets out of the way when nothing is at risk.

THE FOUR:
  git worktree remove   -> block if that worktree is dirty or holds commits not on main
  git branch -D         -> block if the branch holds commits not merged to main
  git reset --hard      -> block if the working tree is dirty (that is what it discards)
  git clean -f          -> block if untracked, non-ignored files exist
  git push --force      -> block always; rewriting shared history is a human decision

FALSE POSITIVES ARE A REAL FAILURE MODE, NOT A NUISANCE.
An earlier sibling of this hook blocked a COMMIT MESSAGE that quoted the anti-pattern in order to describe it
(2026-08-22). A guard that blocks writing *about* the hazard teaches people to stop writing
about it. So this strips quoted strings before matching: `git commit -m "removed the worktree"`
is a commit, not a removal, and must pass.

FAILURE POLICY IS DELIBERATELY LOPSIDED. If the safety check cannot run, this BLOCKS: but only
for the five operations above. Every other git command is allowed without inspection, so a
broken check can never take git away wholesale. Losing commits is worse than one extra prompt.

Protocol: PreToolUse JSON on stdin. exit 0 = allow, exit 2 = block (stderr goes to Claude).
"""
import json, os, re, subprocess, sys


def sh(args, cwd=None):
    """Run a command, return (rc, stdout). Never raises."""
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=20)
        return p.returncode, (p.stdout or "").strip()
    except Exception as e:
        return 99, "guard-git: could not run %s: %s" % (" ".join(args), e)


def strip_quoted(cmd):
    """Remove single- and double-quoted spans so a quoted MENTION never matches.
    This is the false-positive class described above, fixed at the source."""
    out = re.sub(r'"(?:[^"\\]|\\.)*"', ' "" ', cmd)
    out = re.sub(r"'(?:[^'\\]|\\.)*'", " '' ", out)
    return out


def block(msg):
    sys.stderr.write("guard-git: BLOCKED\n" + msg + "\n")
    sys.exit(2)


def main():
    try:
        ev = json.load(sys.stdin)
    except Exception:
        sys.exit(0)                                  # not our event shape; stay out of the way
    if ev.get("tool_name") != "Bash":
        sys.exit(0)
    raw = (ev.get("tool_input") or {}).get("command", "") or ""
    cmd = strip_quoted(raw)
    if not re.search(r"(^|[;&|]\s*)\s*(sudo\s+)?git\b", cmd):
        sys.exit(0)                                  # no git INVOCATION (a quoted mention is gone)

    # Work out which repo this is about: an explicit `cd <path> &&`, else -C, else cwd.
    cwd = os.getcwd()
    m = re.search(r"(?:^|[;&|])\s*cd\s+(\S+)", cmd)
    if m:
        cwd = os.path.expanduser(m.group(1))
    m = re.search(r"git\s+-C\s+(\S+)", cmd)
    if m:
        cwd = os.path.expanduser(m.group(1))

    # ---- git push --force : always a human call -------------------------------------------
    # Adversarially re-tested 2026-09-07. Two holes, both found in one pass:
    #   `git -C <dir> push --force`  -- every OTHER rule below carries the (?:-C \S+ )? clause and
    #                                   this one did not, so the guard could be stepped around by
    #                                   naming the repository instead of standing in it.
    #   `git push origin +main`      -- the leading-plus refspec is a force push with no --force on
    #                                   the line at all, which is the form that does not look like one.
    if re.search(r"git\s+(?:-C\s+\S+\s+)?push\b", cmd):
        forced = re.search(r"(--force(-with-lease)?\b|\s-f\b)", cmd)
        plus   = re.search(r"push\b[^;&|]*\s\+[^\s]", cmd)     # `push origin +main`, `push origin +HEAD:main`
        if forced or plus:
            block("`git push` with %s rewrites history others may already hold.\n"
                  "Run it yourself if you mean it. Nothing was pushed."
                  % ("--force" if forced else "a leading-plus refspec, which forces without saying so"))

    # ---- git worktree remove : the 2026-08-19 shape ---------------------------------------
    # ⚠️ CORRECTED 2026-08-24, first day in service, after it blocked a safe cleanup.
    # The first draft blocked when the branch held commits not on main. That guards a loss that
    # CANNOT happen this way: `git worktree remove` deletes the working directory and deregisters
    # it -- the BRANCH and its commits stay in the repository. Only `git branch -D` discards
    # commits, which is checked separately below. The 2026-08-19 commits were STRANDED (orphaned
    # but present), not deleted; treating "stranded" as "destroyed" made the guard block cleanup.
    #
    # What can actually be lost here is UNCOMMITTED work, and plain `worktree remove` already
    # refuses a dirty worktree on its own. So the only case worth blocking is --force + dirty.
    # --force is a flag, so it can sit on EITHER side of the path. The first draft only looked in
    # front of it, so `worktree remove <path> --force` read as unforced and skipped the dirty check
    # entirely. Found 2026-09-07.
    m = re.search(r"git\s+(?:-C\s+\S+\s+)?worktree\s+remove\s+(.+)", cmd)
    if m:
        rest = m.group(1).split()
        forced = any(a in ("--force", "-f") for a in rest)
        paths = [a for a in rest if not a.startswith("-")]
        if not paths:
            sys.exit(0)
        wt = os.path.expanduser(paths[0])
        if not os.path.isabs(wt):
            wt = os.path.join(cwd, wt)
        if not os.path.isdir(wt):
            sys.exit(0)      # stale registration, directory already gone -- nothing to lose
        if not forced:
            sys.exit(0)      # git itself refuses a dirty worktree without --force
        rc, dirty = sh(["git", "status", "--porcelain"], cwd=wt)
        if rc != 0:
            block("cannot inspect worktree %s while --force is set -- refusing while blind.\n%s"
                  % (wt, dirty))
        rows = [x for x in dirty.splitlines() if x.strip()]
        if rows:
            block("--force would discard %d uncommitted path(s) in %s:\n  %s\n"
                  "Committed work on the branch survives a worktree removal; this does not.\n"
                  "Commit or stash first, or drop --force and let git refuse on its own."
                  % (len(rows), wt, "\n  ".join(rows[:10])))
        sys.exit(0)

    # ---- git branch -D : same stranding risk ----------------------------------------------
    # `git branch -D a b c` deletes all three. The first draft captured only the first name, so a
    # merged branch in front of an unmerged one bought the whole line a pass. Found 2026-09-07.
    m = re.search(r"git\s+(?:-C\s+\S+\s+)?branch\s+(?:-D|--delete\s+--force)\s+(.+)", cmd)
    if m:
        names = [b for b in m.group(1).split() if not b.startswith("-")]
        for br in names:
            rc, ahead = sh(["git", "log", "--oneline", "main..%s" % br], cwd=cwd)
            if rc != 0:
                block("cannot compare %s against main -- refusing while blind." % br)
            n = len([x for x in ahead.splitlines() if x.strip()])
            if n:
                block("branch %s holds %d commit(s) not on main. -D discards them.\n"
                      "Merge or push first, or use -d which refuses unmerged branches itself." % (br, n))
        sys.exit(0)

    # ---- git reset --hard / git clean -f : discard uncommitted work ------------------------
    # `git checkout -- <path>` and `git restore <path>` discard uncommitted TRACKED changes exactly
    # as `reset --hard` does. They were outside the guarded set until 2026-09-07, which meant the
    # hook blocked one spelling of the loss and waved through two others.
    hard = (re.search(r"git\s+(?:-C\s+\S+\s+)?reset\b.*--hard", cmd)
            or re.search(r"git\s+(?:-C\s+\S+\s+)?checkout\s+.*--\s", cmd)
            or re.search(r"git\s+(?:-C\s+\S+\s+)?restore\b(?!.*--staged)", cmd))
    clean = re.search(r"git\s+(?:-C\s+\S+\s+)?clean\b.*(-\w*f|\s--force)", cmd)
    if hard or clean:
        rc, dirty = sh(["git", "status", "--porcelain"], cwd=cwd)
        if rc != 0:
            block("cannot read the working tree in %s -- refusing while blind." % cwd)
        rows = [x for x in dirty.splitlines() if x.strip()]
        # The two commands destroy DIFFERENT things, and conflating them makes the guard both
        # over- and under-protective. `reset --hard` reverts TRACKED changes and leaves untracked
        # files completely alone; `clean -f` deletes UNTRACKED files and leaves tracked ones alone.
        # Counting all dirty rows for reset --hard blocked on a nested worktree dir (a `??` entry)
        # that reset would never have touched -- caught by the test matrix, 2026-08-24.
        if clean:
            rows = [x for x in rows if x.startswith("??")]
        else:
            rows = [x for x in rows if not x.startswith("??")]
        if rows:
            block("%s would discard %d uncommitted path(s) in %s:\n  %s\n"
                  "Commit or stash first. Nothing was discarded."
                  % ("reset --hard" if hard else "clean -f", len(rows), cwd,
                     "\n  ".join(rows[:10])))
    sys.exit(0)


if __name__ == "__main__":
    main()
