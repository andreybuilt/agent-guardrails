# Adversarial findings

What two adversarial reviews found in these hooks, what production denied, and what was wrong
about my own description of it. Moved here from the README on 2026-09-12, unedited. The bypasses
that are still **open** stay in the README, because that is the list you need before installing.

---

## The production denials

The classifier has denied two commands. Both are below, because a clean number would tell you less.

**1. A real catastrophe, caught.**
```
diskutil eraseDisk FAT32 BLANK MBRFormat /dev/disk8 && echo "---VERIFY---" && diskutil list /dev/disk8
```
Reason given: `diskutil (format/erase filesystem)`. This would have erased a disk.

**2. An over-block, and my explanation of it was wrong about my own code.**
```
dd if=/dev/rdisk8 of=/dev/null bs=1m count=16
```
Reason given: `dd writing to a raw device`. The command reads a raw device into `/dev/null`, which
destroys nothing.

For most of a day this README said the rule "matched `dd` beside a raw device path without checking
which side of the operation the device sat on." **That was false, and an adversarial reviewer caught
it by reading the code I had described.** The rule is `of=/dev/`. It always checked the side; reading
a raw device was never the trigger. What it did not do was tell a device from a sink, so every
`/dev/` write target was treated as a disk, including the one that is a hole in the ground.

Fixed 2026-09-07: `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/tty` and `/dev/zero` are sinks and
no longer trip it, while `dd if=/dev/zero of=/dev/rdisk8` still denies. Both directions are cases 
in the battery.

I have left this section in rather than quietly deleting it, because the interesting part is no
longer the over-block. It is that a guard's author can describe his own rule incorrectly for hours
while the code sits three lines away, and that the error survived every check I ran on it. Nobody
verifies a sentence about a mechanism the way they verify the mechanism.

---

## What a second pass closed, and the one that should not have been possible

A separate reviewer attacked the classifier itself and found **nine wrong-ALLOWs**, which is the
outcome this repository calls the only unacceptable one. Three of them ran arbitrary code:

    git -c diff.external=/tmp/x.sh diff        git -c core.fsmonitor=/tmp/x.sh status
    git -c core.pager=/tmp/x.sh log

`git diff` is read-only. `git -c diff.external=X diff` runs `X`. The subcommand parser skipped `-c`
and its value **in order to find the subcommand**, which is exactly what made the dangerous option
invisible to the check that followed. The others: `sort --output=` (the short form was caught and
the long form starts with `--`, not `-o`), `git remote set-url`, `git branch -D`, `git reflog
expire`, `env -0`, and `shutdown -h`, which read as a request for help because `-h` is in the
help-flag set.

All nine are closed and all nine are now battery cases, which is why the count is 108 rather than
85. The lesson is the one this whole file keeps circling: a safe-list answers a question about the
subcommand, and the danger was in an option nobody asked it about.

## What the first pass closed, because the failures are the useful part

`guard-git.py` had published **no** bypass list, and it had four holes plus one I found writing the
control case for the others:

- **`git -C <dir> push --force` was allowed.** Every other rule in that file carries a `-C` clause
  and the force rule did not, so the guard could be stepped around by naming the repository instead
  of standing in it. I found this because a control case I expected to block did not.
- `git push origin +main` was allowed: a leading-plus refspec forces without the word `force`
  appearing on the line.
- `git branch -D merged unmerged` was allowed: only the first branch name was checked.
- `git worktree remove <path> --force` was allowed: `--force` was only recognized in front of the
  path, so the flag after it read as unforced and skipped the dirty check.
- `git checkout -- .` and `git restore <path>` discard tracked changes exactly as `reset --hard`
  does, and were outside the guarded set entirely.

`guard-find.sh` was walked past by `command`, `exec`, `time`, `busybox` and `\find`, because its
command-position list was `sudo|env|nice` and nothing else. The best of the six was a
**backslash-newline continuation**: `find` sits in command position, the destructive flag lands on
the next physical line, and the matcher is line-oriented while the shell is not.

**Fixed on 2026-09-07, and worth the detail because both halves were wrong at once.**
`guard-find.sh` allowed `find . -name '*.py' '-delete'`: the flag match required whitespace in front of
the flag, and a quote is not whitespace. The same hook blocked a report that merely quoted the
flag in order to describe it. Stripping quotes fixes the first and worsens the second, so it now
drops quoted spans containing whitespace (sentences), unquotes those that do not (arguments), and
searches only what follows a `find` in command position. Thirteen cases, six of them cases it must
allow.
