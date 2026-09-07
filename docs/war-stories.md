# War stories

Every hook in this repository exists because something got past an earlier version of it. Each
incident below gives the command, the reason the check said yes, and the fix. I removed the
identifiers and left the mechanics alone.

---

## 1. `shlex` ate the newline, and `rm -rf ~` became `ls`

**The command.**
```
ls
rm -rf ~
```

**Why it was allowed.** The first version of the approver tokenized the whole command with
`shlex.split()` to find the base command. `shlex` treats a newline as ordinary whitespace, so the
token list began `['ls', 'rm', '-rf', '~']` and the base command read as `ls`, a member of the
always-safe set. The dangerous half never appeared.

**The fix.** A quote-aware segmenter splits on `\n ; && || | &` at the top level and classifies
**every** segment independently. A command survives only if all of its segments do. Catastrophe
checks run per segment.

**Now a test case.** Four of them, all `deny`.

---

## 2. The refused check that ran the work anyway

**The command.**
```
lock-acquire <target> ... ; rsync -a ./src remote:/dest
```

**Why nothing stopped it.** The convention lived in a document: `lock-acquire ... || exit 1`, a
caller-side guard. Written with `;` instead of `||`, the acquire refused (another worker held the
lock), printed its refusal, and returned exit 1. The `;` ran the sync regardless, writing to a host
another worker was already writing to.

The check was correct. The check ran. The check was wired to nothing.

**A second route to the same failure.**
```
lock-acquire <target> ... | tail -2
```
Here `$?` belongs to `tail`, so a refusal reads as success.

**The fix.** `guard-sequenced-precondition.py` blocks both shapes and allows `|| exit 1`,
`&& work`, and the bare call. The lesson generalizes: if one character of punctuation defeats your
guard, you wrote documentation.

---

## 3. The guard I measured, then disarmed

One hook in the original set watched an agent's output for six behavioural patterns and blocked the
response on a match.

I emptied its blocking set over time (`BLOCKING = set()`), leaving all six detectors running in
advisory mode, logging and stopping nothing. I measured how often it fired correctly, and the
answer never justified blocking a response the human had asked for.

It stays out of this repository for the reason the README gives: a disarmed guard still looks like
protection. Before you credit any hook in a set, check that its blocking path is reachable.

The uncomfortable half of this story is the general one. Writing an enforcement mechanism is easy.
Measuring whether it earns its false positives is the part most guard sets skip, and the result is
a directory of hooks everyone assumes are working.

---

## 4. The orphan detector that matched on filenames

**The problem.** Agents write throwaway scripts to `/tmp` and forget them. One measurement found
**74** `.sh`/`.py` files in `/tmp`, of which **9** existed anywhere in the work tree. The other 65
would vanish on the next reboot, several of them non-trivial.

**Why the first detector missed things.** It compared filenames. A script rescued into the tree
under a better name still looked like an orphan, and a `/tmp` file its author renamed looked like a
new one.

**The fix.** Hash the content. `orphan-tooling-guard.py` builds a set of content hashes for every
`.sh`/`.py` in the work tree, then flags a `/tmp` executable only when its hash appears nowhere.
Renames on either side stop mattering.

The hook's own header records **three named bugs** with the exact inputs that triggered them. Read
that header before the code.

---

## 5. The subagent parameter that cost real money

**The problem.** A spawn call that omits `model` inherits the parent's, in practice the most
capable and most expensive one available. Nobody chooses that. It is what happens when the field
sits empty.

**The measurement.** Hundreds of spawns over one working day on a single seat. Among those naming
no model, a large majority ran on the top-tier model. Reviewing them afterward, almost none needed
it: they were mechanical fan-out, meaning file sweeps, greps and inventories.

**The fix.** `guard-agent-model.py` refuses any spawn with no `model` and tells the caller how to
size it. Two lines of rule, written because a default is not a decision.

---

## 6. Sixty-two commits stranded, and the guard that first blocked the cleanup

**The loss.** On 2026-08-19, 62 commits ended up stranded across 8 branches. A git command did
that, not a disk fault.

**Why a deny rule was the wrong answer.** The obvious fix refuses `git worktree remove` outright.
That version left an orchestrator lane stuck in five consecutive permission blocks on a worktree
that was provably empty: nothing uncommitted, nothing off main. A guard that blocks safe work
teaches people to route around it, and then it protects nothing.

**The fix.** `guard-git.py` inspects the REPOSITORY rather than the command string. It runs
`git status --porcelain`, compares the branch against main, and gets out of the way when there is
nothing to lose. `git push --force` is the one exception it blocks unconditionally, because
rewriting history other people may already hold is a decision a human should make.

**Two false positives, both caught on its first day in service, both now pinned by tests.**

The first draft blocked `worktree remove` when the branch held commits not on main. That guards a
loss which cannot happen: removing a worktree deletes the directory and deregisters it, while the
branch and its commits stay in the repository. Only `git branch -D` discards commits. Treating
"stranded" as "destroyed" made the guard block ordinary cleanup.

The second: counting every dirty row for `reset --hard` blocked on an untracked directory that
`reset --hard` would never have touched. The two commands destroy different things. `reset --hard`
reverts tracked changes and leaves untracked files alone; `clean -f` deletes untracked files and
leaves tracked ones alone. Conflating them made one guard both over- and under-protective at once.

**A sibling hook taught the third lesson.** An earlier guard blocked a COMMIT MESSAGE that quoted
the anti-pattern in order to describe it. A guard that blocks writing about a hazard teaches people
to stop writing about it, so this one strips quoted spans before matching:
`git commit -m "removed the worktree"` is a commit, not a removal.

---

## The pattern across all six

Five of these six failures show a correct check wired to the wrong thing: parsed with the wrong
tokenizer, sequenced with the wrong operator, matched on the wrong attribute, defaulted instead of
chosen. The agent behaved reasonably in each one.

So I judge every hook here by a single question. Not "does it catch bad commands", but: what is the
exact input that gets past it, and does the test file contain that input?
