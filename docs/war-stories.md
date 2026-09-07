# War stories

Each hook in this repository exists because something got past an earlier version of it. The
incidents are recorded here in the form that matters — what the command looked like, why the check
said yes, and what the fix was. Identifiers have been removed; the mechanics have not.

---

## 1. `shlex` ate the newline, and `rm -rf ~` became `ls`

**The command.**
```
ls
rm -rf ~
```

**Why it was allowed.** The first version of the approver tokenized the whole command with
`shlex.split()` to find the base command. `shlex` treats a newline as ordinary whitespace, so the
token list began `['ls', 'rm', '-rf', '~']` and the base command read as `ls` — a member of the
always-safe set. The dangerous half was invisible.

**The fix.** A quote-aware segmenter that splits on `\n ; && || | &` at the top level, and
classifies **every** segment independently. A command is allowed only if all of its segments are
allowed. Catastrophe checks run per segment.

**Now a test case.** Four of them, all `deny`.

---

## 2. The refused check that ran the work anyway

**The command.**
```
lock-acquire <target> ... ; rsync -a ./src remote:/dest
```

**Why nothing stopped it.** The convention was documented as
`lock-acquire ... || exit 1` — a caller-side guard. Written with `;` instead of `||`, the acquire
refused (another worker held the lock), printed its refusal, returned exit 1 — and the `;` ran the
sync regardless. It wrote to a host another worker was already writing to.

The check was correct. The check ran. The check was wired to nothing.

**A second route to the same failure.**
```
lock-acquire <target> ... | tail -2
```
Here `$?` is `tail`'s status, so a refusal reads as success.

**The fix.** `guard-sequenced-precondition.py` blocks both shapes and allows `|| exit 1`,
`&& work`, and the bare call. The general lesson: **a convention enforced by the caller is not
enforcement.** If defeating your guard is one character of punctuation, it is documentation.

---

## 3. The guard that was measured and disarmed

One hook in the original set watched an agent's output for six behavioural patterns and blocked the
response when it matched.

Over time its blocking set was emptied — `BLOCKING = set()` — leaving all six detectors running in
advisory mode, logging and stopping nothing. That was not neglect. It was the honest outcome of
measuring how often it fired correctly and finding the answer was: not often enough to justify
blocking a response the human had asked for.

It is not shipped here, for the reason stated in the README: **a disarmed guard is worse than no
guard, because it looks like protection.** Anyone auditing a hook set should check whether the
blocking path is actually reachable before crediting it.

The general lesson is the uncomfortable one. Writing an enforcement mechanism is easy. Measuring
whether it earns its false positives is the part most guard sets never do, and the result is a
directory full of hooks that everyone assumes are working.

---

## 4. The orphan detector that matched on filenames

**The problem.** Agents write throwaway scripts to `/tmp` and forget them. A measurement found
**74** `.sh`/`.py` files in `/tmp`, of which only **9** existed anywhere in the work tree — 65
pieces of tooling that would vanish on the next reboot, several of them non-trivial.

**Why the first detector missed things.** It compared filenames. A script rescued into the tree
under a better name still looked like an orphan, and a `/tmp` file renamed by its author looked
like a new one.

**The fix.** Hash the content. `orphan-tooling-guard.py` builds a set of content hashes for every
`.sh`/`.py` in the work tree and flags a `/tmp` executable only when its hash appears nowhere.
Renames on either side stop mattering.

**Three named bugs are recorded in the hook's own header**, with the exact inputs that triggered
them. That header is worth reading before the code.

---

## 5. The subagent parameter that cost real money

**The problem.** A spawn call that omits `model` inherits the parent's — in practice the most
capable and most expensive model available. Nobody chooses that; it is what happens when the field
is left blank.

**The measurement.** Over one working day on a single seat, hundreds of spawns. Of those that named
no model, a large majority ran on the top-tier model. Reviewed afterward, essentially none of them
needed it: they were mechanical fan-out — file sweeps, greps, inventories.

**The fix.** `guard-agent-model.py` refuses any spawn with no `model` and tells the caller how to
size it. It is a two-line rule that exists only because **a default is not a decision.**

---

## The pattern across all five

Four of the five failures above are not the agent being unsafe. They are a *correct check wired to
the wrong thing*: parsed with the wrong tokenizer, sequenced with the wrong operator, matched on
the wrong attribute, or defaulted instead of chosen.

Which is why every hook here is judged on one question, and it is not "does it catch bad commands."
It is: **what is the exact input that gets past it, and is that input in the test file?**
