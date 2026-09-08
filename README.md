# agent-guardrails

[![tests](https://github.com/andreybuilt/agent-guardrails/actions/workflows/tests.yml/badge.svg)](https://github.com/andreybuilt/agent-guardrails/actions/workflows/tests.yml)

Six hooks that refuse unsafe agent actions instead of warning about them afterwards. Five run as
`PreToolUse` and stop the command **before it executes**; one runs as `Stop` and sends the turn back.
They refuse in three different ways, which turns out to matter more than it sounds like it should.

**These six are the ones that generalize.** Others run on the fleet this came from and stay there:
two are bound to my own paths and hosts, one to a single internal API's schema, and `one-step-guard.py`
is the subject of the last section. A sixth published here, `guard-sequenced-precondition.py`, runs on
no machine at all: it is the generalized form of a hook that guarded one specific distributed lock,
rewritten around a configurable pattern. Its error text still says `guard-lease`, which is where it
came from.

🛑 **I am not publishing a total, and the reason is the most useful thing in this section.** Four
counts were made of that fleet in one day and produced four answers: twelve, ten, nine, eight. Nobody
lied and nobody miscounted. Each used a different definition of "enforcement hook", and the
definitions are all defensible:

- **Registered, or enforcing?** One hook is wired as `PreToolUse` and its own docstring says it never
  blocks and always exits 0. It belongs in a list of what is wired and not in a list of what refuses.
- 🛑 **How does a hook refuse?** There are **three** mechanisms, and the six hooks here happen to use
  all three, so this claim is checkable in this repository rather than against a fleet you cannot see:

  | Mechanism | Used by |
  |---|---|
  | `exit 2` | `guard-agent-model.py`, `guard-find.sh`, `guard-git.py`, `guard-sequenced-precondition.py` |
  | exit 0 + `{"decision":"block"}` | `orphan-tooling-guard.py` |
  | exit 0 + `hookSpecificOutput.permissionDecision: "deny"` | `bash-approver.py` |

  `bash-approver.py` contains **zero** `exit 2` and **zero** `decision: block`. It is the busiest
  guard in the set, and a matcher built for the other two mechanisms drops it in silence. Mine did.
  A later matcher caught all three, but only because it also matched the bare words `deny` and
  `blocked`: that is luck, not method. A looser matcher is an untested one that happened to win, and
  it fails the same silent way against a hook that refuses in some fourth manner.
- **Live directories, or tracked copies?** Four seats, and a hook can exist on one and not the others.
- **Is it a hook at all?** My own matcher counted a cron script that happens to `exit 2`.

A number that moves when you change the matcher is a fact about the matcher, not about the fleet.

The sharpest version of this came from the two people who counted most carefully. **Same fleet, same
day, different totals, and two entirely different bugs.** One matcher had the right coverage and the
wrong mechanism; the other had the right mechanism and missed a directory. Neither looked wrong from
the inside, because a grep that returns a clean list gives you no way to tell a hook it never
considered from a hook that is not there.

This is the same failure the hooks themselves are built around: the check and the claim being about
different things. It showed up in the accounting of the hooks before it showed up in the hooks.

Every hook here runs in production against a real agent workload. The numbers below come from its
own logs, not from a benchmark built to make the point.

---

## Why these exist

An agent asked not to do something will usually not do it. "Usually" is the problem.

The failures worth guarding against come from a model trying to be careful, where the shape of the
command defeats the check:

- A safety classifier reads `find . -name '*.py'` and allows it, so it also allows
  `find . -name '*.py' -delete`.
- A caller writes `precondition-check ... ; do-the-work`. The check refuses, prints, returns 1.
  The `;` runs the work anyway.
- A classifier splits on shell whitespace with `shlex`, which eats newlines, so
  `ls\nrm -rf ~` collapses to base command `ls` and gets allowed.

All three happened here. All three are now test cases.

---

## The security model

**A wrong ALLOW is the only unacceptable outcome.** A wrong ASK is friction; a wrong DENY is
friction with a stronger opinion. Ambiguity resolves to ASK.

The production numbers show that asymmetry. Across **40,837 logged decisions**:

| Decision | Count | Share |
|---|---:|---:|
| ask (fell through to the human) | 33,034 | 80.9% |
| allow (auto-approved read-only) | 7,801 | 19.1% |
| deny (blocked outright) | 2 | 0.005% |

Four fifths of traffic goes to a human, by design. The 19% the classifier absorbs is the pure-read
tail that generated most of the prompt fatigue.

### Both denials, in full

The classifier has denied two commands. Both are below, because a clean number would tell you less.

**1. A real catastrophe, caught.**
```
diskutil eraseDisk FAT32 BLANK MBRFormat /dev/disk8 && echo "---VERIFY---" && diskutil list /dev/disk8
```
Reason given: `diskutil (format/erase filesystem)`. This would have erased a disk.

**2. An over-block, and it teaches more than the catch.**
```
dd if=/dev/rdisk8 of=/dev/null bs=1m count=16
```
Reason given: `dd writing to a raw device`. The command *reads* from a raw device into
`/dev/null`, which is harmless. My rule matched `dd` beside a raw device path without checking
which side of the operation the device sat on.

That limitation is still unfixed here. It also shows the design working: when the classifier gets
it wrong, the cost is a retry rather than a disk. Expect a guard tightened this far to over-block
sometimes.

---

## The hooks

| Hook | Blocks | Lines |
|---|---|---:|
| `bash-approver.py` | Auto-approves side-effect-free commands, denies catastrophic ones, asks about everything else. Quote-aware segmenter, redirect analysis, wrapper/env-prefix stripping, `git -C` handling. | 793 |
| `guard-find.sh` | Any `find` carrying `-delete`, `-exec`, `-execdir`, `-ok`, `-okdir`, `-fprint`, `-fprintf`, `-fls`. | 30 |
| `guard-sequenced-precondition.py` | A precondition check followed by `;` or a newline, or piped into anything. Both shapes destroy its exit status. | 158 |
| `guard-agent-model.py` | A subagent spawn with no explicit `model`, which silently inherits the parent's (usually the most expensive one available). | 66 |
| `guard-git.py` | Five git operations that discard work, **and only when work would actually be lost**: `push --force` always; `reset --hard` with tracked changes; `clean -f` with untracked files; `branch -D` holding unmerged commits; `worktree remove --force` on a dirty tree. | 153 |
| `orphan-tooling-guard.py` | Session-scoped executables written to `/tmp` that exist nowhere in the work tree. Matches on **content hash, not filename**, so a rescue that renames the file still counts. | 303 |

### Why a hook rather than a permission rule

Most agent permission systems match on command **prefix**. A prefix rule cannot express
"`find`, but only when it carries `-delete`"; it can only allow all `find` or block all `find`.
A PreToolUse hook sees the real command string, so it can block one shape and leave the other
alone.

---

## Install

Copy the hooks somewhere stable and register them in your agent's settings. A working example is
in [`settings.example.json`](settings.example.json).

```bash
git clone https://github.com/andreybuilt/agent-guardrails
cp agent-guardrails/hooks/* ~/.claude/hooks/
chmod +x ~/.claude/hooks/*
```

`guard-find.sh` needs `jq` and `python3`. Every Python hook needs only the standard library.

### Configuration

| Variable | Used by | Meaning |
|---|---|---|
| `BASH_APPROVER_LOG` | `bash-approver.py` | Append decisions as JSONL, for tuning. |
| `BASH_APPROVER_MODEL` | `bash-approver.py` | `ollama:MODEL@HOST:PORT`. Lets a local model promote gray commands to allow. **Off by default, fails closed.** |
| `GUARD_PRECONDITION_RE` | `guard-sequenced-precondition.py` | Python regex matching your own precondition command. Defaults to a distributed-lock acquire. |
| `AGENT_GUARDRAILS_TREE` | `orphan-tooling-guard.py` | Path to the work tree that counts as "durable". |
| `GUARD_LEAK_RE` | `tests/run-all.sh` | Extra identifiers the pre-publish sweep must refuse. Defaults to your own username and home path. |

---

## Tests

```bash
./tests/run-all.sh
```

`guard-git.py` carries a **13-case matrix** in `tests/test-guard-git.sh` that builds real
temporary repositories and drives the hook through both halves of every rule: six commands it
must refuse, and seven wrongly-satisfied twins it must allow. Three of those seven are false
positives the hook shipped with and had fixed within a day.

`bash-approver.py --selftest` runs an **85-case adversarial battery** and exits non-zero on any
wrong-allow. Each case entered the battery after a bypass got through, so they are regression
tests rather than illustrations. The battery covers newline-separated segments, `&&`/`||`/`;`/`|`
sequencing, redirect targets, `env`/`sudo`/`nice` wrapper prefixes, `$()` and heredocs, and quoted
strings that only look dangerous (`echo 'rm -rf /'` has to stay allowed).

---

## Known bypasses, stated because they are still open

Re-tested 2026-09-07 against shapes an internal audit had recorded. Some were already fixed, one
I fixed that day, and these are the ones that still work. A guard set with no published bypass
list has either not been attacked or is not telling you.

| Hook | Shape that gets through | Why |
|---|---|---|
| `guard-sequenced-precondition.py` | `sh -c '...'`, `bash -c '...'`, `ssh host '...'`, a single `&`, `check \|\| true ; work` | Only the first operator at the top level is examined. A wrapper hides the sequence inside an argument. 7 of 8 audited shapes still work. |
| `bash-approver.py` | `git log --output=FILE`, `git diff --output=FILE`, `file -C -m FILE` | Read-only-looking subcommands that write through a flag the redirect analysis does not model. `sort -o` was the same class and is fixed. |
| `bash-approver.py` | `echo $SECRET` | It models side effects, not disclosure. The source says so; it is a design boundary rather than an oversight, and it is the gap I would close next. |
| `orphan-tooling-guard.py` | `.pl`, `.rb`, extensionless executables | It hashes `.sh` and `.py` only, so tooling in another language is invisible to it. |
| `guard-agent-model.py` | `model="inherit"`, `model="banana"` | It requires a non-empty model and does not validate the value. `inherit` reaches the outcome the hook exists to discourage while satisfying the letter of it. Arguable as a design choice; listed so you can decide for yourself. |

**Fixed on 2026-09-07, and worth the detail because both halves were wrong at once.**
`guard-find.sh` allowed `find . -name '*.py' '-delete'`: the flag match required whitespace in front of
the flag, and a quote is not whitespace. The same hook blocked a report that merely quoted the
flag in order to describe it. Stripping quotes fixes the first and worsens the second, so it now
drops quoted spans containing whitespace (sentences), unquotes those that do not (arguments), and
searches only what follows a `find` in command position. Thirteen cases, six of them cases it must
allow.

---

## What this repository leaves out

- **A hook that logs instead of blocking.** I measured one guard from the original set, found it
  net-negative, and emptied its blocking set. The code stays out of this repository, because a
  disarmed guard still looks like protection. [`docs/war-stories.md`](docs/war-stories.md) tells
  that story.
- **Anything tied to a specific fleet.** I stripped hostnames, IP tables, and internal tool names.
  Where a hook needs one, it reads an environment variable.

---

## License

MIT. See [LICENSE](LICENSE).
