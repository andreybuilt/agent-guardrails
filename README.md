# agent-guardrails

Six PreToolUse hooks that refuse unsafe actions **at the call site**, before a coding agent
executes them. Each one returns exit 2 and stops the call.

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

`guard-find.sh` needs `jq`. The Python hooks need only the standard library.

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
