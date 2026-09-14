# ADR 0001: Ambiguity resolves to ASK

**Status:** Accepted. Recorded 2026-09-14; the rule predates this record and has governed
`bash-approver.py` since its first version.

## Context

`bash-approver.py` sees every shell command an agent proposes and has three possible answers:

- **ALLOW** runs the command with no human involved.
- **DENY** refuses it outright.
- **ASK** hands it to the host's own permission prompt. The hook signals ASK by printing nothing,
  so the host behaves exactly as it would with no hook installed.

Most commands are neither provably safe nor provably catastrophic. `npm install left-pad` might be
fine. `git -c core.pager=/tmp/x.sh log` looks like a read and runs a program. The classifier has to
pick an answer for the whole middle of that range, and whatever it picks is wrong some of the time.
The question is which way it should be wrong.

## Decision

**A wrong ALLOW is the only unacceptable outcome. Anything not proven side-effect-free is ASK.**

1. **ALLOW only when every segment of the command is known to be read-only** and nothing it reads
   is a secret. One unknown segment makes the whole command ASK.
2. **DENY only for a short list of catastrophes**, such as erasing a disk, piping a download into a
   shell, or a recursive delete of a protected path. DENY is for things no one should approve in a
   hurry, not for things that merely look unfamiliar.
3. **Everything else is ASK.**
4. **The optional local model may promote ASK to ALLOW, and nothing else.** It works only inside a
   fixed envelope of inline-expression commands, and it cannot touch a DENY. It is off by default and
   fails closed.

## Alternatives considered

**Allow by default, deny a known-bad list.** Rejected. A denylist is incomplete by construction,
and its failures are silent. Two that happened here: splitting a command with `shlex` ate a newline,
so `ls` followed by `rm -rf ~` read as `ls`. And `git -c diff.external=X diff` ran `X`, because the
parser skipped `-c` to find the subcommand. Under allow-by-default both run with no one watching.

**Deny by default.** Rejected. A DENY has no human in the loop, so a wrong DENY cannot be corrected
inside the agent's turn. The agent routes around it or the user disables the hook, and then the hook
protects nothing. ASK keeps the same caution and leaves the correction to a person.

**Let a model decide.** Rejected as the primary mechanism. A model's false SAFE is a wrong ALLOW,
the one outcome this design exists to prevent, and one was observed: the model once judged a `curl`
command safe. The model survives only as the promote-only step in point 4.

## Consequences

**Measured across 40,837 logged production decisions:** 80.9% ASK, 19.1% ALLOW, 2 DENY.

- **The cost is prompts.** Four fifths of commands still reach a human. The 19% the classifier
  absorbs is the pure-read tail that produced most of the prompt fatigue, which is the part worth
  automating.
- **DENY stays rare enough to mean something.** One of the two production denials stopped a real
  disk erase. The other was an over-block, since fixed, and both are published in
  [`../adversarial-findings.md`](../adversarial-findings.md).
- **This rule does not prevent safe-list errors.** Nine wrong-ALLOWs were found by adversarial
  review. Each was a command the safe-list wrongly believed was read-only, which is a mistake inside
  step 1, not a failure of the rule. They are why every reported bypass becomes a permanent battery
  case, and why the README keeps a list of the classes still open.
- **A new, unknown class of dangerous command degrades to ASK, not to ALLOW.** That is the whole
  point: when the classifier does not recognise something, a person sees it.
