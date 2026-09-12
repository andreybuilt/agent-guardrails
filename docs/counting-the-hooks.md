# Counting the hooks

Why this repository publishes six hooks and no fleet total, and why the total is the less useful
number. Moved here from the README on 2026-09-12, unedited except for two cross-references, so the README can lead with what the
hooks do and how that is proved.

---

Six hooks that refuse unsafe agent actions instead of warning about them afterwards. Five run as
`PreToolUse` and stop the command **before it executes**; one runs as `Stop` and sends the turn back.
They refuse in three different ways, which turns out to matter more than it sounds like it should.

**These six are the ones that generalize.** Others run on the fleet this came from and stay there,
because they encode host paths, lease targets and one internal API's schema. `one-step-guard.py` is
also held back, for the reason in the README's last section. One published here,
`guard-sequenced-precondition.py`, runs on no machine at all: it is the generalized form of a hook
that guarded one specific distributed lock,
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

**Five of the six run in production** against a real agent workload; `guard-sequenced-precondition.py`
is the generalized rewrite described above and runs nowhere, which is why no production number is
claimed for it. The figures in the README's security model come from `bash-approver.py`'s own decision log, not from a
benchmark built to make the point, and they describe that hook rather than the set.
