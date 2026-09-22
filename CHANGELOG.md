# Changelog

All notable changes to this project. Dates are the day the change was published.

## [Unreleased]

### Changed

- **The classifier is a package, not a single file.** `hooks/bash-approver.py` keeps its name, its
  path and its command-line surface, and now holds no rules at all: it reads the host's JSON, calls
  `decide()`, and writes the host's JSON back. The logic moved to `src/bash_approver/`, split by the
  question each part answers: `segmentation` (quote-aware splitting and redirect classification),
  `command_model` (peeling env/wrapper/sudo prefixes to the program that actually runs),
  `destructive` (catastrophe detection, the only module that returns DENY), `policy` (the
  allow/ask/deny rules and the model-promotion envelope), `model_promoter` (the optional local
  model, and the only network I/O in the classifier), `decision_log` (JSONL telemetry).
  **No decision changed.** All 125 distinct commands in the battery, `docs/demo/demo.py` and
  `tests/adversarial/` return the same verdict AND the same reason string, compared byte for byte
  before and after. The reason string is part of the comparison because it is what a human reads
  when a hook stops them.
- **The 108 battery cases left the production file.** They are data, and they now live in
  `tests/fixtures/bash_approver_cases.json`, carrying the group label each one had as a comment.
  `hooks/bash-approver.py --selftest` and `./tests/run-all.sh` are unchanged as entry points, and
  the summary line they print is unchanged, because CI and the README quote it. Four cases target
  the user's home directory and store it as the token `{HOME}`, expanded at load time, so no
  username is written into the repository.
- **Quick start is now `cp -R hooks/* src/bash_approver ~/.claude/hooks/`.** An entry point that
  imports a package cannot survive a flat copy of `hooks/` alone. The hook looks for the package
  beside itself first and in `../src` second, so the flat install and a plain checkout both work
  with no `PYTHONPATH` and no install step. Verified by installing into a throwaway `HOME` and
  piping a real PreToolUse payload through the installed hook for an allow, a deny and an ask.
- `tests/run-all.sh` syntax-checks the package as well as the hooks, and clears every
  `__pycache__` rather than only `hooks/`. A `.pyc` embeds the absolute source path, which is a
  username, and the leak sweep at the end of that script reads binaries.

### Added

- `docs/adr/0001-ambiguity-resolves-to-ask.md`: the decision record for the classifier's core rule.
- `docs/demo/`: a replay of seven real hook decisions (`demo.py`, `render_svg.py`, `demo.svg`), shown in
  the README. The suite fails if the image stops matching what the hooks decide.

## [1.0.0] - 2026-09-14

First tagged release. What it contains:

### Hooks

- **`bash-approver.py`**: auto-approves side-effect-free shell commands, denies catastrophic ones, asks
  about everything else. Quote-aware segmentation, redirect analysis, wrapper and env-prefix stripping,
  optional local-model promotion that is off by default and fails closed.
- **`guard-find.sh`**: refuses `find` carrying `-delete`, `-exec` and the other acting flags.
- **`guard-git.py`**: refuses five git operations that discard work, only when work would be lost.
- **`guard-sequenced-precondition.py`**: refuses a precondition check whose exit status a `;`, newline
  or pipe would destroy.
- **`guard-agent-model.py`**: refuses a subagent spawn with no explicit model.
- **`orphan-tooling-guard.py`** (Stop): sends the turn back when session executables exist only in `/tmp`.

### Tests

- 108-case adversarial battery for `bash-approver.py`, zero wrong-allow.
- 13-case matrices for `guard-git.py` (real temporary repositories) and `guard-find.sh`.
- `tests/adversarial/`: every bypass an adversarial review reported, pinned so it cannot return.
- CI on every push and pull request, with a read-only token and a SHA-pinned checkout action.

### Fixed before this release

- Nine wrong-ALLOWs in the classifier, three of which ran arbitrary code through `git -c`.
- Eleven reported bypasses across `guard-find.sh` and `guard-git.py`.
- The `dd` rule treated `/dev/null` and other sinks as disks.
- `settings.example.json` wired the Stop hook under PreToolUse.

### Known limitations

Published in the README and unchanged by this release.

[1.0.0]: https://github.com/andreybuilt/agent-guardrails/releases/tag/v1.0.0
