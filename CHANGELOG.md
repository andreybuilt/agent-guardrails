# Changelog

All notable changes to this project. Dates are the day the change was published.

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
