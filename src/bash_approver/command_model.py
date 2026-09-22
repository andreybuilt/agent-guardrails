"""What is actually about to run, once the front of the segment is peeled off.

`env FOO=1 sudo nice rm -rf ~` is an `rm`. Every check above this layer wants the `rm`,
not the `env`. v1 looked at the first token and denied nothing, which is how
`env FOO=1 rm -rf ~` reached a mere ASK.

Peeling is not neutral, and that is the interesting part of this module:

  * An env-assignment is NOT inert. `PATH=` changes which binary runs. GIT_EXTERNAL_DIFF,
    PAGER and LESSOPEN each name a program the tool will execute. So the stripper
    classifies the NAME being assigned, and an unsafe name forces the ask path exactly
    as sudo does.
  * A denylist of unsafe names is incomplete by construction. It is chosen anyway, and
    the measurement is in the code: a name ALLOWLIST costs all 661 historical allows that
    carry an assignment, this costs zero of them.
  * git's global options have to be skipped to FIND the subcommand, which is precisely
    what made `-c diff.external=...` invisible to the safe-list. Finding the subcommand
    and judging the options are therefore two separate jobs, and policy does the second.
"""
from __future__ import annotations

import os
import re

# env-assignment / wrapper prefixes to strip to reach the real command.
WRAPPERS = {"command", "builtin", "nice", "nohup", "stdbuf", "time", "env",
            "ionice", "setsid", "timeout"}
# git global options that take a following value (skip both to find the subcommand).
GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}

# Env-prefix fix (c). A denylist is incomplete by construction and is chosen anyway: a name
# ALLOWLIST costs all 661 historical allows carrying an assignment, this costs ZERO
# of them (every observed name was a short path var: R, F, M, d, D, S, SP, ROOT...).
ENV_UNSAFE_EXACT = {"PATH", "IFS", "ENV", "BASH_ENV", "SHELL", "SHELLOPTS",
                    "LESSOPEN", "LESSCLOSE", "RUBYOPT", "PYTHONSTARTUP", "PYTHONPATH"}
ENV_UNSAFE_PREFIX = ("LD_", "DYLD_", "GIT_", "PERL5", "NODE_", "PYTHON")
ENV_UNSAFE_SUBSTR = ("PAGER", "PROXY")


def env_name_unsafe(name: str) -> bool:
    u = (name or "").upper()
    return (u in ENV_UNSAFE_EXACT or u.startswith(ENV_UNSAFE_PREFIX)
            or any(x in u for x in ENV_UNSAFE_SUBSTR))


def base_name(tok: str) -> str:
    """The program name a token resolves to. `\\find` and `/usr/bin/find` are both find."""
    return os.path.basename(tok.lstrip("\\"))


def strip_prefixes(argv):
    """Drop leading env-assignments, WRAPPERS, and a leading sudo (+its options).
    Returns (real_argv, had_sudo)."""
    i = 0
    had_sudo = False
    while i < len(argv):
        tok = argv[i]
        _m_env = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=.*", tok)   # FOO=bar
        if _m_env:
            # Env-prefix fix (c): an env assignment is NOT inert. PATH= changes which binary runs;
            # GIT_EXTERNAL_DIFF / PAGER / LESSOPEN execute a command of the caller's
            # choosing. Proven: GIT_EXTERNAL_DIFF=x git diff ran the script on a pipe.
            if env_name_unsafe(_m_env.group(1)):
                return argv, True          # force the ask path, as sudo does
            i += 1; continue
        base = base_name(tok)
        if base == "sudo":
            had_sudo = True
            i += 1
            # skip sudo options; -u/-g/-C/-p/-h/-D/-R/-r/-t/-U take a value
            while i < len(argv) and argv[i].startswith("-"):
                takes_val = argv[i] in ("-u", "-g", "-C", "-p", "-h", "-D", "-R",
                                        "-r", "-t", "-U", "--user", "--group")
                i += 1
                if takes_val and i < len(argv):
                    i += 1
            continue
        if base in WRAPPERS:
            i += 1
            # `timeout N cmd` / `nice -n N cmd` numeric/flag args are skipped naturally
            # because the next real base is what we return; simple: skip a leading number
            while i < len(argv) and re.fullmatch(r"-?\d+[a-z]?", argv[i]):
                i += 1
            continue
        return argv[i:], had_sudo
    return [], had_sudo


def git_subcommand(args):
    """Find git's subcommand, skipping global options (and their values).

    Skipping `-c k=v` here is correct for THIS question and is exactly what hid the
    config-injection shape from the safe-list. policy.unsafe_shape looks at the options
    this function is deliberately blind to, and it runs first.
    """
    i = 0
    while i < len(args):
        a = args[i]
        if a in GIT_VALUE_OPTS:
            i += 2; continue
        if a.startswith("--") and "=" in a:      # --git-dir=... etc.
            i += 1; continue
        if a.startswith("-"):
            i += 1; continue
        return a
    return None


class NormalizedCommand:
    """One segment, resolved to the program that will actually run.

    Attributes:
        argv      tokens as written, before any peeling
        real      tokens after env-assignments / wrappers / sudo are stripped
        had_sudo  True for a leading sudo, and ALSO for an unsafe env-assignment name,
                  because both mean the same thing here: do not auto-allow this
        base      the program name, basename-resolved and unescaped
        args      real[1:]
    """

    __slots__ = ("argv", "real", "had_sudo", "base", "args")

    def __init__(self, argv):
        self.argv = argv or []
        self.real, self.had_sudo = strip_prefixes(self.argv)
        self.base = base_name(self.real[0]) if self.real else None
        self.args = self.real[1:] if self.real else []

    @property
    def bare_wrapper(self) -> bool:
        """Nothing left after peeling: pure env-assignments, or a wrapper with no command."""
        return not self.real

    def __repr__(self):
        return "NormalizedCommand(base=%r, args=%r, had_sudo=%r)" % (
            self.base, self.args, self.had_sudo)
