"""allow / ask / deny, and the envelope that bounds what a model may promote.

Ordering is the load-bearing part of this file, so it is stated once here rather than
inferred from the code:

  1. catastrophe, per segment, BEFORE and AFTER prefix-stripping, then whole-command
  2. redirects to a real file (ask) or a raw disk (deny)
  3. per-segment classification; ALL segments must allow for the command to allow
  4. the disclosure rule, applied only to a command that would otherwise ALLOW

Inside step 3 the order matters again: unsafe_shape runs BEFORE any safe-list, because a
safe-list answers "is this subcommand read-only" while the danger lives in an OPTION the
list never looks at. `git diff` is read-only; `git -c diff.external=X diff` runs X.

Two rules here are deliberately weaker than they could be, and both are recorded as
limits rather than papered over:

  * The disclosure rule is a SUBSTRING match, not realpath(). realpath touches the
    filesystem and would let a symlink decide the verdict. It therefore does not catch
    symlink aliasing (`cat ~/mykey`).
  * The unsafe-env-name list is a denylist, and a denylist is incomplete by
    construction. See command_model for the measurement behind choosing it anyway.
"""
from __future__ import annotations

import os

from .command_model import (
    NormalizedCommand,
    base_name,
    git_subcommand,
)
from .destructive import is_catastrophic_argv, is_catastrophic_regex
from .segmentation import has_unquoted_hash, preflight, segment, tokenize

DECISION_ALLOW, DECISION_DENY, DECISION_ASK = "allow", "deny", "ask"

# ── command classes ─────────────────────────────────────────────────────────

# Pure read-only / side-effect-free regardless of args.
ALWAYS_SAFE = {
    "ls", "dir", "vdir", "pwd", "echo", "printf", "cat", "tac", "nl", "head",
    "tail", "wc", "stat", "file", "du", "df", "tree", "basename", "dirname",
    "realpath", "readlink", "grep", "egrep", "fgrep", "rg", "ripgrep", "ag",
    "cut", "sort", "uniq", "tr", "column", "comm", "rev", "fold", "fmt",
    "expand", "unexpand", "cmp", "diff", "colordiff", "whoami", "id", "hostname",
    "uname", "arch", "nproc", "date", "cal", "uptime", "w", "who", "groups",
    "which", "whereis", "type", "sw_vers", "lsb_release", "shasum", "sha1sum",
    "sha256sum", "sha512sum", "md5", "md5sum", "cksum", "xxd", "hexdump", "od",
    "jq", "yq", "true", "false", "seq", "printenv", "locale", "tty", "ping",
    "dig", "host", "nslookup", "traceroute", "bat", "glow",
    # harmless navigation / no-ops (fresh shell per Bash call → no persistent effect)
    "cd", "pushd", "popd", "dirs", "test", "[", ":",
}

# Tools where only specific subcommands are read-only.
SUBCOMMAND_SAFE = {
    "git": {
        "status", "log", "diff", "show", "branch", "remote", "ls-files",
        "ls-tree", "rev-parse", "describe", "blame", "shortlog", "reflog",
        "cat-file", "whatchanged", "name-rev", "merge-base", "for-each-ref",
        "count-objects", "fsck", "grep", "show-ref", "var", "help", "version",
        "config",  # gated below to read-only forms
    },
    "docker": {"ps", "images", "logs", "inspect", "version", "info", "port", "top"},
    "kubectl": {"get", "describe", "logs", "version", "top", "explain",
                "api-resources", "api-versions", "cluster-info"},
    "brew": {"list", "info", "search", "outdated", "deps", "--version", "config"},
    "pip": {"list", "show", "freeze", "--version"},
    "pip3": {"list", "show", "freeze", "--version"},
}

HELP_VERSION = {"--version", "-v", "-V", "-version", "version", "--help", "-h",
                "help", "--usage"}

FIND_DESTRUCTIVE = {"-delete", "-exec", "-execdir", "-ok", "-okdir",
                    "-fprint", "-fprintf", "-fls"}


# ── shapes that reach an ALLOW through a safe-list ───────────────────────────
# Adversarial review 2026-09-07. Every one of these was reported ALLOW by a pass that was
# handed the published bypass table and told to find what was not in it. Three of them
# execute arbitrary code.
#
# The common cause is that a safe-list answers "is this subcommand read-only" while the
# danger lives in an OPTION the list never looks at. The subcommand parser was skipping
# `-c` and its value precisely so it could find the subcommand, which is what made the
# option invisible.
#
# This gate runs BEFORE the safe-lists so no path can reach them without passing here.
_GIT_CONFIG_INJECT = ("-c", "--config-env")


def unsafe_shape(base, args):
    """Return a reason string when a nominally-safe invocation is not, else None."""
    # 1. git -c <key>=<value> sets config for one command. Several keys name a program that
    #    git then executes: diff.external, core.fsmonitor, core.pager, *.textconv, and more.
    #    There is no safe subset worth enumerating, so any command-line config goes to ASK.
    if base == "git" and any(a in _GIT_CONFIG_INJECT or a.startswith("--config-env=")
                             for a in args):
        return "git -c/--config-env sets config for this command, and several keys name a program git will execute"

    # 2. git subcommands that read AND write. They were on the safe list whole.
    if base == "git":
        sub = git_subcommand(args)
        rest = [a for a in args if a != sub]
        if sub == "remote" and any(a in ("add", "remove", "rm", "set-url", "rename", "prune",
                                         "set-head", "set-branches") for a in rest):
            return "git remote %s mutates repository config" % next(
                a for a in rest if a in ("add", "remove", "rm", "set-url", "rename", "prune",
                                         "set-head", "set-branches"))
        if sub == "branch" and any(a.startswith("-") and any(f in a for f in ("D", "d", "m", "M", "f"))
                                   and a != "--list" for a in rest):
            return "git branch with a delete/move/force flag rewrites refs"
        if sub == "reflog" and any(a in ("expire", "delete") for a in rest):
            return "git reflog expire/delete destroys the recovery log"

    # 3. sort's long-form output flag. The short form was already caught; `--output=` does not
    #    start with "-o", which is what the original check tested.
    if base == "sort" and any(a == "--output" or a.startswith("--output=") for a in args):
        return "sort --output writes a file"

    # 4. env/printenv dumping the whole environment. `-0` was swallowed by the numeric-argument
    #    skip, and a full environment dump is a disclosure whatever its separator.
    if base in ("env", "printenv") and not [a for a in args if not a.startswith("-")]:
        return "%s with no command dumps the environment" % base

    # 5. Halting the machine. `-h` is in the help/version set, so `shutdown -h` read as a
    #    request for help. On systemd it schedules a halt.
    if base in ("shutdown", "reboot", "halt", "poweroff"):
        return "%s stops the machine" % base

    return None


def writes_despite_always_safe(base, args) -> bool:
    """Safe-list fix (b). Members of ALWAYS_SAFE that write given the right arguments."""
    if base == "sort" and any(a == "-o" or a.startswith("-o") for a in args):
        return True
    if base == "yq" and any(a in ("-i", "--inplace") for a in args):
        return True
    if base in ("uniq", "xxd") and len([a for a in args if not a.startswith("-")]) >= 2:
        return True
    return False


# ── per-segment classification ───────────────────────────────────────────────

def classify_segment(argv):
    """Return 'allow' | 'ask' | ('deny', reason) for one segment's resolved argv."""
    if not argv:
        return DECISION_ASK

    cmd = NormalizedCommand(argv)
    if cmd.bare_wrapper:
        # `env` and `printenv` with no command print the whole environment, which is a
        # disclosure whatever the separator. They were reaching this branch as a "bare
        # wrapper" and being allowed: the stripper removes `env` in order to find the real
        # command, so by the time anything looked, there was nothing left to look at.
        if argv and base_name(argv[0]) in ("env", "printenv"):
            return DECISION_ASK
        return DECISION_ALLOW                     # pure env-assignments / bare wrapper
    if cmd.had_sudo:
        return DECISION_ASK                       # sudo (non-catastrophic) → always ask

    base, args = cmd.base, cmd.args

    if unsafe_shape(base, args):
        return DECISION_ASK

    if args and all(a in HELP_VERSION for a in args):
        return DECISION_ALLOW

    # Safe-list fix (b): these live in ALWAYS_SAFE, whose contract is "side-effect-free
    # regardless of args", and they WRITE with the right args. Proven:
    # `sort -o victim.txt src.txt` overwrote a file reading PROTECTED-ORIGINAL.
    if writes_despite_always_safe(base, args):
        return DECISION_ASK
    if base in ALWAYS_SAFE:
        return DECISION_ALLOW

    if base == "find":
        return DECISION_ASK if any(t in FIND_DESTRUCTIVE for t in args) else DECISION_ALLOW

    if base in SUBCOMMAND_SAFE:
        if base == "git":
            sub = git_subcommand(args)
        else:
            sub = next((a for a in args if not a.startswith("-")), None)
        if sub is None and any(a in HELP_VERSION for a in args):
            return DECISION_ALLOW
        if sub in SUBCOMMAND_SAFE[base]:
            if base == "git" and sub == "config":
                if any(a in ("--get", "--get-all", "--list", "-l", "--get-regexp") for a in args):
                    return DECISION_ALLOW
                if all(not (aa.startswith("-")) for aa in args) and len(args) == 1:
                    return DECISION_ALLOW          # `git config` alone → usage
                return DECISION_ASK                # `git config k v` = write
            return DECISION_ALLOW
        return DECISION_ASK

    return DECISION_ASK


# ── disclosure rule: disclosure, not side effects ────────────────────────────
# Ported between seats 2026-09-06. It shipped on the first seat 2026-08-31; the others never
# picked it up because it landed as a mirrored copy rather than in the owning
# project. Verified before the port: `cat ~/.ssh/id_rsa` returned ALLOW on both.
#
# It does NOT deny. It downgrades ALLOW -> ASK so a human sees the read first.
# Deliberately a SUBSTRING match rather than realpath(): realpath touches the
# filesystem and would let a symlink decide the verdict. Known NOT to catch symlink
# aliasing (`cat ~/mykey`) or environment disclosure (`echo $SOME_KEY`): both are
# recorded as a known limit rather than papered over.
SECRET_PATH_MARKERS = (
    ".ssh/id_", ".ssh/identity", "authorized_keys", "known_hosts",
    ".claude.json", ".claude/settings", "credstore", "credentials",
    "rclone.conf", ".netrc", ".pgpass", ".my.cnf", ".aws/", ".azure/", ".kube/config",
    ".env", ".age", "age/keys", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
    "keychain", "secring", "gnupg", "_secrets", "/secrets", "vault", "token", "secret",
    ".zshenv", ".bash_history", ".zsh_history", "wg0.conf", "wireguard",
    # Added 2026-09-07. A review found the list caught `echo $SECRET` and `$AWS_SECRET_ACCESS_KEY`
    # while `echo $OPENAI_API_KEY` and `echo $GH_PAT` went straight through, so the README's own
    # example of this gap was the one shape the list happened to cover. These are the names that
    # actually appear on credentials in the wild.
    "api_key", "apikey", "_pat", "access_key", "private_key", "client_secret",
    "passwd", "password", "passphrase", "session_key", "refresh_token", "bearer",
    # `.ssh/id_` misses a glob, because a glob has no substring to match.
    ".ssh/",
)
ENV_DUMPERS = ("printenv", "env")


def disclosure_risk(segs):
    """-> reason string if any segment reads a secret-bearing path, else None."""
    for seg in segs:
        argv = tokenize(seg)
        if not argv:
            continue
        base = os.path.basename(argv[0])
        if base in ENV_DUMPERS and not any(a.startswith("-") and a != "-" for a in argv[1:]):
            return ("`%s` dumps the whole environment, where bearer tokens live "
                    "(disclosure rule)" % base)
        for a in argv[1:]:
            low = a.lower()
            for m in SECRET_PATH_MARKERS:
                if m in low:
                    return ("reads a secret-bearing path (matched %r) - side-effect-free "
                            "but DISCLOSING" % m)
    return None


# ── top-level decision ───────────────────────────────────────────────────────

def decide(command: str):
    """The whole classifier. Returns (decision, reason)."""
    command = (command or "").strip()
    if not command:
        return DECISION_ASK, "empty command"

    pre = preflight(command)
    if pre:
        return DECISION_ASK, pre

    segs, redir, reason = segment(command)
    if segs is None:
        return DECISION_ASK, reason

    # 1) catastrophe (deny): per segment, pre- AND post-prefix-strip
    for seg in segs:
        argv = tokenize(seg)
        if argv is None:
            return DECISION_ASK, f"unparseable segment: {seg!r}"
        cat = is_catastrophic_argv(argv)
        if cat:
            return DECISION_DENY, cat
        cat2 = is_catastrophic_argv(NormalizedCommand(argv).real)
        if cat2:
            return DECISION_DENY, cat2
    # whole-command regex catastrophe (curl|sh, fork bomb, raw-disk redirect)
    wcat = is_catastrophic_regex(command)
    if wcat:
        return DECISION_DENY, wcat

    # 2) redirects to a real file (or raw disk)
    if redir:
        if redir[0] == "deny":
            return DECISION_DENY, redir[1]
        return DECISION_ASK, redir[1]

    # 3) classify every segment; ALL must be allow to auto-allow
    verdicts = []
    for seg in segs:
        v = classify_segment(tokenize(seg))
        if isinstance(v, tuple) and v[0] == DECISION_DENY:
            return DECISION_DENY, v[1]
        verdicts.append(v)
    if all(v == DECISION_ALLOW for v in verdicts):
        _d = disclosure_risk(segs)       # disclosure rule: side-effect-free but DISCLOSING
        if _d:
            return DECISION_ASK, _d
        return DECISION_ALLOW, "all segments are read-only / side-effect-free"
    return DECISION_ASK, "not all segments are known-safe"


# ── promotion envelope (bounds what the model is even allowed to promote) ────
# Default-deny allow-list. The model may ONLY promote ask→allow within this envelope,
# so a model false-SAFE (e.g. it once judged `curl …` safe) can never leak a network /
# package / service / file-mutating command through. The model's value is reading the
# CONTENT of inline interpreter/expression commands; that: and only that: is promotable.
PROMOTABLE_BASES = {"python", "python3", "python2", "perl", "ruby", "node", "deno",
                    "php", "lua", "awk", "gawk", "mawk", "nawk", "jq", "yq", "sed",
                    "tr", "expr", "bc", "dc"}
INTERP_NEEDS_INLINE = {"python", "python3", "python2", "perl", "ruby", "node", "deno",
                       "php", "lua"}

# Per-interpreter INLINE-CODE flags. Interpreter-flag fix: the old check accepted any arg starting with
# -c/-e/-E for every interpreter, so `python3 -E file.py` (-E is an env flag carrying no
# code) promoted a FILE the gate cannot read. A flag now counts as inline only for the
# interpreters where it actually carries code, and it must appear BEFORE any file arg.
INTERP_INLINE_FLAGS = {
    "python": ("-c",), "python3": ("-c",), "python2": ("-c",),
    "perl": ("-e", "-E"), "ruby": ("-e",),
    "node": ("-e", "--eval", "-p", "--print"), "deno": (),
    "php": ("-r",), "lua": ("-e",),
}
# Benign no-payload option flags allowed to precede the inline flag.
INTERP_BENIGN_FLAGS = {
    "python": {"-E", "-I", "-S", "-B", "-s", "-u", "-O", "-OO", "-q", "-b", "-v"},
    "perl": {"-w", "-W", "-T"},
}
INTERP_BENIGN_FLAGS["python3"] = INTERP_BENIGN_FLAGS["python2"] = INTERP_BENIGN_FLAGS["python"]


def inline_invocation(base: str, args) -> bool:
    """True iff the interpreter runs INLINE code: an inline-code flag for THIS interpreter
    appears before any file/unknown argument. Fail-closed on anything else."""
    inline = INTERP_INLINE_FLAGS.get(base, ())
    benign = INTERP_BENIGN_FLAGS.get(base, set())
    for a in args:
        if any(a == f or (len(f) == 2 and a.startswith(f) and len(a) > 2) for f in inline):
            return True                       # -c'code' / -e code: rest is payload+argv
        if a in benign:
            continue                          # env/warning flag, carries no code
        return False                          # a file, '-', '--', or an unknown flag
    return False


def promotable(command: str) -> bool:
    """True only if EVERY segment is a clean, inline interpreter/expression command with
    no redirect/sudo/mutation-flag. Network/transfer/package/service/file bases are excluded
    by construction (they are simply not in PROMOTABLE_BASES)."""
    # Disclosure rule: whatever the model votes, a read of a secret-bearing path must reach
    # a human. `cat` is in ALWAYS_SAFE, so the loop below would `continue` past it,
    # re-importing the exact assumption this gate exists to break.
    if disclosure_risk(segment(command)[0] or []):
        return False
    # Model-reply fix, carrier: tokenize runs shlex with comments off and the loop below never
    # inspects trailing tokens, so `python3 -c "..." # <payload>` feeds the model text
    # the SHELL DISCARDS. Refusing promotion closes it model-independently.
    if has_unquoted_hash(command):
        return False
    if preflight(command):
        return False
    segs, redir, _ = segment(command)
    if segs is None or redir:
        return False
    for seg in segs:
        argv = tokenize(seg)
        if argv is None:
            return False
        cmd = NormalizedCommand(argv)
        if cmd.had_sudo or cmd.bare_wrapper:
            return False
        base, args = cmd.base, cmd.args
        if base in ALWAYS_SAFE:
            continue                                     # already-safe (e.g. in a pipe)
        if base not in PROMOTABLE_BASES:
            return False
        if base in ("sed", "perl") and any(a == "-i" or a.startswith("-i") for a in args):
            return False                                 # in-place edit = write
        if base in INTERP_NEEDS_INLINE and not inline_invocation(base, args):
            return False                                 # running a FILE = content we can't read
    return True
