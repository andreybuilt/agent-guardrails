#!/usr/bin/env python3
"""orphan-tooling-guard: Stop hook. Catches executables written to /tmp and left there.

Measured 2026-08-22: **74** .sh/.py files in /tmp, **9** with a copy anywhere under the work tree,
**65 existing nowhere else**, oldest 2026-08-17. They span threads (client-land.sh, cert-watch.sh,
c2pa_probe.py), so this is systemic rather than one thread's habit. /tmp does not survive a reboot.

`project-wrap` Pass 0 already rescues these: but only at wrap, and only if a wrap runs at all.
This moves the catch to the end of the turn that CREATED the file, while it can still be acted on.

Why the decision cannot be made at write time: you usually cannot tell tooling from throwaway when
you write it. `to_delivery.sh` was five lines and looked disposable; it encoded the Veo 24fps+AAC
delivery fix, which had cost real debugging. So the check belongs at turn end, not at creation.

WHAT IT FLAGS: a .sh or .py under /tmp or THIS session's scratchpad, modified during this turn,
whose CONTENT HASH appears nowhere under the work tree. Hash not name, so a rescue that renames the
file still counts as rescued.

WHAT IT DELIBERATELY DOES NOT FLAG:
  - data files (.json/.txt/.csv/.log/.tar): manifests and staging are legitimately ephemeral
  - scripts that already have a copy under the work tree: already durable
  - scripts not touched this turn: someone else's problem, and nagging about them is noise
  - anything when stop_hook_active is set: never block twice

Exit 0 + JSON {"decision":"block"} sends it back; plain exit 0 allows.
Log: ~/.claude/hooks/orphan-tooling-guard.log
Origin: 2026-08-22, after the fifth executable of one session was rescued from /tmp
by Pass 0 rather than written somewhere durable in the first place.
"""
import hashlib, json, os, subprocess, sys, time

HOME = os.path.expanduser("~")
# Point AGENT_GUARDRAILS_TREE at your work tree. The fallbacks below are the
# deprecated predecessors, kept in the list so this still works on a box that has not moved yet.
# Hardcoding one makes the guard flag EVERYTHING on the other seat, because no file would ever be
# found "already durable". ORDER MATTERS: Tree first, or a seat that still has both scans the old one.
TREE = os.environ.get("AGENT_GUARDRAILS_TREE") or next(
    (os.path.join(HOME, n) for n in ("Tree", "work", "src", "Projects")
     if os.path.isdir(os.path.join(HOME, n))), os.path.join(HOME, "Tree"))
LOG = os.path.join(HOME, ".claude", "hooks", "orphan-tooling-guard.log")
# Files already reported once. Without this the guard nags every turn about the same script -

def _stranded_count():
    """Measured, never asserted. A guard that states a stale number teaches lanes to distrust it -
    the exact defect this guard exists to prevent. Counts THIS seat, now."""
    n = 0
    for d in WATCH_DIRS:
        try:
            for f in os.listdir(d):
                if f.endswith((".sh", ".py")):
                    n += 1
        except OSError:
            pass
    return n

# and the block message PROMISES it will not ("this will not fire again for the same file").
# A promise in the message with no code behind it is the exact defect class this hook exists
# alongside; implement the claim rather than wording it more carefully.
SEEN = os.path.join(HOME, ".claude", "hooks", ".orphan-guard-seen")
WATCH_DIRS = ["/tmp"]          # /private/tmp is the same filesystem; realpath dedupes
# Other live sessions write their own scratchpads under /tmp/claude-*/. Those are their threads'
# problem and nagging about them is pure noise, so skip any scratchpad that is not this session's.
#
# ⚠️ FIXED 2026-08-22. This read os.environ["CLAUDE_SESSION_ID"], which is NOT set in a hook's
# environment, so MY_SESSION was always "": and the skip condition was written
# `if "/claude-" in dirpath and MY_SESSION and ...`, where the empty string short-circuits and
# disables the skip entirely. The guard spent a night reporting five other sessions' files
# (fix_t36.py, node_owner_fix.py, publish_v92.py, diag_inline.py, publish_v92b.py) to a thread that
# had written none of them. The truthiness test meant to make the check safe is what turned it off
#: same shape as feedback_guard_disarmed_by_its_argument.
#
# The session id arrives in the hook PAYLOAD on stdin. It is resolved in main() and passed down,
# and scoping now fails CLOSED: unknown session => skip every scratchpad rather than report all.
MY_SESSION = os.environ.get("CLAUDE_SESSION_ID", "")   # fallback only
CODE_EXT = (".sh", ".py")
# Only files touched in this window count as "created this turn". Generous enough for a long
# turn, tight enough that yesterday's leftovers do not nag every single turn.
WINDOW_S = 45 * 60
MAX_REPORT = 6


def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}\n")
    except Exception:
        pass


def recent_code_files(session_id):
    """Executables under the watched dirs modified inside the window.

    session_id scopes the scratchpad sweep. Empty/unknown => skip ALL session scratchpads
    (fail closed); /tmp proper is still swept, which is the case this guard exists for.
    """
    now = time.time()
    hits = []
    for root in WATCH_DIRS:
        if not os.path.isdir(root):
            continue
        # Depth-limited walk: /tmp itself plus session scratchpads, not the whole tree.
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth >= 5:
                dirnames[:] = []
                continue
            # NOTE: do NOT prune here on session id. The scratchpad lives several levels below
            # /tmp/claude-<uid>/, so a prune at this level matches "/claude-" on the TOP directory
            #: where the session id cannot appear yet: and cuts off our OWN scratchpad too.
            # Caught by the dry run on 2026-08-22: the first version of this fix stopped reporting
            # the reporting session's own files, i.e. it silently disabled half the guard while
            # looking correct. Session filtering happens per FILE, below.
            for fn in filenames:
                if not fn.endswith(CODE_EXT):
                    continue
                p = os.path.join(dirpath, fn)
                rp = os.path.realpath(p)
                # A file inside ANY session scratchpad counts only if it is inside OURS.
                # Unknown session => fail closed, skip every scratchpad. /tmp proper is unaffected,
                # which is the case this guard was built for.
                if "/claude-" in rp and (not session_id or session_id not in rp):
                    continue
                try:
                    if now - os.path.getmtime(p) <= WINDOW_S and os.path.getsize(p) > 0:
                        hits.append(rp)
                except OSError:
                    continue
    return sorted(set(hits))   # /tmp and /private/tmp are one filesystem on macOS


# ── ATTRIBUTION for bare /tmp ──────────────────────────────────────────────────────────────────
#
# ⚠️ ADDED 2026-09-04 after FOUR misfires in two days, all against one thread, none of the files
# written by it: wrap_resume.py + port_to_tree.sh (09-03, two consecutive turns) and fj2.sh,
# probe1.sh, probe_inspect.sh, probe3.sh (09-04, one lane's git-server probes: three of them
# written BEFORE the blocked session even started).
#
# The scratchpad half of this guard was scoped to the session on 2026-08-22. Bare /tmp never was:
# it blocks on mtime alone, so on a seat running many lanes it blocks whoever happens to stop next.
#
# THE ASYMMETRY, and it is lopsided on purpose. A false BLOCK costs a turn and teaches the reader
# to dismiss the guard: measured, four times. A false MISS costs nothing new: the file is still in
# /tmp and its real owner still gets blocked the next time they touch it. So when attribution is
# impossible, DO NOT BLOCK. Session scratchpads keep their existing fail-closed scoping.
_TRANSCRIPT = None


def transcript_text(transcript_path):
    """This session's own transcript, read once. None if unavailable."""
    global _TRANSCRIPT
    if _TRANSCRIPT is not None:
        return _TRANSCRIPT or None
    if not transcript_path or not os.path.isfile(transcript_path):
        _TRANSCRIPT = ""
        return None
    try:
        with open(transcript_path, "r", errors="replace") as f:
            _TRANSCRIPT = f.read()
    except OSError:
        _TRANSCRIPT = ""
        return None
    return _TRANSCRIPT or None


def named_by_this_session(path, transcript_path):
    """Did THIS session name this file?

    Basename, not full path: /tmp and /private/tmp are one filesystem and a command may write
    either form. A basename collision errs toward NOT blocking, which is the direction chosen
    above.
    """
    text = transcript_text(transcript_path)
    if text is None:
        return False          # cannot attribute => do not block (see the asymmetry note)
    return os.path.basename(path) in text


_TREE_HASHES = None


def _sha(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def tree_hashes():
    """Content hashes of every .sh/.py under the work tree.

    Hash, NOT basename. The dry run on 2026-08-22 caught this: to_delivery.sh had been rescued
    as veo_to_delivery.sh, and a name-only check called the rescued file an orphan: the guard
    would have false-fired on the exact file that motivated it. Content survives a rename.
    """
    global _TREE_HASHES
    if _TREE_HASHES is not None:
        return _TREE_HASHES
    out = set()
    try:
        r = subprocess.run(
            ["find", TREE, "-type", "f", "(", "-name", "*.sh", "-o", "-name", "*.py", ")"],
            capture_output=True, text=True, timeout=60)
        for line in r.stdout.splitlines():
            s = _sha(line)
            if s:
                out.add(s)
    except Exception:
        # Fail OPEN: a broken check must never block real work.
        _TREE_HASHES = None
        return None
    _TREE_HASHES = out
    return out


def has_copy_in_tree(path):
    hashes = tree_hashes()
    if hashes is None:
        return True          # fail open
    s = _sha(path)
    return s is None or s in hashes


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        payload = {}

    if payload.get("stop_hook_active"):
        return 0

    try:
        seen = set(open(SEEN).read().split()) if os.path.exists(SEEN) else set()
    except Exception:
        seen = set()

    session_id = payload.get("session_id") or MY_SESSION
    transcript_path = payload.get("transcript_path") or ""

    orphans = []
    skipped_unattributed = []
    for p in recent_code_files(session_id):
        s = _sha(p)
        if s and s in seen:          # already reported this exact content once
            continue
        # A file in a session scratchpad is already scoped to THIS session by recent_code_files.
        # A file in bare /tmp is not, so it must be attributed before it can block. See the
        # ATTRIBUTION note above for why an unattributable file is skipped rather than reported.
        if "/claude-" not in p and not named_by_this_session(p, transcript_path):
            skipped_unattributed.append(p)
            continue
        if not has_copy_in_tree(p):
            orphans.append((p, s))

    if skipped_unattributed:
        log(f"SKIP {len(skipped_unattributed)} unattributed /tmp file(s) "
            f"[session={session_id or 'UNKNOWN'}]: "
            f"{[os.path.basename(x) for x in skipped_unattributed[:6]]}")

    if not orphans:
        return 0

    try:
        with open(SEEN, "a") as f:
            for _, s in orphans:
                if s:
                    f.write(s + "\n")
    except Exception:
        pass
    orphans = [p for p, _ in orphans]

    shown = orphans[:MAX_REPORT]
    more = len(orphans) - len(shown)
    lines = "\n".join(f"  {p}" for p in shown)
    if more:
        lines += f"\n  …and {more} more"

    reason = (
        "orphan-tooling-guard: this turn wrote executable(s) to a temp path with no copy under "
        f"{os.path.basename(TREE)}:\n" + lines + "\n\n"
        f"/tmp does not survive a reboot, and {_stranded_count()} .sh/.py files are already "
        f"sitting there on this seat. If any of "
        "these is real tooling, copy it into the owning project's 10_SOURCE/<pipeline>/ now: "
        "not at wrap, which only runs if a wrap happens.\n"
        "If it is genuinely throwaway, say so in one line and continue; this will not fire again "
        "for the same file once it stops being touched."
    )
    log(f"BLOCK {len(orphans)} orphan(s) [session={session_id or 'UNKNOWN'}]: "
        f"{[os.path.basename(p) for p in orphans]}")
    print(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        # Never let a guard failure block a turn.
        log(f"ERROR {e}")
        sys.exit(0)
