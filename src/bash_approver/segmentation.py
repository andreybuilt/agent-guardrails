"""Quote-aware segmentation: turning one command string into the pieces that will run.

This is the layer v1 got wrong. v1 used shlex, which eats a newline as ordinary
whitespace, so `safe\\ndangerous` collapsed to base=safe and was ALLOWED. Nothing above
this layer can be correct if this layer hands it the wrong pieces, which is why it is
the first module and has no dependency on any other.

Three things are decided here and nowhere else:

  * preflight  - constructs whose meaning is not recoverable from the text
                 ($(), backticks, process substitution, heredocs, arithmetic). We do not
                 reason about them; we hand them to a human.
  * segment    - the top-level split on \\n ; && || | & , respecting quotes and escapes,
                 while classifying every output redirect it passes over.
  * tokenize   - shlex on a single segment, returning None rather than raising.

The redirect verdict travels out of the segmenter rather than being re-derived later,
because deciding it needs the quote state the scanner already has and a second pass
would have to rebuild it.
"""
from __future__ import annotations

import re
import shlex


def preflight(command: str):
    """-> reason string for a construct we refuse to reason about, else None."""
    if re.search(r"\$\(|`|<\(|>\(", command):
        return "command/process substitution"
    if re.search(r"<<", command):        # heredoc / here-string: body is unparseable data
        return "heredoc/here-string"
    if "$((" in command:                 # arithmetic subst (rare in shell commands here)
        return "arithmetic substitution"
    return None


def segment(command: str):
    """Split into top-level segments on \\n ; && || | & respecting quotes/escapes.

    Returns (segments, redirect_verdict, reason).
      segments        = list[str] (None on hard-ask like unbalanced quote)
      redirect_verdict = None | ("ask", reason) | ("deny", reason)
      reason          = str when segments is None
    """
    segs, cur = [], []
    i, n = 0, len(command)
    q = None                         # active quote char
    redir = None                     # worst redirect verdict seen

    def _redirect_target(op_start, op_len):
        """From just after the redirect operator, classify its target. Returns
        (new_index, verdict_or_None). Consumes the operator+target into cur."""
        k = op_start + op_len
        while k < n and command[k] in " \t":
            k += 1
        # fd-dup: >&1, >&2, 1>&2, >&-  -> safe
        # Redirect fix (a): a genuine fd-dup is >&1 / 2>&1 / >&- ; `>&word` REDIRECTS TO A FILE.
        # Proven: zsh -c 'ls >&w1.txt' wrote 26 bytes while this returned "safe".
        # zsh MULTIOS also writes for `2>&file`, which bash rejects.
        if k < n and command[k] == "&":
            j = k + 1
            while j < n and (command[j].isdigit() or command[j] == "-"):
                j += 1
            if j > k + 1 and (j >= n or command[j] in " \t\n;&|<>"):
                cur.append(command[op_start:j])
                return j, None
            k += 1
        t0 = k
        while k < n and command[k] not in " \t\n;&|<>":
            k += 1
        target = command[t0:k]
        cur.append(command[op_start:k])
        if target == "" or target == "/dev/null":   # redirect fix (d): no prefix match
            return k, None
        if re.match(r"/dev/(sd|disk|rdisk|nvme|hd)", target):
            return k, ("deny", "redirect to a raw disk device")
        return k, ("ask", f"redirects output to a file ({target})")

    while i < n:
        c = command[i]
        if q:                                        # inside a quote
            cur.append(c)
            if c == "\\" and q == '"' and i + 1 < n:
                cur.append(command[i + 1]); i += 2; continue
            if c == q:
                q = None
            i += 1; continue
        if c in ("'", '"'):
            q = c; cur.append(c); i += 1; continue
        if c == "\\" and i + 1 < n:                  # escape / line-continuation
            if command[i + 1] == "\n":
                i += 2; continue                     # backslash-newline = whitespace
            cur.append(c); cur.append(command[i + 1]); i += 2; continue
        # redirects (must precede operator handling so &> and >& aren't mis-split)
        if c == "&" and command[i:i + 2] == "&>":
            op_len = 3 if command[i:i + 3] == "&>>" else 2
            i, v = _redirect_target(i, op_len)
            if v and (redir is None or v[0] == "deny"):
                redir = v
            continue
        if c == ">":
            op_len = 2 if command[i:i + 2] == ">>" else 1
            i, v = _redirect_target(i, op_len)
            if v and (redir is None or v[0] == "deny"):
                redir = v
            continue
        # operators
        if command[i:i + 2] in ("&&", "||"):
            segs.append("".join(cur)); cur = []; i += 2; continue
        if c in (";", "&", "|", "\n"):
            segs.append("".join(cur)); cur = []; i += 1; continue
        cur.append(c); i += 1

    if q is not None:
        return None, None, "unbalanced quote"
    segs.append("".join(cur))
    return [s for s in segs if s.strip()], redir, None


def tokenize(seg: str):
    """shlex a single segment. None on an unparseable one, never an exception."""
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return None


def has_unquoted_hash(command: str) -> bool:
    """True if a `#` appears outside quotes. Model-reply fix, carrier: shlex runs with
    comments off, so `python3 -c "..." # <payload>` feeds the model text the SHELL
    DISCARDS. Refusing promotion on it closes the carrier model-independently."""
    q = None
    for i, ch in enumerate(command):
        if q:
            if ch == q: q = None
        elif ch in "'\"":
            q = ch
        elif ch == "#" and (i == 0 or command[i-1] in " \t\n;&|"):
            return True
    return False
