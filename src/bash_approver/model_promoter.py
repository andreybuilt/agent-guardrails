"""Optional local model that may upgrade ask -> allow. Off by default, fail-closed.

Separate from policy because it is the only part of the classifier that does network I/O
and the only part whose answer comes from outside the repository. Keeping it in its own
module makes the trust boundary visible: policy.promotable decides WHAT may be asked
about, this decides only whether the answer was yes, and neither can override a deny.

The reply check is a whole-token match, not a prefix. A prefix match promotes any reply
beginning "SAFE", including "SAFETY: UNSAFE", "SAFE? UNSAFE" and "SAFE_NO", where the
model answered CORRECTLY and the comparison discarded its answer. Measured: 20 live
false-SAFE -> 2. A more capable model makes the prefix bug WORSE, because a fuller
correct reply still begins with those four characters.

Config: BASH_APPROVER_MODEL="ollama:MODEL@HOST:PORT"
"""
from __future__ import annotations

import json
import os
import re

PROMPT = (
    "You are a strict shell-command safety gate. Answer with ONLY 'SAFE' or "
    "'UNSAFE'. 'SAFE' means the command has NO side effects: it does not "
    "write, move, delete, or create files; does not install, network-mutate, "
    "start/stop services, or change config; is purely read-only/inspection. "
    "Fetching or sending over the network (curl, wget, ssh, nc, scp, etc.) is UNSAFE. "
    "If in any doubt, answer UNSAFE.\n\nCommand:\n%s\n\nAnswer:"
)


def verdict_ok(out: str) -> bool:
    """True only if the model's FIRST TOKEN is exactly SAFE (model-reply fix)."""
    tok = (out or "").strip().upper().strip(" \t\r\n.:!?,;_-\"'`")
    return tok.split()[0] == "SAFE" if tok.split() else False


def model_promote(command: str) -> bool:
    """Ask the configured local model. Any error, any timeout, any other reply -> False."""
    spec = os.getenv("BASH_APPROVER_MODEL", "").strip()
    if not spec or spec.lower() in ("off", "0", "false", "none"):
        return False
    try:
        import urllib.request
        m = re.match(r"ollama:([^@]+)@(.+)", spec)
        if not m:
            return False
        model, hostport = m.group(1), m.group(2)
        body = json.dumps({"model": model, "prompt": PROMPT % command, "stream": False,
                           "options": {"temperature": 0}}).encode()
        req = urllib.request.Request(f"http://{hostport}/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            out = json.loads(r.read().decode()).get("response", "")
        return verdict_ok(out)
    except Exception:
        return False
