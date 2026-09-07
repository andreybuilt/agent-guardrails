#!/usr/bin/env python3
"""guard-agent-model.py — PreToolUse(Agent). REFUSES an Agent call that does not name its model.

WHY: an Agent call with no `model` inherits the parent's model. Measured on one seat over eight hours:
350 Agent calls, 168 inherited, 126 of those ran Opus, ZERO ever pinned to Opus — every Opus
subagent came from an omitted parameter, never a decision. A charter rule cannot reach a session
that is not reading the charter; a refusal can.

Blocks : tool_name == "Agent" and tool_input has no non-empty "model"  (main thread AND subagents)
Allows : any Agent call with a model; every other tool (exit 0, no output)
Escape : none by design. A model name costs one token; there is no legitimate "I could not decide".

Protocol: PreToolUse JSON on stdin; exit 0 = allow; exit 2 = deny (stderr is shown to Claude).
Log    : ~/.local/state/agent-model-guard.log  (one line per decision; never the prompt body)
"""
import sys, json, os, datetime

LOG = os.path.expanduser("~/.local/state/agent-model-guard.log")
ALLOWED = {"opus", "sonnet", "haiku", "fable", "inherit"}   # aliases; full ids also pass

def log(msg):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(f"{datetime.datetime.now():%Y-%m-%dT%H:%M:%S} {msg}\n")
    except Exception:
        pass

def main():
    try:
        ev = json.load(sys.stdin)
    except Exception:
        sys.exit(0)                      # unreadable event: not ours to judge
    if ev.get("tool_name") != "Agent":
        sys.exit(0)
    inp = ev.get("tool_input") or {}
    # 🛑 FORKS ARE EXEMPT. The Agent tool's own schema says `model` is IGNORED for
    # subagent_type "fork" — a fork always inherits the parent model by design. Refusing there
    # would be a false positive, and a guard that fires on correct behaviour trains people past it.
    if (inp.get("subagent_type") or "").lower() == "fork":
        log("ALLOW subagent_type=fork (model is ignored for forks)")
        sys.exit(0)

    model = inp.get("model")
    desc = (inp.get("description") or "")[:60]
    agent = ev.get("agent_id") or "main"
    if isinstance(model, str) and model.strip():
        m = model.strip()
        ok = m in ALLOWED or m.startswith("claude-")
        log(f"ALLOW model={m} ok_alias={ok} agent={agent} desc={desc!r}")
        sys.exit(0)

    log(f"BLOCK model=<missing> agent={agent} sid={ev.get('session_id','?')} desc={desc!r}")
    sys.stderr.write(
        "guard-agent-model: BLOCKED — this Agent call names no `model`, so the subagent would\n"
        "silently inherit this session's model (usually Opus). A default is not a decision.\n\n"
        "Re-issue the same call with `model` set. Size it to the work:\n"
        "  \"model\": \"haiku\"   mechanical fan-out — grep-and-report, counting, messaging N targets\n"
        "  \"model\": \"sonnet\"  bounded real work — verification, sweeps, running a clear plan\n"
        "  \"model\": \"opus\"    judgment or irreversible work — and then say why in `description`\n\n"
        "Nothing else about the call needs to change. (Measured 2026-09-03: 126 Opus subagents on\n"
        "one seat in a day, all from an omitted parameter. This hook is why that number stops growing.)\n")
    sys.exit(2)

if __name__ == "__main__":
    main()
