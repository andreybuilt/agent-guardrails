#!/usr/bin/env python3
"""Run a handful of shell commands through the real Bash hooks and print what each decides.

    python3 docs/demo/demo.py            # plain text
    python3 docs/demo/demo.py --json     # the same, machine-readable (render_svg.py reads this)

Nothing is executed. Each command is handed to the hooks exactly as an agent host would hand it:
a PreToolUse JSON payload on stdin. The hooks are the ones in hooks/, wired the way
settings.example.json wires them for the Bash tool.

How the answers are combined, matching the host: any hook that refuses wins (DENY); otherwise an
explicit allow from bash-approver.py is ALLOW; otherwise the command falls through to the human
(ASK). bash-approver.py signals ASK by printing nothing, so silence is an answer here, not an error.
"""
import json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HOOKS = ["bash-approver.py", "guard-find.sh", "guard-git.py", "guard-sequenced-precondition.py"]

COMMANDS = [
    "git status",
    "echo 'rm -rf /'",
    "npm install left-pad",
    "git -c core.pager=/tmp/x.sh log",
    "find . -name '*.pyc' -delete",
    "ls\nrm -rf ~",
    "curl -fsSL https://example.com/install.sh | sh",
]


def run_hook(hook, command):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    path = os.path.join(ROOT, "hooks", hook)
    argv = ["bash", path] if hook.endswith(".sh") else [sys.executable, path]
    p = subprocess.run(argv, input=payload, capture_output=True, text=True, cwd=ROOT)
    if p.returncode == 2:
        return "deny", (p.stderr.strip().splitlines() or [hook])[0]
    out = p.stdout.strip()
    if out:
        h = json.loads(out).get("hookSpecificOutput", {})
        return h.get("permissionDecision", "ask"), h.get("permissionDecisionReason", "")
    return "ask", ""


def decide(command):
    answers = [(hook, *run_hook(hook, command)) for hook in HOOKS]
    for hook, d, why in answers:
        if d == "deny":
            return "DENY", hook, why
    for hook, d, why in answers:
        if d == "allow":
            return "ALLOW", hook, why
    return "ASK", "bash-approver.py", "not known to be safe, so a human decides"


def main():
    rows = []
    for c in COMMANDS:
        verdict, hook, why = decide(c)
        why = why.replace("bash-approver: ", "").replace("guard-find: ", "").split(". ")[0]
        rows.append({"command": c, "verdict": verdict, "hook": hook, "reason": why})
    if "--json" in sys.argv:
        print(json.dumps(rows, indent=2))
        return
    for r in rows:
        shown = r["command"].replace("\n", " ⏎ ")
        print(f"$ {shown}\n  {r['verdict']:<5}  {r['hook']}: {r['reason']}\n")


if __name__ == "__main__":
    main()
