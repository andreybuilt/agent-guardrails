#!/usr/bin/env python3
"""Render docs/demo/demo.svg from the live output of demo.py. Standard library only.

    python3 docs/demo/render_svg.py            # regenerate
    python3 docs/demo/render_svg.py --check    # exit 1 if the SVG no longer matches the hooks (run by the suite)

The SVG is a looping terminal replay of what the hooks ACTUALLY decided on this checkout. It is
generated, never hand-edited, so it cannot drift from the code: rerun this after changing a hook.
"""
import json, os, subprocess, sys
from html import escape

HERE = os.path.dirname(os.path.abspath(__file__))
rows = json.loads(subprocess.check_output([sys.executable, os.path.join(HERE, "demo.py"), "--json"], text=True))

W, LINE, TOP, LEFT = 860, 22, 58, 22
COLORS = {"ALLOW": "#3fb950", "ASK": "#d29922", "DENY": "#f85149"}
CYCLE = 2.2 * len(rows) + 4.0            # seconds per loop: each row gets 2.2 s, then a 4 s hold

lines = []                                # (y, svg-text, reveal-at-seconds)
y = TOP
for i, r in enumerate(rows):
    t = 0.4 + i * 2.2
    cmd = escape(r["command"].replace("\n", " ⏎ "))
    lines.append((y, f'<tspan fill="#8b949e">$ </tspan><tspan fill="#e6edf3">{cmd}</tspan>', t))
    y += LINE
    col = COLORS[r["verdict"]]
    why = escape(f'{r["hook"]}: {r["reason"]}')
    lines.append((y, f'<tspan fill="{col}" font-weight="700">  {r["verdict"]:<5}</tspan>'
                     f'<tspan fill="#8b949e">  {why}</tspan>', t + 0.9))
    y += LINE + 8
H = y + 10

css = [f".l{{opacity:0;animation-duration:{CYCLE:.1f}s;animation-iteration-count:infinite}}"]
body = []
for n, (ly, text, t) in enumerate(lines):
    on = 100 * t / CYCLE
    css.append(f"@keyframes k{n}{{0%,{on:.2f}%{{opacity:0}}{on + 0.8:.2f}%,97%{{opacity:1}}100%{{opacity:0}}}}"
               f".k{n}{{animation-name:k{n}}}")
    body.append(f'<text class="l k{n}" x="{LEFT}" y="{ly}" xml:space="preserve">{text}</text>')

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img"
 aria-label="Terminal replay: seven agent shell commands and what the guardrail hooks decided for each">
<style>
text{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13.5px}}
{"".join(css)}
@media (prefers-reduced-motion: reduce){{.l{{animation:none;opacity:1}}}}
</style>
<rect width="{W}" height="{H}" rx="10" fill="#0d1117"/>
<circle cx="22" cy="20" r="6" fill="#f85149"/><circle cx="42" cy="20" r="6" fill="#d29922"/><circle cx="62" cy="20" r="6" fill="#3fb950"/>
<text x="{W // 2}" y="24" text-anchor="middle" fill="#8b949e" font-size="12">agent-guardrails: what the hooks decide (nothing is executed)</text>
{chr(10).join(body)}
</svg>
'''
out = os.path.join(HERE, "demo.svg")
if "--check" in sys.argv:
    current = open(out).read() if os.path.exists(out) else ""
    if current != svg:
        sys.exit("demo.svg is stale: the hooks now decide differently. Run python3 docs/demo/render_svg.py")
    print("  ok    demo.svg matches what the hooks decide today")
else:
    open(out, "w").write(svg)
    print(f"wrote demo.svg: {len(rows)} commands, {len(svg)} bytes, {CYCLE:.1f}s loop")
