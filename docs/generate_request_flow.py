#!/usr/bin/env python3
"""Generate docs/request-flow.svg — animated version of the README's ASCII
request-flow diagram (chat lane vs dashboards lane).

SMIL animation only (no scripts) so GitHub renders it. Elbow connectors mirror
the ASCII tree (├ └); no two connectors cross.
"""

import math
from pathlib import Path

W, H = 1180, 660
BG = "#0f172a"
BOX = "#1e293b"
BORDER = "#334155"
TEXT = "#e2e8f0"
MUTED = "#94a3b8"
FLOW = "#38bdf8"
ACCENTS = {
    "blue": "#3b82f6",
    "green": "#22c55e",
    "amber": "#f59e0b",
    "rose": "#f43f5e",
    "violet": "#8b5cf6",
    "cyan": "#06b6d4",
}

parts = [
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
    f'viewBox="0 0 {W} {H}" font-family="ui-sans-serif, -apple-system, Helvetica, Arial">',
    f'<rect width="{W}" height="{H}" fill="{BG}"/>',
    f'<text x="40" y="44" fill="{TEXT}" font-size="20" font-weight="700">'
    "Request Flow — chat (streaming) vs dashboards (REST)</text>",
    '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" '
    'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
    f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{MUTED}"/></marker></defs>',
]

_n = 0


def box(x, y, w, h, title, subtitle="", accent="blue", pulse=False):
    a = ACCENTS[accent]
    if pulse:
        parts.append(
            f'<rect x="{x - 3}" y="{y - 3}" width="{w + 6}" height="{h + 6}" rx="12" '
            f'fill="none" stroke="{a}" stroke-width="1.5" opacity="0.5">'
            '<animate attributeName="opacity" values="0.5;0.08;0.5" dur="3s" '
            'repeatCount="indefinite"/></rect>'
        )
    parts.append(
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" '
        f'fill="{BOX}" stroke="{BORDER}" stroke-width="1.5"/>'
    )
    parts.append(f'<rect x="{x}" y="{y}" width="4" height="{h}" rx="2" fill="{a}"/>')
    ty = y + (h // 2 - 2 if not subtitle else 26)
    parts.append(
        f'<text x="{x + 14}" y="{ty}" fill="{TEXT}" font-size="14" '
        f'font-weight="600">{title}</text>'
    )
    if subtitle:
        parts.append(
            f'<text x="{x + 14}" y="{ty + 17}" fill="{MUTED}" font-size="11">{subtitle}</text>'
        )


def edge(points, label="", label_at=0, delay=0.0):
    """Polyline edge with dash-flow and a traveling dot. points = [(x,y), ...]"""
    global _n
    _n += 1
    pid = f"f{_n}"
    d = "M " + " L ".join(f"{x} {y}" for x, y in points)
    length = sum(
        math.hypot(points[i + 1][0] - points[i][0], points[i + 1][1] - points[i][1])
        for i in range(len(points) - 1)
    )
    parts.append(
        f'<path id="{pid}" d="{d}" stroke="{MUTED}" stroke-width="1.5" fill="none" '
        f'marker-end="url(#arr)" stroke-dasharray="5 5">'
        '<animate attributeName="stroke-dashoffset" from="10" to="0" dur="0.9s" '
        'repeatCount="indefinite"/></path>'
    )
    dur = max(1.0, length / 110)
    parts.append(
        f'<circle r="3.2" fill="{FLOW}" opacity="0">'
        f'<animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.08;0.92;1" '
        f'dur="{dur:.2f}s" begin="{delay:.2f}s" repeatCount="indefinite"/>'
        f'<animateMotion dur="{dur:.2f}s" begin="{delay:.2f}s" repeatCount="indefinite">'
        f'<mpath href="#{pid}"/></animateMotion></circle>'
    )
    if label:
        lx, ly = points[label_at]
        parts.append(
            f'<text x="{lx + 10}" y="{ly - 8}" fill="{MUTED}" font-size="11.5" '
            f'font-weight="600">{label}</text>'
        )


# ---- Browser (both lanes originate here) ----
box(40, 250, 190, 120, "Browser", "React PWA · Cognito JWT", "blue")

# ---- Chat lane (top) ----
box(280, 84, 250, 62, "CloudFront /agent/*", "reverse proxy · WAF", "violet")
box(
    590,
    84,
    270,
    62,
    "AgentCore Data Plane",
    "InvokeHarness · JWT verified · streaming",
    "blue",
)
box(920, 84, 220, 62, "Harness", "declarative agent · Claude", "rose", pulse=True)

# browser → cloudfront (elbow up then right), label "chat"
edge([(135, 250), (135, 115), (280, 115)], "chat", label_at=1, delay=0.0)
edge([(530, 115), (590, 115)], delay=0.9)
edge([(860, 115), (920, 115)], delay=1.5)

# ---- Harness branches (ASCII tree ├ └, trunk left of the branch stack) ----
box(
    700,
    210,
    440,
    58,
    "AgentCore Gateway (MCP)",
    "5 tool Lambdas → DynamoDB · market-data / portfolio / risk / trading / kb",
    "cyan",
)
box(
    700,
    292,
    440,
    58,
    "Knowledge Base tool",
    "Bedrock KB · S3 Vectors · policy docs",
    "cyan",
)
box(700, 374, 440, 58, "Built-in tools", "browser · code interpreter", "violet")
box(700, 456, 440, 58, "AgentCore Memory", "preferences · facts · summaries", "violet")

# trunk from harness bottom, stubs into each branch
trunk_x = 672
edge([(1030, 146), (1030, 178), (trunk_x, 178), (trunk_x, 239), (700, 239)], delay=2.0)
edge([(trunk_x, 239), (trunk_x, 321), (700, 321)], delay=2.6)
edge([(trunk_x, 321), (trunk_x, 403), (700, 403)], delay=3.0)
edge([(trunk_x, 403), (trunk_x, 485), (700, 485)], delay=3.4)

# ---- Dashboards lane (bottom) ----
box(280, 545, 250, 62, "API Gateway (HTTP API)", "Cognito JWT authorizer", "green")
box(590, 545, 220, 62, "Dashboard Lambda", "same tool logic as the agent", "green")
box(870, 545, 220, 62, "Amazon DynamoDB", "positions · demo order book", "amber")

edge([(135, 370), (135, 576), (280, 576)], "dashboards", label_at=1, delay=0.4)
edge([(530, 576), (590, 576)], delay=1.6)
edge([(810, 576), (870, 576)], delay=2.2)

parts.append(
    f'<text x="40" y="{H - 20}" fill="{MUTED}" font-size="11.5">'
    "Both lanes carry the user's Cognito JWT · dashboard numbers and agent-quoted numbers "
    "come from the same deterministic tool functions</text>"
)
parts.append("</svg>")

out = Path(__file__).parent / "request-flow.svg"
out.write_text("\n".join(p for p in parts if p))
print(f"wrote {out}")
