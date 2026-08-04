#!/usr/bin/env python3
"""Generate docs/architecture.svg — layered layout, no crossing connectors.

Animated: request dots flow along every edge (SMIL animateMotion — works in
GitHub READMEs, which allow SMIL/CSS but not scripts in SVG), edges carry a
moving dash pattern, and the Harness box breathes. architecture.png stays as
the static fallback.

Layers (top → bottom): client → edge → auth/api → agent core → tools/data.
All edges run vertically between adjacent layers or horizontally within a
layer, so no two connectors can intersect.
"""

import math
from pathlib import Path

W, H = 1180, 860
BG = "#0f172a"
BOX = "#1e293b"
BORDER = "#334155"
TEXT = "#e2e8f0"
MUTED = "#94a3b8"
FLOW = "#38bdf8"  # request-flow dots (sky-400)
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
    f'<text x="40" y="48" fill="{TEXT}" font-size="24" font-weight="700">'
    "Agentic AI Industry Use Cases — AWS Bedrock AgentCore Harness</text>",
    f'<text x="40" y="74" fill="{MUTED}" font-size="14">'
    "Declarative managed agents · Gateway MCP tools · Knowledge Base (S3 Vectors) · Cognito end to end</text>",
]

_edge_n = 0


def box(x, y, w, h, title, subtitle="", accent="blue", pulse=False):
    a = ACCENTS[accent]
    extra = ""
    if pulse:
        # breathing border on the hero box
        extra = (
            f'<rect x="{x - 3}" y="{y - 3}" width="{w + 6}" height="{h + 6}" rx="12" '
            f'fill="none" stroke="{a}" stroke-width="1.5" opacity="0.5">'
            '<animate attributeName="opacity" values="0.5;0.08;0.5" dur="3s" '
            'repeatCount="indefinite"/></rect>'
        )
    parts.append(extra)
    parts.append(
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" '
        f'fill="{BOX}" stroke="{BORDER}" stroke-width="1.5"/>'
    )
    parts.append(f'<rect x="{x}" y="{y}" width="4" height="{h}" rx="2" fill="{a}"/>')
    ty = y + 28
    parts.append(
        f'<text x="{x + 16}" y="{ty}" fill="{TEXT}" '
        f'font-size="15" font-weight="600">{title}</text>'
    )
    if subtitle:
        parts.append(
            f'<text x="{x + 16}" y="{ty + 18}" fill="{MUTED}" font-size="11.5">{subtitle}</text>'
        )


def arrow(x1, y1, x2, y2, label="", delay=0.0, dot=True):
    """Edge with arrowhead, animated dash flow, and a traveling request dot."""
    global _edge_n
    _edge_n += 1
    pid = f"e{_edge_n}"
    length = math.hypot(x2 - x1, y2 - y1)
    parts.append(
        f'<path id="{pid}" d="M {x1} {y1} L {x2} {y2}" stroke="{MUTED}" '
        f'stroke-width="1.5" fill="none" marker-end="url(#arr)" '
        f'stroke-dasharray="5 5">'
        '<animate attributeName="stroke-dashoffset" from="10" to="0" '
        'dur="0.9s" repeatCount="indefinite"/></path>'
    )
    if dot:
        dur = max(0.9, length / 90)
        parts.append(
            f'<circle r="3.2" fill="{FLOW}" opacity="0">'
            f'<animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.1;0.9;1" '
            f'dur="{dur:.2f}s" begin="{delay:.2f}s" repeatCount="indefinite"/>'
            f'<animateMotion dur="{dur:.2f}s" begin="{delay:.2f}s" repeatCount="indefinite">'
            f'<mpath href="#{pid}"/></animateMotion></circle>'
        )
    if label:
        lx = (x1 + x2) / 2 + 8
        ly = (y1 + y2) / 2 - 6
        parts.append(
            f'<text x="{lx}" y="{ly}" fill="{MUTED}" font-size="11">{label}</text>'
        )


parts.append(
    '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" '
    'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
    f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{MUTED}"/></marker></defs>'
)

# Layer 1: client
box(
    430,
    100,
    320,
    62,
    "Responsive PWA (React 19 + Amplify)",
    "mobile / tablet / desktop · industry modules",
    "blue",
)

# Layer 2: edge — delays stagger the dots so the request "travels" down the page
box(
    430,
    212,
    320,
    62,
    "Amazon CloudFront + AWS WAF",
    "static site (S3, OAC) · /agent/* reverse proxy",
    "violet",
)
arrow(590, 162, 590, 212, "HTTPS · Cognito JWT", delay=0.0)

# Layer 3: two entry paths (left REST, right agent) + Cognito on far left
box(60, 324, 260, 62, "Amazon Cognito", "user pool · TOTP MFA · JWT issuer", "amber")
arrow(320, 355, 360, 355, delay=0.3)
box(360, 324, 220, 62, "API Gateway (HTTP API)", "JWT authorizer · dashboards", "green")
box(
    620,
    324,
    300,
    62,
    "AgentCore Data Plane",
    "InvokeHarness · customJWTAuthorizer · streaming",
    "blue",
)
arrow(500, 274, 470, 324, "REST", delay=0.6)
arrow(680, 274, 710, 324, "chat (eventstream)", delay=0.6)

# Layer 4: agent core (hero box breathes)
box(
    620,
    436,
    300,
    76,
    "AgentCore Harness (per industry)",
    "Claude Sonnet · declarative · 6 industries live",
    "rose",
    pulse=True,
)
arrow(770, 386, 770, 436, delay=1.2)
box(360, 436, 220, 62, "Dashboard Lambda", "portfolio / orders / market", "green")
arrow(470, 386, 470, 436, delay=1.2)

# Layer 5: harness capabilities
box(
    620,
    562,
    300,
    62,
    "AgentCore Gateway (MCP)",
    "AWS_IAM inbound · 5 Lambda targets / industry",
    "cyan",
)
arrow(770, 512, 770, 562, "tools", delay=1.8)
box(950, 436, 190, 76, "AgentCore Memory", "preferences · facts · summaries", "violet")
arrow(920, 474, 950, 474, delay=1.8)
box(950, 562, 190, 62, "Built-in tools", "browser · code interpreter", "violet")
arrow(920, 593, 950, 593, delay=2.1)

# Layer 6: tool lambdas + data
box(
    620,
    674,
    300,
    62,
    "Tool Lambdas ×5 per industry",
    "4 domain tools + kb search",
    "green",
)
arrow(770, 624, 770, 674, delay=2.4)
box(360, 674, 220, 62, "Amazon DynamoDB", "positions · demo order book", "amber")
arrow(620, 705, 580, 705, delay=3.0)
box(950, 674, 190, 62, "Bedrock Knowledge Base", "S3 Vectors · policy docs", "cyan")
arrow(920, 705, 950, 705, delay=3.0)
arrow(470, 498, 470, 674, "reads", delay=1.8)

# footer badges
parts.append(
    f'<text x="40" y="{H - 30}" fill="{MUTED}" font-size="12">'
    "Security: JWT verified at every entry · WAF attached · least-privilege IAM · KMS · "
    "no VPC/NAT · simulated market data disclosed</text>"
)

parts.append("</svg>")

out = Path(__file__).parent / "architecture.svg"
out.write_text("\n".join(p for p in parts if p))
print(f"wrote {out}")
