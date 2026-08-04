#!/usr/bin/env python3
"""Generate docs/architecture.svg — layered layout, no crossing connectors.

Layers (top → bottom): client → edge → auth/api → agent core → tools/data.
All edges run vertically between adjacent layers or horizontally within a
layer, so no two connectors can intersect.
"""

from pathlib import Path

W, H = 1180, 860
BG = "#0f172a"
BOX = "#1e293b"
BORDER = "#334155"
TEXT = "#e2e8f0"
MUTED = "#94a3b8"
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


def box(x, y, w, h, title, subtitle="", accent="blue", small=False):
    a = ACCENTS[accent]
    parts.append(
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" '
        f'fill="{BOX}" stroke="{BORDER}" stroke-width="1.5"/>'
    )
    parts.append(f'<rect x="{x}" y="{y}" width="4" height="{h}" rx="2" fill="{a}"/>')
    ty = y + (24 if small else 28)
    parts.append(
        f'<text x="{x + 16}" y="{ty}" fill="{TEXT}" '
        f'font-size="{13 if small else 15}" font-weight="600">{title}</text>'
    )
    if subtitle:
        parts.append(
            f'<text x="{x + 16}" y="{ty + 18}" fill="{MUTED}" font-size="11.5">{subtitle}</text>'
        )


def arrow(x1, y1, x2, y2, label="", color=MUTED):
    parts.append(
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
        f'stroke-width="1.5" marker-end="url(#arr)"/>'
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

# Layer 2: edge
box(
    430,
    212,
    320,
    62,
    "Amazon CloudFront + AWS WAF",
    "static site (S3, OAC) · /agent/* reverse proxy",
    "violet",
)
arrow(590, 162, 590, 212, "HTTPS · Cognito JWT")

# Layer 3: two entry paths (left REST, right agent) + Cognito on far left
box(60, 324, 260, 62, "Amazon Cognito", "user pool · TOTP MFA · JWT issuer", "amber")
arrow(320, 355, 360, 355)
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
arrow(500, 274, 470, 324, "REST")
arrow(680, 274, 710, 324, "chat (eventstream)")

# Layer 4: agent core
box(
    620,
    436,
    300,
    76,
    "AgentCore Harness (per industry)",
    "Claude Sonnet · declarative config · finance + healthcare live",
    "rose",
)
arrow(770, 386, 770, 436)
box(360, 436, 220, 62, "Dashboard Lambda", "portfolio / orders / market", "green")
arrow(470, 386, 470, 436)

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
arrow(770, 512, 770, 562, "tools")
box(950, 436, 190, 76, "AgentCore Memory", "preferences · facts · summaries", "violet")
arrow(920, 474, 950, 474)
box(950, 562, 190, 62, "Built-in tools", "browser · code interpreter", "violet")
arrow(920, 593, 950, 593)

# Layer 6: tool lambdas + data
box(
    620,
    674,
    300,
    62,
    "Tool Lambdas ×5",
    "market-data / portfolio / risk / trading / kb",
    "green",
)
arrow(770, 624, 770, 674)
box(360, 674, 220, 62, "Amazon DynamoDB", "positions · demo order book", "amber")
arrow(620, 705, 580, 705)
box(950, 674, 190, 62, "Bedrock Knowledge Base", "S3 Vectors · policy docs", "cyan")
arrow(920, 705, 950, 705)
arrow(470, 498, 470, 674, "reads")

# footer badges
parts.append(
    f'<text x="40" y="{H - 30}" fill="{MUTED}" font-size="12">'
    "Security: JWT verified at every entry · WAF attached · least-privilege IAM · KMS · "
    "no VPC/NAT · simulated market data disclosed</text>"
)

parts.append("</svg>")

out = Path(__file__).parent / "architecture.svg"
out.write_text("\n".join(parts))
print(f"wrote {out}")
