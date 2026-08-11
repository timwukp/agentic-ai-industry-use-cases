#!/usr/bin/env python3
"""Generate docs/business-flows/<industry>.svg — six animated business-logic
flow diagrams, one per industry, from the declarative FLOWS specs below.

Visual grammar (identical across all six):
  - vertical SPINE (the business process, top -> bottom) at x 430..750
  - LEFT RAIL (systems / data / KB policies, cyan) at x 60..340
  - RIGHT RAIL (humans / escalations, amber / rose) at x 840..1140
  - reserved RETURN CHANNELS at x=28 and x=1156 for loop-back edges only
  - encodings: AI step = blue stripe + AI chip · human approval gate = amber
    diamond · compliance checkpoint = rose double border · write/transactional
    action = green + WRITE chip · escalation = dashed rose edge

Crossing avoidance is by construction (verticals only at the spine center and
the two channels; horizontals at unique per-element y's) and then VERIFIED by
a geometric check (segment x segment proper intersections + segment x rect
sweeps) that fails generation on any hit.

SMIL animation only (no scripts) so GitHub renders it, matching
docs/generate_architecture.py and docs/generate_request_flow.py.

Usage:
  python generate_business_flows.py             # write the six SVGs
  python generate_business_flows.py --mermaid   # print mermaid blocks (the
                                                # editable logic source pasted
                                                # into docs/business-flows.md)
"""

import math
import sys
from pathlib import Path

W = 1180
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

# column geometry (identical for all six diagrams)
SPINE_X, SPINE_W = 430, 320
SPINE_CX = SPINE_X + SPINE_W // 2  # 590
LEFT_X, LEFT_W = 60, 280
RIGHT_X, RIGHT_W = 840, 300
CH_LEFT, CH_RIGHT = 28, 1156
TRUNK_X = 790  # gate fan-out trunk (request-flow ASCII-tree precedent)

STAGE_H, STAGE_GAP = 72, 34
GATE_HALF, GATE_PAD = 26, 14
RAIL_H = 58

KIND_ACCENT = {
    "ai": "blue",
    "write": "green",
    "compliance": "rose",
    "human": "amber",
    "data": "cyan",
    "escalation": "rose",
}
KIND_CHIP = {
    "ai": ("AI", "blue"),
    "write": ("WRITE", "green"),
    "compliance": ("COMPLIANCE", "rose"),
    "human": ("HUMAN", "amber"),
    "escalation": ("ESCALATION", "rose"),
}


# --------------------------------------------------------------------------
# six declarative flow specs
# --------------------------------------------------------------------------

FLOWS = [
    {
        "slug": "finance-trading",
        "title": "Finance Trading — Signal to Executed Order",
        "tagline": "Four labeled data worlds · every recommendation carries a "
        "suitability check · confirm-then-execute",
        "stages": [
            {
                "id": "intel",
                "title": "Market intelligence",
                "sub": "quotes · macro · news factors",
                "kind": "ai",
            },
            {
                "id": "prism",
                "title": "Regime & signal read (PRISM)",
                "sub": "regime = lens, never a timing signal",
                "kind": "ai",
            },
            {
                "id": "port",
                "title": "Portfolio review",
                "sub": "positions · P&L · concentration",
                "kind": "ai",
            },
            {
                "id": "risk",
                "title": "Risk assessment",
                "sub": "VaR · stress tests · Monte Carlo",
                "kind": "ai",
            },
            {
                "id": "suit",
                "title": "Suitability & compliance check",
                "sub": "profile matrix · restricted list",
                "kind": "compliance",
            },
            {
                "id": "confirm",
                "title": "Client confirmation",
                "sub": "symbol · side · quantity · type",
                "kind": "human",
            },
            {
                "id": "order",
                "title": "Order placement & management",
                "sub": "market fills now · limit stays open",
                "kind": "write",
            },
        ],
        "gates": [
            {
                "id": "g_margin",
                "after": "risk",
                "label": "margin call?",
                "passes": "none / cured",
                "branches": [
                    {
                        "label": "> $250k same day",
                        "to": "riskdesk",
                        "style": "escalation",
                    }
                ],
            },
            {
                "id": "g_profile",
                "after": "suit",
                "label": "in profile?",
                "passes": "within client risk profile",
                "branches": [
                    {"label": "out-of-profile rec", "to": "super", "style": "human"}
                ],
            },
        ],
        "rails": [
            {
                "id": "worlds",
                "side": "left",
                "anchor": "intel",
                "kind": "data",
                "title": "Data worlds (labeled)",
                "sub": "LIVE · DERIVED · MODEL · SIMULATED",
            },
            {
                "id": "kb",
                "side": "left",
                "anchor": "suit",
                "kind": "data",
                "title": "KB: margin & suitability policy",
                "sub": "profile matrix · restricted list",
            },
            {
                "id": "riskdesk",
                "side": "right",
                "anchor": "g_margin",
                "kind": "escalation",
                "title": "Risk Desk",
                "sub": "margin calls > $250k",
            },
            {
                "id": "super",
                "side": "right",
                "anchor": "g_profile",
                "kind": "human",
                "title": "Supervisor approval",
                "sub": "documented rationale required",
            },
        ],
        "returns": [],
        "footer": "No crash dates or probabilities-by-date — ever · regime lags "
        "real time by 10+ trading days and is disclosed as history",
    },
    {
        "slug": "healthcare-medical",
        "title": "Healthcare — Chart Review to Care Plan",
        "tagline": "Decision support only: a licensed clinician reviews before "
        "any care decision",
        "stages": [
            {
                "id": "verify",
                "title": "Patient identity verification",
                "sub": "two identifiers · minimum necessary",
                "kind": "compliance",
            },
            {
                "id": "chart",
                "title": "Chart review",
                "sub": "summary · meds · labs · notes",
                "kind": "ai",
            },
            {
                "id": "triage",
                "title": "Clinical assessment & triage",
                "sub": "red flags · ICD-10 differentials",
                "kind": "ai",
            },
            {
                "id": "ix",
                "title": "Interactions & risk scores",
                "sub": "drug pairs · ASCVD · Morse · LACE+",
                "kind": "ai",
            },
            {
                "id": "care",
                "title": "Care planning",
                "sub": "care gaps · LACE+ >=30% -> transitional",
                "kind": "ai",
            },
            {
                "id": "sched",
                "title": "Scheduling & reminders",
                "sub": "no diagnosis in any reminder",
                "kind": "write",
            },
            {
                "id": "pop",
                "title": "Population health roll-up",
                "sub": "HEDIS gaps · prevalence · utilization",
                "kind": "ai",
            },
        ],
        "gates": [
            {
                "id": "g_triage",
                "after": "triage",
                "label": "triage level?",
                "passes": "URGENT / ROUTINE · age auto-escalation",
                "branches": [
                    {"label": "EMERGENCY (RED)", "to": "ed", "style": "escalation"}
                ],
            },
            {
                "id": "g_ix",
                "after": "ix",
                "label": "major interaction?",
                "passes": "none found (list non-exhaustive)",
                "branches": [
                    {"label": "major pair flagged", "to": "rx", "style": "human"}
                ],
            },
        ],
        "rails": [
            {
                "id": "ehr",
                "side": "left",
                "anchor": "chart",
                "kind": "data",
                "title": "EHR (HIPAA audit-logged)",
                "sub": "every access: who · when · why",
            },
            {
                "id": "kb",
                "side": "left",
                "anchor": "ix",
                "kind": "data",
                "title": "KB: clinical protocols",
                "sub": "medication safety · PHI policy",
            },
            {
                "id": "ed",
                "side": "right",
                "anchor": "g_triage",
                "kind": "escalation",
                "title": "ED / 911 handoff",
                "sub": "chest pain · stroke · anaphylaxis",
            },
            {
                "id": "rx",
                "side": "right",
                "anchor": "g_ix",
                "kind": "human",
                "title": "Prescriber acknowledgment",
                "sub": "required before dispensing",
            },
        ],
        "returns": [],
        "footer": "PHI: reference by patient ID · verify identity before any "
        "disclosure · critical labs flagged to provider immediately",
    },
    {
        "slug": "insurance-claims",
        "title": "Insurance Claims — FNOL to Settlement",
        "tagline": "Every claim is fraud-screened before a dollar moves · "
        "authority ladder on every payout",
        "stages": [
            {
                "id": "fnol",
                "title": "FNOL intake",
                "sub": "acknowledge 24h · assign adjuster 48h",
                "kind": "write",
            },
            {
                "id": "verify",
                "title": "Policy & coverage verification",
                "sub": "active? premium paid? exclusions?",
                "kind": "ai",
            },
            {
                "id": "fraud",
                "title": "Mandatory fraud screen",
                "sub": "weighted indicators -> score 0-1",
                "kind": "compliance",
            },
            {
                "id": "damage",
                "title": "Damage assessment",
                "sub": "fast-track / standard / investigation",
                "kind": "ai",
            },
            {
                "id": "reserve",
                "title": "Reserve estimation",
                "sub": "Chain-Ladder + BF · initial <= 5 days",
                "kind": "ai",
            },
            {
                "id": "settle",
                "title": "Settlement calculation",
                "sub": "deductible · depreciation · limits",
                "kind": "ai",
            },
            {
                "id": "pay",
                "title": "Payment",
                "sub": "itemized · written basis · cite policy",
                "kind": "write",
            },
        ],
        "gates": [
            {
                "id": "g_fraud",
                "after": "fraud",
                "label": "fraud score?",
                "passes": "<= 0.4 standard track",
                "branches": [
                    {"label": "0.4 - 0.7", "to": "enh", "style": "human"},
                    {
                        "label": "> 0.7 · freeze settlement",
                        "to": "siu",
                        "style": "escalation",
                    },
                ],
            },
            {
                "id": "g_auth",
                "after": "settle",
                "label": "within authority?",
                "passes": "adjuster <= $10k",
                "branches": [
                    {"label": "$25k / $100k / above", "to": "signoff", "style": "human"}
                ],
            },
        ],
        "rails": [
            {
                "id": "kb",
                "side": "left",
                "anchor": "fraud",
                "kind": "data",
                "title": "KB: claims-handling manual",
                "sub": "fraud-indicators guide (weights)",
            },
            {
                "id": "ladder",
                "side": "left",
                "anchor": "g_auth",
                "kind": "data",
                "title": "Authority ladder",
                "sub": "$10k adjuster · $25k supr · $100k dir",
            },
            {
                "id": "enh",
                "side": "right",
                "anchor": "g_fraud",
                "kind": "human",
                "title": "Enhanced review",
                "sub": "senior adjuster",
            },
            {
                "id": "siu",
                "side": "right",
                "anchor": "g_fraud",
                "kind": "escalation",
                "title": "SIU investigation",
                "sub": "report <= 15 days · neutral comms",
            },
            {
                "id": "signoff",
                "side": "right",
                "anchor": "g_auth",
                "kind": "human",
                "title": "Supervisor / Director sign-off",
                "sub": "> $100k adds committee review",
            },
        ],
        "returns": [
            {
                "src": "siu",
                "dst": "settle",
                "label": "cleared -> resume",
                "channel": "far_right",
            }
        ],
        "footer": "Fair claims practice: respond 10 business days · decide within "
        "40 days of proof of loss · deny only in writing citing policy language",
    },
    {
        "slug": "retail-inventory",
        "title": "Retail Inventory — Stockout to Reorder to Price",
        "tagline": "A-class first, always · transfer beats emergency PO · price "
        "moves are capped",
        "stages": [
            {
                "id": "stock",
                "title": "Stock position check",
                "sub": "ABC classes · fill targets 98/95/90%",
                "kind": "ai",
            },
            {
                "id": "forecast",
                "title": "Demand forecast",
                "sub": "seasonality · confidence intervals",
                "kind": "ai",
            },
            {
                "id": "reorder",
                "title": "Reorder computation",
                "sub": "EOQ + safety stock 7d (14d peak)",
                "kind": "ai",
            },
            {
                "id": "supplier",
                "title": "Supplier evaluation",
                "sub": "tiers: PREFERRED >=90 · APPROVED >=75",
                "kind": "ai",
            },
            {
                "id": "po",
                "title": "Purchase order",
                "sub": "terms · delivery · line items",
                "kind": "write",
            },
            {
                "id": "price",
                "title": "Pricing & markdown",
                "sub": "auto moves capped ±15% · 25/40/60 ladder",
                "kind": "ai",
            },
        ],
        "gates": [
            {
                "id": "g_net",
                "after": "reorder",
                "label": "network stock?",
                "passes": "none free -> buy",
                "branches": [
                    {
                        "label": "another store has it",
                        "to": "transfer",
                        "style": "human",
                    }
                ],
            },
            {
                "id": "g_po",
                "after": "po",
                "label": "PO value?",
                "passes": "within buyer authority",
                "branches": [
                    {"label": "> $50k / > $250k", "to": "approvals", "style": "human"}
                ],
            },
        ],
        "rails": [
            {
                "id": "kb",
                "side": "left",
                "anchor": "supplier",
                "kind": "data",
                "title": "KB: inventory policy",
                "sub": "supplier SLA standards",
            },
            {
                "id": "transfer",
                "side": "right",
                "anchor": "g_net",
                "kind": "write",
                "title": "Inter-store transfer",
                "sub": "A-class stockout: expedite <= 4h",
            },
            {
                "id": "approvals",
                "side": "right",
                "anchor": "g_po",
                "kind": "human",
                "title": "Category manager / VP",
                "sub": "> $50k cat-mgr · > $250k VP",
            },
        ],
        "returns": [
            {
                "src": "price",
                "dst": "forecast",
                "label": "sell-through feeds next cycle",
                "channel": "left",
            }
        ],
        "footer": "Below-cost pricing needs margin sign-off · single-source SKUs "
        "need a qualified alternate or signed risk acceptance",
    },
    {
        "slug": "manufacturing-maintenance",
        "title": "Manufacturing — Sensor to Work Order",
        "tagline": "Predictive over reactive · no work order without permits · "
        "Zone D stops the machine",
        "stages": [
            {
                "id": "monitor",
                "title": "Condition monitoring",
                "sub": "health score · ISO 10816 zones A-D",
                "kind": "ai",
            },
            {
                "id": "diagnose",
                "title": "Diagnosis",
                "sub": "FFT bearing tones · anomalies · RUL",
                "kind": "ai",
            },
            {
                "id": "urgency",
                "title": "Urgency validation",
                "sub": "criticality x production impact",
                "kind": "ai",
            },
            {
                "id": "parts",
                "title": "Parts availability",
                "sub": "stock · lead time · alternatives",
                "kind": "ai",
            },
            {
                "id": "sched",
                "title": "Scheduling (permit-gated)",
                "sub": "LOTO · confined space · hot work",
                "kind": "compliance",
            },
            {
                "id": "wo",
                "title": "Work order execution",
                "sub": "tasks · parts · labor · safety steps",
                "kind": "write",
            },
            {
                "id": "kpi",
                "title": "Reliability KPIs",
                "sub": "OEE target 75% · reactive < 30%",
                "kind": "ai",
            },
        ],
        "gates": [
            {
                "id": "g_zone",
                "after": "diagnose",
                "label": "Zone D + high-crit?",
                "passes": "zones A-C: plan within window",
                "branches": [
                    {"label": "danger zone", "to": "stop", "style": "escalation"}
                ],
            },
            {
                "id": "g_parts",
                "after": "parts",
                "label": "parts cost?",
                "passes": "< $1k auto-issue",
                "branches": [{"label": ">= $1k", "to": "proc", "style": "human"}],
            },
        ],
        "rails": [
            {
                "id": "kb",
                "side": "left",
                "anchor": "sched",
                "kind": "data",
                "title": "KB: lockout-tagout policy",
                "sub": "maintenance standards (ISO 55000)",
            },
            {
                "id": "stop",
                "side": "right",
                "anchor": "g_zone",
                "kind": "escalation",
                "title": "Stop machine",
                "sub": "notify shift supervisor · same-shift WO",
            },
            {
                "id": "proc",
                "side": "right",
                "anchor": "g_parts",
                "kind": "human",
                "title": "Procurement approval",
                "sub": "order placed on sign-off",
            },
        ],
        "returns": [
            {
                "src": "kpi",
                "dst": "monitor",
                "label": "continuous improvement",
                "channel": "left",
            }
        ],
        "footer": "Deferred maintenance needs documented risk acceptance by the "
        "reliability manager · predictive triggers override calendar PMs",
    },
    {
        "slug": "real-estate-valuation",
        "title": "Real Estate — Subject Property to Value Range",
        "tagline": "Read-only advisory: zero transactional writes anywhere in "
        "this flow",
        "stages": [
            {
                "id": "subject",
                "title": "Subject property profile",
                "sub": "characteristics · zoning · tax history",
                "kind": "ai",
            },
            {
                "id": "comps",
                "title": "Comparable selection",
                "sub": "6-12 mo · 1 mile · ±25% GLA · adjust comp",
                "kind": "ai",
            },
            {
                "id": "approaches",
                "title": "Three approaches to value",
                "sub": "sales · income · cost — reconcile >= 2",
                "kind": "ai",
            },
            {
                "id": "cma",
                "title": "CMA report (USPAP)",
                "sub": "RANGE + confidence · never a point",
                "kind": "compliance",
            },
            {
                "id": "market",
                "title": "Market context",
                "sub": "DOM · months of supply · forecast",
                "kind": "ai",
            },
            {
                "id": "invest",
                "title": "Investment analysis",
                "sub": "cap rate · NOI · cash-on-cash · ROI",
                "kind": "ai",
            },
        ],
        "gates": [
            {
                "id": "g_fh",
                "after": "comps",
                "label": "steering request?",
                "passes": "objective criteria only",
                "branches": [
                    {
                        "label": "demographics as value factor",
                        "to": "refused",
                        "style": "escalation",
                    }
                ],
            },
            {
                "id": "g_bias",
                "after": "cma",
                "label": "bias challenge?",
                "passes": "none raised",
                "branches": [
                    {"label": "value challenged", "to": "second", "style": "human"}
                ],
            },
        ],
        "rails": [
            {
                "id": "mls",
                "side": "left",
                "anchor": "subject",
                "kind": "data",
                "title": "MLS · assessor · market data",
                "sub": "listings · parcels · tax rolls",
            },
            {
                "id": "kb",
                "side": "left",
                "anchor": "g_fh",
                "kind": "data",
                "title": "KB: fair-housing policy",
                "sub": "appraisal methodology guide",
            },
            {
                "id": "refused",
                "side": "right",
                "anchor": "g_fh",
                "kind": "escalation",
                "title": "Refused — Fair Housing",
                "sub": "even when the client requests it",
            },
            {
                "id": "second",
                "side": "right",
                "anchor": "g_bias",
                "kind": "human",
                "title": "Second independent valuation",
                "sub": "compliance review <= 10 days",
            },
        ],
        "returns": [
            {
                "src": "second",
                "dst": "approaches",
                "label": "re-run, independent",
                "channel": "far_right",
            }
        ],
        "footer": "An AVM/CMA is NOT a formal appraisal — stated in every report · "
        "lending/legal use requires a licensed appraiser",
    },
]


# --------------------------------------------------------------------------
# geometry: collision registry + checks
# --------------------------------------------------------------------------


def pretty(text):
    """Typography: ASCII operators -> unicode in display labels."""
    return (
        text.replace(" -> ", " \u2192 ").replace("<=", "\u2264").replace(">=", "\u2265")
    )


def esc(text):
    """XML-escape label text (& < > appear in business labels)."""
    text = pretty(text)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _ccw(a, b, c):
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def _segments_cross(p, q, a, b):
    """Proper crossing only; shared endpoints / collinear touches are allowed."""
    if p in (a, b) or q in (a, b):
        return False
    d1, d2 = _ccw(a, b, p), _ccw(a, b, q)
    d3, d4 = _ccw(p, q, a), _ccw(p, q, b)
    return ((d1 > 0) != (d2 > 0) and d1 != 0 and d2 != 0) and (
        (d3 > 0) != (d4 > 0) and d3 != 0 and d4 != 0
    )


def _seg_hits_rect(p, q, rect, shrink=3):
    """True if segment p-q enters rect (shrunk to tolerate border attaches)."""
    x, y, w, h = rect
    x0, y0, x1, y1 = x + shrink, y + shrink, x + w - shrink, y + h - shrink
    if x0 >= x1 or y0 >= y1:
        return False
    for pt in (p, q):
        if x0 < pt[0] < x1 and y0 < pt[1] < y1:
            return True
    corners = [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
    borders = [(corners[i], corners[(i + 1) % 4]) for i in range(4)]
    crossings = 0
    for a, b in borders:
        d1, d2 = _ccw(a, b, p), _ccw(a, b, q)
        d3, d4 = _ccw(p, q, a), _ccw(p, q, b)
        if (d1 > 0) != (d2 > 0) and (d3 > 0) != (d4 > 0):
            crossings += 1
    return crossings >= 2  # passes through the rect interior


def check_geometry(segments, rects):
    """segments: list of (points, src_id, dst_id, edge_name);
    rects: dict id -> (x, y, w, h). Returns list of violation strings."""
    flat = []
    for points, src, dst, name in segments:
        for i in range(len(points) - 1):
            flat.append((points[i], points[i + 1], src, dst, name))
    bad = []
    for i in range(len(flat)):
        for j in range(i + 1, len(flat)):
            p, q, _, _, n1 = flat[i]
            a, b, _, _, n2 = flat[j]
            if _segments_cross(p, q, a, b):
                bad.append(f"edge x edge: {n1} crosses {n2} ({p}-{q} vs {a}-{b})")
    for p, q, src, dst, name in flat:
        for rid, rect in rects.items():
            if rid in (src, dst):
                continue
            if _seg_hits_rect(p, q, rect):
                bad.append(f"edge x box: {name} passes through {rid}")
    return bad


# --------------------------------------------------------------------------
# svg primitives (house kit + grammar extensions)
# --------------------------------------------------------------------------


class Canvas:
    def __init__(self, w, h, title, tagline):
        self.parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="0 0 {w} {h}" '
            'font-family="ui-sans-serif, -apple-system, Helvetica, Arial">',
            f'<rect width="{w}" height="{h}" fill="{BG}"/>',
            f'<text x="40" y="44" fill="{TEXT}" font-size="21" '
            f'font-weight="700">{esc(title)}</text>',
            f'<text x="40" y="70" fill="{MUTED}" font-size="13">{esc(tagline)}</text>',
            '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" '
            'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{MUTED}"/></marker></defs>',
        ]
        self._n = 0
        self.segments = []  # (points, src_id, dst_id, name)
        self.rects = {}  # id -> (x, y, w, h)

    def _guard(self, text, width, px):
        assert len(text) * px <= width - 28, f"label too wide: {text!r}"

    def text(self, x, y, label, anchor="start", size=11, color=MUTED):
        self.parts.append(
            f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" '
            f'text-anchor="{anchor}">{esc(label)}</text>'
        )

    def chip(self, x, y, label, accent):
        a = ACCENTS[accent]
        w = 10 + len(label) * 6.4
        self.parts.append(
            f'<rect x="{x - w}" y="{y}" width="{w:.0f}" height="16" rx="8" '
            f'fill="{a}" opacity="0.18" stroke="{a}" stroke-width="0.8"/>'
            f'<text x="{x - w / 2:.0f}" y="{y + 11.5}" fill="{a}" font-size="9.5" '
            f'font-weight="700" text-anchor="middle">{label}</text>'
        )

    def node(self, nid, x, y, w, h, title, sub, kind, double=False):
        a = ACCENTS[KIND_ACCENT[kind]]
        self._guard(title, w, 7.4)
        if sub:
            self._guard(sub, w, 6.2)
        if double:
            self.parts.append(
                f'<rect x="{x - 4}" y="{y - 4}" width="{w + 8}" height="{h + 8}" '
                f'rx="12" fill="none" stroke="{a}" stroke-width="1" opacity="0.55"/>'
            )
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" '
            f'fill="{BOX}" stroke="{BORDER}" stroke-width="1.5"/>'
            f'<rect x="{x}" y="{y}" width="4" height="{h}" rx="2" fill="{a}"/>'
        )
        ty = y + (h // 2 - 2 if not sub else 28)
        self.parts.append(
            f'<text x="{x + 16}" y="{ty}" fill="{TEXT}" font-size="14.5" '
            f'font-weight="600">{esc(title)}</text>'
        )
        if sub:
            self.parts.append(
                f'<text x="{x + 16}" y="{ty + 18}" fill="{MUTED}" '
                f'font-size="11">{esc(sub)}</text>'
            )
        if kind in KIND_CHIP:
            label, accent = KIND_CHIP[kind]
            self.chip(x + w - 8, y + 8, label, accent)
        self.rects[nid] = (x, y, w, h)

    def diamond(self, nid, cx, cy, label):
        a = ACCENTS["amber"]
        d = GATE_HALF
        pts = f"{cx},{cy - d} {cx + d},{cy} {cx},{cy + d} {cx - d},{cy}"
        self.parts.append(
            f'<polygon points="{pts}" fill="{BOX}" stroke="{a}" stroke-width="1.6"/>'
        )
        self.parts.append(
            f'<text x="{cx - d - 10}" y="{cy - 12}" fill="{a}" font-size="11.5" '
            f'font-weight="600" text-anchor="end">{esc(label)}</text>'
        )
        self.rects[nid] = (cx - d, cy - d, 2 * d, 2 * d)

    def edge(
        self, points, src, dst, label="", label_at=0, delay=0.0, style="flow", dot=True
    ):
        self._n += 1
        pid = f"e{self._n}"
        color = ACCENTS["rose"] if style == "escalation" else MUTED
        dot_color = ACCENTS["rose"] if style == "escalation" else FLOW
        d = "M " + " L ".join(f"{x} {y}" for x, y in points)
        length = sum(
            math.hypot(points[i + 1][0] - points[i][0], points[i + 1][1] - points[i][1])
            for i in range(len(points) - 1)
        )
        self.parts.append(
            f'<path id="{pid}" d="{d}" stroke="{color}" stroke-width="1.5" '
            f'fill="none" marker-end="url(#arr)" stroke-dasharray="5 5">'
            '<animate attributeName="stroke-dashoffset" from="10" to="0" '
            'dur="0.9s" repeatCount="indefinite"/></path>'
        )
        if dot:
            dur = max(1.0, length / 110)
            self.parts.append(
                f'<circle r="3.2" fill="{dot_color}" opacity="0">'
                f'<animate attributeName="opacity" values="0;1;1;0" '
                f'keyTimes="0;0.08;0.92;1" dur="{dur:.2f}s" begin="{delay:.2f}s" '
                'repeatCount="indefinite"/>'
                f'<animateMotion dur="{dur:.2f}s" begin="{delay:.2f}s" '
                f'repeatCount="indefinite"><mpath href="#{pid}"/></animateMotion>'
                "</circle>"
            )
        if label:
            lx, ly = points[label_at]
            self.parts.append(
                f'<text x="{lx + 10}" y="{ly - 7}" fill="{MUTED}" '
                f'font-size="11">{esc(label)}</text>'
            )
        self.segments.append((points, src, dst, f"{src}->{dst}"))

    def legend(self, y):
        items = [
            ("AI", "blue", "AI-executed step"),
            ("HUMAN", "amber", "human approval gate"),
            ("COMPLIANCE", "rose", "compliance checkpoint"),
            ("WRITE", "green", "transactional action"),
            ("ESCALATION", "rose", "escalation path"),
            ("", "cyan", "systems / policy data"),
        ]
        x = 40
        for label, accent, desc in items:
            a = ACCENTS[accent]
            if label:
                w = 10 + len(label) * 6.4
                self.parts.append(
                    f'<rect x="{x}" y="{y}" width="{w:.0f}" height="16" rx="8" '
                    f'fill="{a}" opacity="0.18" stroke="{a}" stroke-width="0.8"/>'
                    f'<text x="{x + w / 2:.0f}" y="{y + 11.5}" fill="{a}" '
                    f'font-size="9.5" font-weight="700" '
                    f'text-anchor="middle">{label}</text>'
                )
                x += w + 6
            else:
                self.parts.append(
                    f'<rect x="{x}" y="{y + 2}" width="12" height="12" rx="3" '
                    f'fill="{a}" opacity="0.6"/>'
                )
                x += 18
            self.parts.append(
                f'<text x="{x}" y="{y + 12}" fill="{MUTED}" '
                f'font-size="11">{esc(desc)}</text>'
            )
            x += len(desc) * 6.2 + 24


# --------------------------------------------------------------------------
# layout + render
# --------------------------------------------------------------------------


def layout(flow):
    """Assign y positions. Returns (order, pos, spine_end_y) where pos maps
    element id -> dict(kind=stage|gate, y/cy, ...)."""
    gates_after = {g["after"]: g for g in flow["gates"]}
    order = []
    pos = {}
    y = 108
    for s in flow["stages"]:
        pos[s["id"]] = {"type": "stage", "y": y, "cy": y + STAGE_H // 2}
        order.append(("stage", s))
        y += STAGE_H + STAGE_GAP
        g = gates_after.get(s["id"])
        if g:
            cy = y - STAGE_GAP + GATE_PAD + GATE_HALF
            pos[g["id"]] = {"type": "gate", "cy": cy}
            order.append(("gate", g))
            y = cy + GATE_HALF + GATE_PAD + STAGE_GAP
    spine_end = y - STAGE_GAP
    # rails: anchor to element center, push down on collision per side
    last_bottom = {"left": 0, "right": 0}
    for r in flow["rails"]:
        anchor = pos[r["anchor"]]
        cy = anchor["cy"]
        ry = cy - RAIL_H // 2
        if ry < last_bottom[r["side"]] + 16:
            ry = last_bottom[r["side"]] + 16
        pos[r["id"]] = {
            "type": "rail",
            "y": ry,
            "cy": ry + RAIL_H // 2,
            "side": r["side"],
        }
        last_bottom[r["side"]] = ry + RAIL_H
    return order, pos, spine_end


def render_flow(flow):
    order, pos, spine_end = layout(flow)
    rail_end = max([pos[r["id"]]["y"] + RAIL_H for r in flow["rails"]] + [spine_end])
    H = int(rail_end + 96)
    c = Canvas(W, H, flow["title"], flow["tagline"])

    # spine boxes + diamonds
    for kind, el in order:
        if kind == "stage":
            p = pos[el["id"]]
            c.node(
                el["id"],
                SPINE_X,
                p["y"],
                SPINE_W,
                STAGE_H,
                el["title"],
                el["sub"],
                el["kind"],
                double=(el["kind"] == "compliance"),
            )
        else:
            c.diamond(el["id"], SPINE_CX, pos[el["id"]]["cy"], el["label"])

    # rail boxes
    for r in flow["rails"]:
        p = pos[r["id"]]
        x = LEFT_X if r["side"] == "left" else RIGHT_X
        w = LEFT_W if r["side"] == "left" else RIGHT_W
        c.node(r["id"], x, p["y"], w, RAIL_H, r["title"], r["sub"], r["kind"])

    # spine edges (stage -> stage/gate -> stage), staggered dots
    delay = 0.0
    for i in range(len(order) - 1):
        k1, e1 = order[i]
        k2, e2 = order[i + 1]
        y1 = (
            pos[e1["id"]]["y"] + STAGE_H
            if k1 == "stage"
            else pos[e1["id"]]["cy"] + GATE_HALF
        )
        y2 = pos[e2["id"]]["y"] if k2 == "stage" else pos[e2["id"]]["cy"] - GATE_HALF
        c.edge([(SPINE_CX, y1), (SPINE_CX, y2)], e1["id"], e2["id"], delay=delay)
        if k1 == "gate":
            c.text(SPINE_CX + 14, y1 + 16, e1.get("passes", ""))
        delay += 0.55

    # left-rail connectors (data feeds INTO the anchored element, no dot)
    for r in flow["rails"]:
        if r["side"] != "left":
            continue
        acy = pos[r["anchor"]]["cy"]
        rcy = pos[r["id"]]["cy"]
        x_attach = (
            SPINE_X if pos[r["anchor"]]["type"] == "stage" else SPINE_CX - GATE_HALF
        )
        if abs(acy - rcy) < 2:
            pts = [(LEFT_X + LEFT_W, rcy), (x_attach, acy)]
        else:
            midx = (LEFT_X + LEFT_W + x_attach) // 2
            pts = [(LEFT_X + LEFT_W, rcy), (midx, rcy), (midx, acy), (x_attach, acy)]
        c.edge(pts, r["id"], r["anchor"], dot=False)

    # gate branches (fan out right, request-flow trunk pattern)
    for g in flow["gates"]:
        gcy = pos[g["id"]]["cy"]
        start = (SPINE_CX + GATE_HALF, gcy)
        for bi, b in enumerate(g["branches"]):
            tcy = pos[b["to"]]["cy"]
            if bi == 0:
                pts = [start, (TRUNK_X, gcy)]
                if abs(tcy - gcy) > 2:
                    pts += [(TRUNK_X, tcy)]
                pts += [(RIGHT_X, tcy)]
            else:
                prev_cy = pos[g["branches"][bi - 1]["to"]]["cy"]
                pts = [(TRUNK_X, prev_cy), (TRUNK_X, tcy), (RIGHT_X, tcy)]
            c.edge(
                pts,
                g["id"],
                b["to"],
                delay=2.0 + bi * 0.4,
                style="escalation" if b["style"] == "escalation" else "flow",
            )
            if bi == 0:
                c.text(TRUNK_X - 6, gcy - 8, b["label"], anchor="end")
            else:
                c.text(TRUNK_X + 8, (prev_cy + tcy) / 2 + 4, b["label"])

    # returns via reserved channels
    for ret in flow["returns"]:
        scy = pos[ret["src"]]["cy"]
        dcy = pos[ret["dst"]]["cy"]
        if ret["channel"] == "far_right":
            pts = [
                (RIGHT_X + RIGHT_W, scy),
                (CH_RIGHT, scy),
                (CH_RIGHT, dcy),
                (SPINE_X + SPINE_W, dcy),
            ]
        else:
            pts = [
                (SPINE_X, scy),
                (CH_LEFT, scy),
                (CH_LEFT, dcy),
                (SPINE_X, dcy),
            ]
        c.edge(pts, ret["src"], ret["dst"], delay=3.2, style="escalation")
        mid_y = (scy + dcy) / 2
        # place the label at the first candidate y whose text band clears all boxes
        est_w = len(ret["label"]) * 6.4
        if ret["channel"] == "far_right":
            band_x = (CH_RIGHT - 8 - est_w, CH_RIGHT - 8)
        else:
            band_x = (CH_LEFT + 8, CH_LEFT + 8 + est_w)
        label_y = mid_y
        for cand in (
            mid_y,
            mid_y - 48,
            mid_y + 48,
            min(scy, dcy) + 30,
            max(scy, dcy) - 30,
        ):
            clear = all(
                not (
                    band_x[0] < rx + rw
                    and band_x[1] > rx
                    and cand - 12 < ry + rh
                    and cand > ry
                )
                for rx, ry, rw, rh in c.rects.values()
            )
            if clear:
                label_y = cand
                break
        if ret["channel"] == "far_right":
            c.text(CH_RIGHT - 8, label_y, ret["label"], anchor="end")
        else:
            c.text(CH_LEFT + 8, label_y, ret["label"])

    # legend + footer
    c.legend(rail_end + 22)
    c.parts.append(
        f'<text x="40" y="{H - 18}" fill="{MUTED}" '
        f'font-size="11.5">{esc(flow["footer"])}</text>'
    )
    c.parts.append("</svg>")

    violations = check_geometry(c.segments, c.rects)
    if violations:
        raise SystemExit(
            f"GEOMETRY FAIL in {flow['slug']}:\n  " + "\n  ".join(violations)
        )
    return "\n".join(p for p in c.parts if p)


# --------------------------------------------------------------------------
# mermaid emit (the editable logic source, pasted into business-flows.md)
# --------------------------------------------------------------------------


def mermaid(flow):
    lines = ["flowchart TD"]
    lines += [
        "    classDef ai fill:#1e293b,stroke:#3b82f6,color:#e2e8f0",
        "    classDef write fill:#1e293b,stroke:#22c55e,color:#e2e8f0",
        "    classDef compliance fill:#1e293b,stroke:#f43f5e,color:#e2e8f0",
        "    classDef human fill:#1e293b,stroke:#f59e0b,color:#e2e8f0",
        "    classDef escalation fill:#3f1d2b,stroke:#f43f5e,color:#fecdd3",
        "    classDef data fill:#164e63,stroke:#06b6d4,color:#e2e8f0",
        "    classDef gate fill:#1e293b,stroke:#f59e0b,color:#fcd34d",
    ]
    gates_after = {g["after"]: g for g in flow["gates"]}
    chain = []
    for s in flow["stages"]:
        chain.append(("stage", s))
        if s["id"] in gates_after:
            chain.append(("gate", gates_after[s["id"]]))
    for kind, el in chain:
        if kind == "stage":
            lines.append(
                f'    {el["id"]}["{pretty(el["title"])} — {pretty(el["sub"])}"]:::{el["kind"]}'
            )
        else:
            lines.append(f'    {el["id"]}{{"{el["label"]}"}}:::gate')
    for r in flow["rails"]:
        if r["side"] == "right":
            style = (
                r["kind"] if r["kind"] in ("human", "escalation", "write") else "human"
            )
            lines.append(
                f'    {r["id"]}["{pretty(r["title"])} — {pretty(r["sub"])}"]:::{style}'
            )
        else:
            lines.append(f'    {r["id"]}[("{r["title"]}")]:::data')
    for i in range(len(chain) - 1):
        k1, e1 = chain[i]
        _, e2 = chain[i + 1]
        if k1 == "gate":
            lines.append(f'    {e1["id"]} -->|"{pretty(e1["passes"])}"| {e2["id"]}')
        else:
            lines.append(f'    {e1["id"]} --> {e2["id"]}')
    for g in flow["gates"]:
        for b in g["branches"]:
            lines.append(f'    {g["id"]} -->|"{pretty(b["label"])}"| {b["to"]}')
    for r in flow["rails"]:
        if r["side"] == "left":
            lines.append(f'    {r["id"]} -.-> {r["anchor"]}')
    for ret in flow["returns"]:
        lines.append(f'    {ret["src"]} -->|"{pretty(ret["label"])}"| {ret["dst"]}')
    return "\n".join(lines)


def main():
    here = Path(__file__).parent
    if "--mermaid" in sys.argv:
        for flow in FLOWS:
            print(f"===== {flow['slug']} =====")
            print(mermaid(flow))
        return
    for flow in FLOWS:
        svg = render_flow(flow)
        out = here / f"{flow['slug']}.svg"
        out.write_text(svg)
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
