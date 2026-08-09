"""CAMEO -> factor mapping for GDELT 1.0 historical factor proxies — FROZEN.

Maps GDELT event root codes (CAMEO taxonomy) and actor country codes to our
13-factor taxonomy. Fixed before any data was extracted; editing after the
`study-preregistered` tag invalidates Track A1 claims.

HONEST COVERAGE STATEMENT (part of the pre-registration):
Only the factors listed in CAMEO_FACTORS are mappable from CAMEO event
codes. The six sector factors in UNMAPPABLE have no CAMEO representation —
they are validated only via Track A2 (GDELT 2.0 GKG themes, 2015+) and
Track B (event studies). Any claim that Track A1 validates "the 13 factors"
would be false; it validates at most these seven.
"""

# CAMEO root codes: 01-05 cooperation, 06-09 material cooperation/aid,
# 10-14 demands/protests, 15-17 coercion, 18-20 assault/fight/mass violence.

CAMEO_FACTORS = {
    "war-conflict": {
        # kinetic conflict events, any actors
        "root_codes": ["18", "19", "20"],
        "actor_filter": None,
    },
    "us-china": {
        # any event class between US and CHN actors — intensity carried by
        # Goldstein scale, not code class
        "root_codes": None,
        "actor_filter": ("USA", "CHN"),
    },
    "us-policy": {
        # government policy events with US as actor1
        "root_codes": ["02", "03", "04", "05", "10", "11", "12"],
        "actor_filter": ("USA", None),
    },
    "china-policy": {
        "root_codes": ["02", "03", "04", "05", "10", "11", "12"],
        "actor_filter": ("CHN", None),
    },
    "energy-supply": {
        # coercion/conflict events involving major oil producers
        "root_codes": ["13", "14", "15", "16", "17", "18", "19", "20"],
        "actor_filter": (
            ["SAU", "IRN", "IRQ", "KWT", "VEN", "RUS", "LBY", "ARE", "QAT"],
            None,
        ),
    },
    "fed-policy": {
        # WEAK proxy: US government economic consultation/policy events;
        # CAMEO cannot distinguish the Fed from other US agencies. Flagged
        # weak in the protocol; H5 conclusions for this factor are caveated.
        "root_codes": ["01", "02", "03", "04"],
        "actor_filter": ("USAGOV", None),
    },
    "economic-cycle": {
        # POOR proxy: economic cooperation/aid event counts as a cycle
        # activity proxy. Retained only for completeness; pre-registered as
        # lowest-confidence mapping.
        "root_codes": ["06", "07", "08"],
        "actor_filter": None,
    },
}

UNMAPPABLE = [
    "shipping-logistics",
    "aviation",
    "tech-supply-chain",
    "semiconductors",
    "precious-metals",
    "rare-earths",
]

# Aggregates computed per factor per day from matching events:
# n_events, mean Goldstein scale (conflict-cooperation intensity, -10..+10,
# sign FLIPPED so higher = more conflictual, matching our loading semantics),
# mean AvgTone (negated likewise).
AGG_SPEC = {
    "count": "n_events",
    "goldstein": "mean_goldstein_neg",
    "tone": "mean_tone_neg",
}
