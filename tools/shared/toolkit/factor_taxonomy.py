"""Geopolitical/macro factor taxonomy — versioned, shared by the news
collector (scoring prompt + GDELT queries) and the macro-signals tools
(payload metadata).

Every factor loading derived from news is HYPOTHESIS-grade until the Phase 3
validation protocol (out-of-sample + multiple-testing control) confirms a
regularity; payloads must carry grade="hypothesis" until then.

Bump TAXONOMY_VERSION whenever factors are added/renamed/redefined — factor
time series across a version change are not comparable and the modeling layer
must not mix them.
"""

TAXONOMY_VERSION = "2026-08-09.1"

# factor id -> (display label, description for the scoring model, GDELT query)
FACTORS = {
    "energy-supply": (
        "Energy Supply",
        "Oil/gas production, OPEC decisions, pipelines, embargoes, outages "
        "affecting global energy supply",
        '(OPEC OR "oil supply" OR "oil production" OR pipeline OR "gas supply")',
    ),
    "shipping-logistics": (
        "Shipping & Logistics",
        "Container shipping, ports, canals (Suez/Panama), freight rates, "
        "chokepoints, blockades",
        '("container shipping" OR "Suez Canal" OR "Panama Canal" OR "freight rates" OR "Red Sea shipping")',
    ),
    "aviation": (
        "Aviation",
        "Airlines, airspace closures, jet fuel, aircraft supply chain "
        "(Boeing/Airbus), air cargo",
        '(airline OR "airspace closure" OR "jet fuel" OR Boeing OR Airbus)',
    ),
    "us-china": (
        "US-China Relations",
        "Tariffs, export controls, sanctions, diplomacy, tensions between "
        "the United States and China",
        '("US China" AND (tariff OR "export control" OR sanction OR trade))',
    ),
    "war-conflict": (
        "War & Conflict",
        "Armed conflicts, military escalation, regional wars — score higher "
        "magnitude when oil supply routes or producers are involved",
        '(war OR invasion OR "military strike" OR ceasefire) AND (oil OR energy OR strait)',
    ),
    "us-policy": (
        "US Policy",
        "US fiscal policy, major legislation, regulation, government "
        "shutdowns, debt ceiling, elections",
        '("White House" OR Congress) AND (policy OR legislation OR "debt ceiling" OR shutdown)',
    ),
    "fed-policy": (
        "Fed Policy",
        "Federal Reserve rate decisions, QT/QE, dot plot, Fed speakers, "
        "inflation expectations",
        '("Federal Reserve" OR FOMC OR Powell) AND (rate OR inflation OR policy)',
    ),
    "china-policy": (
        "China Policy",
        "PBoC/Beijing policy: stimulus, property sector, regulation "
        "crackdowns, capital controls, yuan",
        '(China AND (stimulus OR PBOC OR "property sector" OR regulation OR yuan))',
    ),
    "tech-supply-chain": (
        "Tech Supply Chain",
        "Electronics/hardware supply chains, component shortages, factory "
        "disruptions, tech manufacturing relocation",
        '("supply chain" AND (semiconductor OR electronics OR component OR factory))',
    ),
    "semiconductors": (
        "Semiconductors",
        "Chip makers (TSMC/Nvidia/Samsung), fab capacity, chip export "
        "controls, AI hardware demand",
        '(semiconductor OR TSMC OR Nvidia OR "chip export" OR fab)',
    ),
    "precious-metals": (
        "Precious Metals",
        "Gold/silver demand, central bank buying, safe-haven flows",
        '(gold AND ("central bank" OR "safe haven" OR bullion OR demand))',
    ),
    "rare-earths": (
        "Rare Earths",
        "Rare earth elements supply/demand, export restrictions, mining, "
        "processing capacity (no free official price series exists — this "
        "factor is news-derived only)",
        '("rare earth" AND (export OR mining OR supply OR restriction))',
    ),
    "economic-cycle": (
        "Economic Cycle",
        "Recession signals, PMI, employment, consumer demand, credit "
        "conditions, business cycle turning points",
        '(recession OR PMI OR "jobs report" OR "consumer spending" OR "credit conditions")',
    ),
}
