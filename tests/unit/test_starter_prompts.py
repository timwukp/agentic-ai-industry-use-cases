"""The AI Assistant's starter questions must stay grounded in the real tools.

These prompts are the first thing a visitor clicks, so a stale entity id or an
enum the handler rejects is a broken front door. Two ways they rot:

1. A prompt names an id that does not exist. The bases fall back to synthetic
   data for unknown ids (``sku_basis("SKU-1001")`` happily returns "Product
   1001"), so nothing errors — the agent just answers about a product that
   appears nowhere else in the app. Only a membership check catches that.
2. A prompt names an enum value the handler rejects. "improve margin" reads
   fine and makes the agent call ``optimize_pricing(objective="margin")``,
   which returns ``{"error": "Invalid objective: margin"}``. Found exactly this
   while writing the prompts.

So the ids are asserted against the shared catalogs, and every enum literal a
prompt states is asserted against the handler's own accepted set. This parses
the TypeScript rather than duplicating the prompt list: a copy here would drift
silently, which is the failure mode the test exists to prevent.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
STARTERS_TS = REPO / "web" / "src" / "industries" / "starterPrompts.ts"
REGISTRY_TS = REPO / "web" / "src" / "industries" / "registry.ts"

sys.path.insert(0, str(REPO / "tools" / "shared"))


def _load(rel, name):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _starters():
    """{industryId: [(label, prompt)]} parsed out of starterPrompts.ts.

    The file is hand-maintained TS, not JSON, so this walks the `STARTER_PROMPTS`
    object literal with a brace counter rather than pretending a regex can nest.
    """
    text = STARTERS_TS.read_text()
    start = text.index("export const STARTER_PROMPTS")
    body = text[text.index("{", start) :]
    depth, end = 0, None
    for i, ch in enumerate(body):
        depth += (ch == "{") - (ch == "}")
        if depth == 0:
            end = i
            break
    assert end is not None, "unbalanced braces in STARTER_PROMPTS"
    body = body[: end + 1]

    out, current = {}, None
    for line in body.splitlines():
        key = re.match(r"\s*'?([a-z-]+)'?:\s*\[", line)
        if key:
            current = key.group(1)
            out[current] = []
            continue
        # Both quote styles: a label with an apostrophe ("Dr. Chen's openings")
        # is written with double quotes, and a single-quote-only pattern dropped
        # it silently — the parse looked healthy at 4 starters when the file had 5.
        label = re.match(r"""\s*label:\s*['"](.+?)['"],?\s*$""", line)
        if label and current:
            out[current].append([label.group(1), None])
            continue
        # prompt: may be on its own line or wrapped onto the next
        prompt = re.match(r"""\s*prompt:\s*$|\s*prompt:\s*['"](.*?)['"],?\s*$""", line)
        if prompt and current and out[current]:
            if prompt.group(1) is not None:
                out[current][-1][1] = prompt.group(1)
            continue
        cont = re.match(r"""\s*['"](.+?)['"],?\s*$""", line)
        if cont and current and out[current] and out[current][-1][1] is None:
            out[current][-1][1] = cont.group(1)
    return {k: [(a, b) for a, b in v] for k, v in out.items()}


@pytest.fixture(scope="module")
def starters():
    parsed = _starters()
    # Guard the parser itself: an empty or half-read dict would make every
    # assertion below vacuously pass, which is the whole point of these tests.
    assert len(parsed) == 6, f"parsed {len(parsed)} industries, expected 6"
    for industry, items in parsed.items():
        assert items, f"{industry}: parsed zero starters"
        for label, prompt in items:
            assert prompt, f"{industry}/{label}: prompt did not parse"

    # Count against the file, not just against itself. A regex that silently skips
    # an entry leaves a plausible-looking dict — this actually happened: a
    # single-quote-only label pattern dropped "Dr. Chen's openings" and the parse
    # reported 4 healthcare starters for a file containing 5.
    declared = len(re.findall(r"""^\s*label:\s*['"]""", STARTERS_TS.read_text(), re.M))
    assert sum(len(v) for v in parsed.values()) == declared, (
        f"parsed {sum(len(v) for v in parsed.values())} starters but the file "
        f"declares {declared} — the parser is dropping entries"
    )
    return parsed


# --------------------------------------------------------------------------
# every industry in the registry gets starters, and vice versa
# --------------------------------------------------------------------------


def test_every_registry_industry_has_starters(starters):
    ids = set(re.findall(r"^\s*id: '([a-z-]+)',", REGISTRY_TS.read_text(), re.M))
    assert ids, "parsed no industry ids out of registry.ts"
    assert ids == set(
        starters
    ), f"registry ids {sorted(ids)} != starter keys {sorted(starters)}"


def test_starters_are_a_usable_number(starters):
    for industry, items in starters.items():
        assert 3 <= len(items) <= 5, f"{industry}: {len(items)} starters"
        labels = [label for label, _ in items]
        assert len(set(labels)) == len(labels), f"{industry}: duplicate labels"
        for label, prompt in items:
            # Labels are scanned in a ~340px column; long ones wrap and the
            # card loses its one-line-scan property.
            assert len(label) <= 24, f"{industry}/{label}: label too long"
            assert prompt.endswith(("?", ".")), f"{industry}/{label}: unpunctuated"


# --------------------------------------------------------------------------
# every id a prompt names must exist in the shared catalogs
# --------------------------------------------------------------------------


def _all_prompts(starters):
    return [
        (industry, label, prompt)
        for industry, items in starters.items()
        for label, prompt in items
    ]


def test_prompt_skus_are_real_catalog_skus(starters):
    from toolkit.retail_basis import CATALOG_BY_SKU

    found = 0
    for industry, label, prompt in _all_prompts(starters):
        for sku in re.findall(r"SKU-[A-Z0-9-]+", prompt):
            found += 1
            assert sku in CATALOG_BY_SKU, (
                f"{industry}/{label}: {sku} is not in the catalog — the basis "
                f"would invent a synthetic product for it"
            )
    assert found >= 2, f"only {found} SKUs checked; parser likely missed prompts"


def test_prompt_equipment_ids_are_real_assets(starters):
    from toolkit.asset_basis import CRITICALITY

    found = 0
    for industry, label, prompt in _all_prompts(starters):
        for eq in re.findall(r"EQ-[A-Z]+-\d+", prompt):
            found += 1
            assert eq in CRITICALITY, f"{industry}/{label}: {eq} not in the fleet"
    assert found >= 2, f"only {found} equipment ids checked"


def test_prompt_zipcodes_are_offered_markets(starters):
    markets = set(
        re.findall(
            r"zipcode: '(\d{5})'",
            (REPO / "web" / "src")
            .joinpath("industries", "realestate", "types.ts")
            .read_text(),
        )
    )
    assert markets, "parsed no markets out of realestate/types.ts"
    found = 0
    for industry, label, prompt in _all_prompts(starters):
        if industry != "real-estate-valuation":
            continue
        for zipcode in re.findall(r"\b(\d{5})\b", prompt):
            found += 1
            assert zipcode in markets, f"{label}: {zipcode} is not a MARKETS entry"
    assert found >= 2, f"only {found} zipcodes checked"


def test_prompt_provider_ids_are_real_providers(starters):
    src = (
        (REPO / "web" / "src" / "industries" / "healthcare")
        .joinpath("SchedulingSection.tsx")
        .read_text()
    )
    providers = set(re.findall(r"id: '([A-Z]{2}-[A-Z]+)'", src))
    assert providers, "parsed no providers out of SchedulingSection.tsx"
    found = 0
    for industry, label, prompt in _all_prompts(starters):
        for pid in re.findall(r"\b(?:DR|NP)-[A-Z]+\b", prompt):
            found += 1
            assert pid in providers, f"{industry}/{label}: {pid} is not a provider"
    assert found >= 1, "no provider ids checked"


def test_prompt_patient_ids_resolve(starters):
    analytics = _load("tools/healthcare/analytics/handler.py", "hc_analytics")
    found = 0
    for industry, label, prompt in _all_prompts(starters):
        for pid in re.findall(r"PT-\d+", prompt):
            found += 1
            result = analytics.get_care_gap_analysis(pid)
            assert "error" not in result, f"{industry}/{label}: {pid} -> {result}"
    assert found >= 2, f"only {found} patient ids checked"


def test_prompt_finance_symbols_are_simulated(starters):
    from toolkit.market_sim import BASE_PRICES

    # Only all-caps standalone tickers; skip words like VaR that survive a
    # naive [A-Z]{2,5} match. NON_TICKERS: product/model names the prompts
    # legitimately mention that must not be mistaken for symbols.
    non_tickers = {"PRISM"}
    for industry, label, prompt in _all_prompts(starters):
        if industry != "finance":
            continue
        for word in re.findall(r"\b([A-Z]{3,5})\b", prompt):
            if word in non_tickers:
                continue
            assert word in BASE_PRICES, f"{label}: {word} is not a simulated symbol"


# --------------------------------------------------------------------------
# every enum literal a prompt states must be one the handler accepts
# --------------------------------------------------------------------------


def test_stated_enums_are_accepted_by_the_handler(starters):
    """A prompt that names an argument value must name a valid one.

    `optimize_pricing` is the case that bit: the handler returns the valid set in
    its error, so this asserts against the handler rather than a copied list.
    """
    pricing = _load("tools/retail/pricing/handler.py", "rt_pricing")
    prompts = {label: prompt for _, label, prompt in _all_prompts(starters)}
    stated = [
        (sku, objective)
        for prompt in prompts.values()
        for sku, objective in re.findall(
            r"pricing for (SKU-[A-Z0-9-]+) with the objective (\w+)", prompt
        )
    ]
    assert stated, "no objective-stating prompt found; did the wording change?"
    for sku, objective in stated:
        result = pricing.optimize_pricing(sku, objective)
        assert "error" not in result, f"{sku}/{objective} -> {result}"


# --------------------------------------------------------------------------
# the prompts actually return data — a starter that errors is a broken door
# --------------------------------------------------------------------------


TOOL_CALLS = [
    ("finance", "tools/finance/market_data/handler.py", "get_market_overview", ()),
    ("finance", "tools/finance/market_data/handler.py", "get_sector_performance", ()),
    ("finance", "tools/finance/market_data/handler.py", "get_stock_quote", ("NVDA",)),
    ("finance", "tools/finance/risk/handler.py", "calculate_var", (250000,)),
    ("finance", "tools/finance/risk/handler.py", "stress_test_portfolio", (250000,)),
    (
        "healthcare",
        "tools/healthcare/clinical/handler.py",
        "check_drug_interactions",
        (json.dumps(["metformin", "lisinopril", "atorvastatin"]),),
    ),
    (
        "healthcare",
        "tools/healthcare/analytics/handler.py",
        "get_readmission_risk",
        ("PT-1001",),
    ),
    (
        "healthcare",
        "tools/healthcare/analytics/handler.py",
        "get_population_health_metrics",
        (),
    ),
    (
        "healthcare",
        "tools/healthcare/scheduling/handler.py",
        "get_provider_availability",
        ("DR-CHEN",),
    ),
    ("insurance", "tools/insurance/claims/handler.py", "list_claims", ()),
    (
        "insurance",
        "tools/insurance/fraud_detection/handler.py",
        "get_fraud_dashboard",
        (),
    ),
    (
        "insurance",
        "tools/insurance/policy/handler.py",
        "verify_policy",
        ("POL-2024-118273",),
    ),
    (
        "insurance",
        "tools/insurance/policy/handler.py",
        "check_coverage",
        ("POL-2024-118273", "home", 25000),
    ),
    (
        "insurance",
        "tools/insurance/settlement/handler.py",
        "get_settlement_analytics",
        (),
    ),
    ("retail", "tools/retail/inventory/handler.py", "get_stockout_report", ()),
    (
        "retail",
        "tools/retail/demand_forecast/handler.py",
        "forecast_demand",
        ("SKU-ELEC-1001", 30),
    ),
    ("retail", "tools/retail/demand_forecast/handler.py", "get_abc_analysis", ()),
    (
        "retail",
        "tools/retail/supplier/handler.py",
        "get_supplier_performance",
        ("SUP-100",),
    ),
    (
        "manufacturing",
        "tools/manufacturing/equipment/handler.py",
        "get_equipment_alerts",
        (),
    ),
    (
        "manufacturing",
        "tools/manufacturing/prediction/handler.py",
        "predict_failure",
        ("EQ-TURB-001",),
    ),
    (
        "manufacturing",
        "tools/manufacturing/prediction/handler.py",
        "analyze_vibration",
        ("EQ-CNC-001",),
    ),
    (
        "manufacturing",
        "tools/manufacturing/maintenance/handler.py",
        "get_maintenance_calendar",
        (),
    ),
    (
        "realestate",
        "tools/realestate/market/handler.py",
        "get_market_conditions",
        ("78701",),
    ),
    (
        "realestate",
        "tools/realestate/market/handler.py",
        "get_market_forecast",
        ("78701", 12),
    ),
    (
        "realestate",
        "tools/realestate/valuation/handler.py",
        "generate_cma_report",
        ("1200 Oak Dr, 78701",),
    ),
    (
        "realestate",
        "tools/realestate/property/handler.py",
        "search_properties",
        (json.dumps({"zipcode": "78701", "beds_min": 3}),),
    ),
]


@pytest.mark.parametrize(
    "industry,module_path,fn_name,args",
    TOOL_CALLS,
    ids=[f"{i}.{f}" for i, _, f, _ in TOOL_CALLS],
)
def test_starter_tool_path_returns_data(industry, module_path, fn_name, args):
    module = _load(module_path, f"{industry}_{fn_name}")
    result = getattr(module, fn_name)(*args)
    assert isinstance(result, dict), f"{fn_name} returned {type(result)}"
    assert "error" not in result, f"{fn_name}{args} -> {result.get('error')}"

    # A payload of nothing but {"source": "simulated"} plus the echoed argument
    # would satisfy "no error" while answering nothing. Counting keys is the
    # wrong measure — get_sector_performance legitimately returns one rich list
    # plus `source`. What matters is that something beyond the boilerplate
    # carries content.
    boilerplate = {"source", "as_of", "analysis_date", *(str(a) for a in args)}
    substantive = {
        key: value
        for key, value in result.items()
        if key not in boilerplate and str(value) not in boilerplate
    }
    assert substantive, f"{fn_name} returned only boilerplate: {result}"
    assert any(
        (isinstance(v, (list, dict)) and len(v) > 0) or isinstance(v, (int, float))
        for v in substantive.values()
    ), f"{fn_name} returned no populated field: {result}"


# --------------------------------------------------------------------------
# a starter question must get the *right* answer, not merely a non-error one
# --------------------------------------------------------------------------


def test_drug_interactions_match_regardless_of_case():
    """The "Check interactions" starter question names its drugs in lowercase.

    ``INTERACTION_DB`` is keyed on capitalized names, so a case-sensitive lookup
    answered "LOW - No significant interactions detected in the reference
    database" for metformin + lisinopril — a pair that database does hold. The
    parametrized check above passed throughout: the payload had no ``error`` key
    and plenty of populated fields. It was simply wrong, which is the worse
    failure for a clinical tool, and it also left the chart panel blank because
    an all-zero severity summary has nothing to plot.
    """
    clinical = _load("tools/healthcare/clinical/handler.py", "clinical_case")

    pairs = [
        (["metformin", "lisinopril"], "minor"),
        (["warfarin", "aspirin"], "major"),
        (["lisinopril", "potassium"], "moderate"),
    ]
    for meds, severity in pairs:
        for variant in (meds, [m.title() for m in meds], [m.upper() for m in meds]):
            result = clinical.check_drug_interactions(json.dumps(variant))
            assert result["interactions_found"] == 1, f"{variant} -> {result}"
            assert result["severity_summary"][severity] == 1, f"{variant} -> {result}"
            # The reply echoes the names the user typed, not the database's.
            assert result["interactions"][0]["medication_pair"] == variant

    # Reversed order must match too — the pair is unordered clinically.
    reversed_result = clinical.check_drug_interactions(
        json.dumps(["aspirin", "Warfarin"])
    )
    assert reversed_result["severity_summary"]["major"] == 1

    # And a genuinely clean list must still come back clean, or the fix would be
    # matching everything.
    clean = clinical.check_drug_interactions(json.dumps(["metformin", "atorvastatin"]))
    assert clean["interactions_found"] == 0
    assert clean["overall_risk"].startswith("LOW")


def test_overall_risk_sentence_agrees_with_the_interaction_list():
    """``overall_risk`` is the sentence the agent quotes, so it cannot contradict
    the list beside it.

    With the case fix in place, metformin + lisinopril returned one minor
    interaction *and* "LOW - No significant interactions detected in the
    reference database" — the tool disagreeing with itself in the same payload.
    """
    clinical = _load("tools/healthcare/clinical/handler.py", "clinical_risk")

    cases = [
        (["metformin", "atorvastatin"], 0, "no significant"),
        (["metformin", "lisinopril"], 1, "minor interaction"),
        (["lisinopril", "potassium"], 1, "moderate"),
        (["warfarin", "aspirin"], 1, "major"),
    ]
    for meds, expected, phrase in cases:
        result = clinical.check_drug_interactions(json.dumps(meds))
        assert result["interactions_found"] == expected, f"{meds} -> {result}"
        assert (
            phrase in result["overall_risk"].lower()
        ), f"{meds} -> {result['overall_risk']}"
        # "No significant interactions" must never appear alongside a populated
        # list, in either direction.
        says_none = "no significant" in result["overall_risk"].lower()
        assert says_none == (result["interactions_found"] == 0), (
            f"{meds}: overall_risk {result['overall_risk']!r} contradicts "
            f"{result['interactions_found']} interaction(s)"
        )
        assert sum(result["severity_summary"].values()) == result["interactions_found"]


def test_starter_interaction_prompt_names_a_flagged_pair():
    """The prompt's own drug names must be a pair the database actually flags.

    Otherwise the starter question demonstrates the feature by showing nothing —
    which is what the live app did, and what the E2E chart census caught.
    """
    clinical = _load("tools/healthcare/clinical/handler.py", "clinical_prompt")
    prompts = _starters()["healthcare-medical"]
    matching = [p for _, p in prompts if "interaction" in p.lower()]
    assert matching, "no interaction starter prompt found; did the wording change?"

    known = {name.casefold() for pair in clinical.INTERACTION_DB for name in pair}
    for prompt in matching:
        named = [d for d in known if re.search(rf"\b{re.escape(d)}\b", prompt.lower())]
        assert len(named) >= 2, (
            f"{prompt!r} names {named} from the interaction database; a starter "
            "question needs at least two so a real interaction surfaces"
        )
        result = clinical.check_drug_interactions(json.dumps(named))
        assert result["interactions_found"] >= 1, f"{prompt!r} -> {result}"
