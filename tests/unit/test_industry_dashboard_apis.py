"""dashboard_api routes for insurance / retail / manufacturing / realestate.

Each industry's Lambda bundle is staged exactly the way
infra/cdk/stacks/industry_stack.py::_stage does it (handler.py + toolkit/ +
aliased tool handlers), so an import that only works because of a repo-relative
path would fail here the same way it would fail in Lambda.

The alias maps below must stay in sync with DASHBOARD_MODULES in
infra/cdk/app.py — test_alias_maps_match_cdk asserts that mechanically.
"""

import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "tools"

ALIASES = {
    "insurance": {
        "claims_tools": "claims",
        "fraud_tools": "fraud_detection",
        "settlement_tools": "settlement",
    },
    "retail": {
        "inventory_tools": "inventory",
        "forecast_tools": "demand_forecast",
        "pricing_tools": "pricing",
        "supplier_tools": "supplier",
    },
    "manufacturing": {
        "equipment_tools": "equipment",
        "prediction_tools": "prediction",
        "maintenance_tools": "maintenance",
        "parts_tools": "parts",
    },
    "realestate": {
        "market_tools": "market",
        "property_tools": "property",
        "valuation_tools": "valuation",
    },
}


def _stage_handler(industry, bundle):
    src = TOOLS / industry
    shutil.copy(src / "dashboard_api" / "handler.py", bundle / "handler.py")
    shutil.copytree(TOOLS / "shared" / "toolkit", bundle / "toolkit")
    for alias, d in ALIASES[industry].items():
        shutil.copy(src / d / "handler.py", bundle / f"{alias}.py")
    names = ["handler", "toolkit", *ALIASES[industry]]
    sys.path.insert(0, str(bundle))
    try:
        for name in list(sys.modules):
            if name in names or name.startswith("toolkit."):
                sys.modules.pop(name, None)
        return importlib.import_module("handler")
    finally:
        sys.path.pop(0)


@pytest.fixture
def handler(request, tmp_path):
    """Parameterized by industry name via indirect fixture request."""
    industry = request.param
    return _stage_handler(industry, tmp_path)


def _get(handler, route, params=None):
    resp = handler.lambda_handler(
        {"routeKey": route, "queryStringParameters": params or {}}, None
    )
    return resp["statusCode"], json.loads(resp["body"])


# --------------------------------------------------------------------------
# alias map / route map parity with the CDK app (a drifting alias would make
# the bundle import-error at cold start, which no other test would catch)
# --------------------------------------------------------------------------


def _cdk_app_namespace():
    import ast

    tree = ast.parse((REPO / "infra" / "cdk" / "app.py").read_text())
    wanted = {"DASHBOARD_MODULES", "DASHBOARD_ROUTES", "INDUSTRIES"}
    out = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and getattr(node.targets[0], "id", "") in wanted
        ):
            out[node.targets[0].id] = ast.literal_eval(node.value)
    return out


def test_alias_maps_match_cdk():
    cdk = _cdk_app_namespace()["DASHBOARD_MODULES"]
    for industry, aliases in ALIASES.items():
        assert cdk[industry] == aliases, f"{industry} alias map drifted from app.py"


@pytest.mark.parametrize("industry", sorted(ALIASES))
def test_every_declared_route_is_handled(industry, tmp_path):
    """Each path in DASHBOARD_ROUTES must return non-404 from the handler."""
    routes = _cdk_app_namespace()["DASHBOARD_ROUTES"][industry]
    handler = _stage_handler(industry, tmp_path)
    required = {
        "claim": {"claimId": "CLM-2026-0001"},
        "equipment": {"equipmentId": "EQ-100"},
        "sensor": {"equipmentId": "EQ-100"},
        "comparables": {"address": "500 Congress Ave, Austin TX"},
    }
    for path in routes:
        status, body = _get(
            handler, f"GET /api/{industry}/{path}", required.get(path, {})
        )
        assert status == 200, f"{industry}/{path} -> {status} {body}"
        assert body, f"{industry}/{path} returned an empty body"


@pytest.mark.parametrize("industry", sorted(ALIASES))
def test_unknown_route_is_404(industry, tmp_path):
    handler = _stage_handler(industry, tmp_path)
    status, body = _get(handler, f"GET /api/{industry}/nope")
    assert status == 404
    assert "Unknown route" in body["error"]


@pytest.mark.parametrize("industry", sorted(ALIASES))
def test_payloads_are_deterministic(industry, tmp_path):
    """Same request twice -> identical body (dashboard must match chat)."""
    handler = _stage_handler(industry, tmp_path)
    path = _cdk_app_namespace()["DASHBOARD_ROUTES"][industry][0]
    first = _get(handler, f"GET /api/{industry}/{path}")
    second = _get(handler, f"GET /api/{industry}/{path}")
    assert first == second


# --------------------------------------------------------------------------
# per-industry shape assertions — these pin the exact keys the frontend reads,
# so a tool refactor that renames a key fails here instead of rendering blanks
# --------------------------------------------------------------------------


@pytest.mark.parametrize("handler", ["insurance"], indirect=True)
def test_insurance_overview_shape(handler):
    _, body = _get(handler, "GET /api/insurance/overview")
    assert {"metrics", "top_fraud_types", "trend"} <= set(body["fraud"])
    assert body["fraud"]["metrics"]["detection_rate_pct"] > 0
    assert {"kpis", "by_claim_type", "trend"} <= set(body["settlement"])
    assert body["settlement"]["kpis"]["total_settlements"] > 0


@pytest.mark.parametrize("handler", ["insurance"], indirect=True)
def test_insurance_claims_queue_has_rows(handler):
    _, body = _get(handler, "GET /api/insurance/claims", {"status": "flagged"})
    assert body["claims"], "claims queue must not be empty"
    assert {"claim_id", "status", "amount", "fraud_risk"} <= set(body["claims"][0])


@pytest.mark.parametrize("handler", ["insurance"], indirect=True)
def test_insurance_claim_requires_id(handler):
    status, body = _get(handler, "GET /api/insurance/claim")
    assert status == 400
    assert "claimId" in body["error"]


@pytest.mark.parametrize("handler", ["retail"], indirect=True)
def test_retail_overview_shape(handler):
    _, body = _get(handler, "GET /api/retail/overview")
    assert body["inventory"]["overall"]["total_skus"] > 0
    assert body["inventory"]["summary"], "per-category rows required"
    assert set("ABC") <= set(body["abc"]["classification"])
    assert body["margins"]["overall"]["blended_gross_margin"] > 0
    assert body["supplier_risk"]["top_risks"]


@pytest.mark.parametrize("handler", ["retail"], indirect=True)
def test_retail_stockouts_and_forecast(handler):
    _, stockouts = _get(handler, "GET /api/retail/stockouts")
    assert stockouts["items"]
    assert {"sku", "abc_class", "estimated_total_loss"} <= set(stockouts["items"][0])

    _, forecast = _get(handler, "GET /api/retail/forecast", {"sku": "SKU-1001"})
    assert forecast["forecasts"]
    assert {"date", "predicted_units", "lower_bound", "upper_bound"} <= set(
        forecast["forecasts"][0]
    )


@pytest.mark.parametrize("handler", ["retail"], indirect=True)
def test_retail_demand_trend_has_weekly_series(handler):
    _, body = _get(handler, "GET /api/retail/demand")
    assert body["weekly_data"]
    assert {"week", "units_sold", "revenue"} <= set(body["weekly_data"][0])


@pytest.mark.parametrize("handler", ["manufacturing"], indirect=True)
def test_manufacturing_overview_shape(handler):
    _, body = _get(handler, "GET /api/manufacturing/overview")
    assert body["fleet"]["equipment"]
    assert {"equipment_id", "health_score", "status", "criticality"} <= set(
        body["fleet"]["equipment"][0]
    )
    assert body["alerts"]["alerts"]
    assert {"critical", "warning", "info"} <= set(body["alerts"]["severity_counts"])
    assert body["calendar"]["schedule"]
    assert body["parts"]["kpis"]["fill_rate_pct"] > 0


@pytest.mark.parametrize("handler", ["manufacturing"], indirect=True)
def test_manufacturing_equipment_detail(handler):
    _, body = _get(
        handler, "GET /api/manufacturing/equipment", {"equipmentId": "EQ-CNC-001"}
    )
    pred = body["prediction"]["primary_prediction"]
    assert {"failure_mode", "remaining_useful_life_days", "failure_probability"} <= set(
        pred
    )
    assert body["reliability"]["oee_breakdown"]["oee_pct"] > 0


@pytest.mark.parametrize("handler", ["manufacturing"], indirect=True)
def test_manufacturing_sensor_series(handler):
    _, body = _get(
        handler,
        "GET /api/manufacturing/sensor",
        {"equipmentId": "EQ-CNC-001", "sensorType": "vibration"},
    )
    assert body["readings"]
    assert {"timestamp", "value"} <= set(body["readings"][0])
    assert {"warning", "critical"} <= set(body["thresholds"])


@pytest.mark.parametrize("handler", ["manufacturing"], indirect=True)
def test_manufacturing_detail_routes_require_id(handler):
    for path in ("equipment", "sensor"):
        status, body = _get(handler, f"GET /api/manufacturing/{path}")
        assert status == 400
        assert "equipmentId" in body["error"]


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_market_shape(handler):
    _, body = _get(handler, "GET /api/realestate/market", {"zipcode": "78701"})
    assert body["conditions"]["market_snapshot"]["median_sale_price"] > 0
    # 13 points, not 12: a twelve-month span needs both endpoints, and pinning 12
    # here is what let the chart header measure eleven months of drift against a
    # twelve-month YoY tile. See test_realestate_chart_header_agrees_with_the_yoy_tile.
    assert len(body["trends"]["trends"]) == 13
    assert {"date", "median_sale_price", "closed_sales"} <= set(
        body["trends"]["trends"][0]
    )
    assert len(body["forecast"]["forecast"]) == 12
    assert {"date", "forecasted_median_price", "confidence_low", "confidence_high"} <= (
        set(body["forecast"]["forecast"][0])
    )


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_listings_pass_json_criteria(handler):
    """Query params must reach search_properties as typed filters.

    (toolkit.parse_json_arg accepts a dict as well as a JSON string, so this
    pins the *coercion* — bedsMin arrives as the string "4" and must come back
    as int 4 — not the encoding.)
    """
    _, body = _get(
        handler, "GET /api/realestate/listings", {"zipcode": "78704", "bedsMin": "4"}
    )
    assert "error" not in body, body
    assert body["listings"]
    assert {"listing_id", "address", "list_price", "sqft"} <= set(body["listings"][0])
    assert body["search_criteria"]["beds_min"] == 4


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_comparables(handler):
    _, body = _get(
        handler,
        "GET /api/realestate/comparables",
        {"address": "500 Congress Ave, Austin TX"},
    )
    assert len(body["comparables"]) == 6
    assert {"address", "sale_price", "similarity_score"} <= set(body["comparables"][0])

    status, err = _get(handler, "GET /api/realestate/comparables")
    assert status == 400
    assert "address" in err["error"]


# --------------------------------------------------------------------------
# data-coherence regressions — every one of these was found by eyeballing a
# screenshot, not by an assertion. Independently-drawn fields for the same
# entity produce visible contradictions that a shape test happily passes.
# --------------------------------------------------------------------------

# SKU prefix -> the category and product names that prefix is allowed to carry
RETAIL_CATALOG = {
    "ELEC": ("Electronics", {"Wireless Earbuds", "USB-C Cable", "Smart Thermostat"}),
    "APRL": ("Apparel", {"Winter Jacket", "Rain Shell", "Merino Base Layer"}),
    "GROC": ("Grocery", {"Organic Coffee", "Olive Oil 1L", "Almond Butter"}),
    "HOME": ("Home & Garden", {"Air Purifier", "Cast Iron Skillet", "Linen Duvet"}),
    "SPRT": ("Sports", {"Running Shoes", "Yoga Mat", "Trail Backpack"}),
}


@pytest.mark.parametrize("handler", ["retail"], indirect=True)
def test_retail_stockout_rows_are_internally_coherent(handler):
    """A row's SKU prefix, category and product name must agree.

    "SKU-SPRT-216 / Organic Coffee / Electronics" reads as broken data rather
    than a simulation, and each product may appear at most once per report.
    """
    _, body = _get(handler, "GET /api/retail/stockouts")
    assert body["items"]
    seen = set()
    for row in body["items"]:
        prefix = row["sku"].split("-")[1]
        category, names = RETAIL_CATALOG[prefix]
        assert row["category"] == category, f"{row['sku']} -> {row['category']}"
        assert row["product_name"] in names, f"{row['sku']} -> {row['product_name']}"
        assert row["product_name"] not in seen, f"duplicate {row['product_name']}"
        seen.add(row["product_name"])


@pytest.mark.parametrize("handler", ["retail"], indirect=True)
def test_retail_stockout_eta_follows_reorder_status(handler):
    """Only an ON_ORDER item has a confirmed delivery date.

    Drawing status and ETA independently produced "NOT_ORDERED, arriving next
    Tuesday" rows.
    """
    _, body = _get(handler, "GET /api/retail/stockouts")
    for row in body["items"]:
        if row["reorder_status"] == "ON_ORDER":
            assert row["eta"], f"{row['sku']} is ON_ORDER with no ETA"
        else:
            assert (
                row["eta"] is None
            ), f"{row['sku']} is {row['reorder_status']} yet has an ETA"


@pytest.mark.parametrize("handler", ["manufacturing"], indirect=True)
def test_manufacturing_weekly_capacity_has_no_gaps(handler):
    """A week with no jobs must be present as zero, not omitted.

    Omitting it makes the capacity chart skip a bar, which reads as if that
    week does not exist rather than "nothing is booked".
    """
    _, body = _get(handler, "GET /api/manufacturing/overview")
    weeks = body["calendar"]["weekly_capacity"]
    assert weeks
    numbers = sorted(int(label.split()[1]) for label in weeks)
    assert numbers == list(
        range(numbers[0], numbers[0] + len(numbers))
    ), f"gap in weekly_capacity: {numbers}"
    # a zeroed week is the whole point — assert the shape survives one
    for bucket in weeks.values():
        assert bucket["maintenance_hours"] >= 0
        assert bucket["events"] >= 0


@pytest.mark.parametrize("handler", ["retail"], indirect=True)
def test_retail_headline_growth_matches_the_plotted_series(handler):
    """trends.*_growth_pct must be derived from weekly_data, not drawn apart.

    The card header showed "units +6.6%" above a line that visibly fell,
    because the percentage was an independent r.uniform() draw.
    """
    _, body = _get(handler, "GET /api/retail/demand")
    weeks = body["weekly_data"]
    assert len(weeks) >= 2
    for key, field in (
        ("units_growth_pct", "units_sold"),
        ("revenue_growth_pct", "revenue"),
        ("aov_change_pct", "avg_order_value"),
    ):
        expected = (weeks[-1][field] / weeks[0][field] - 1) * 100
        assert body["trends"][key] == pytest.approx(expected, abs=0.1), (
            f"{key}={body['trends'][key]} but {field} moved "
            f"{weeks[0][field]} -> {weeks[-1][field]} ({expected:.1f}%)"
        )


@pytest.mark.parametrize("handler", ["retail"], indirect=True)
def test_retail_weekly_revenue_follows_units(handler):
    """revenue == units_sold * avg_order_value, or the two lines contradict."""
    _, body = _get(handler, "GET /api/retail/demand")
    for w in body["weekly_data"]:
        assert w["revenue"] == pytest.approx(
            w["units_sold"] * w["avg_order_value"], rel=1e-6
        ), w


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_comparables_are_size_plausible(handler):
    """A comp must be within 25% of the subject's size, with rooms to match.

    A 635 sqft "3 bed / 2 bath" comp for a 1,229 sqft subject carried a +$98K
    size adjustment — not something an appraiser would accept.
    """
    from toolkit import property_basis

    # anchor on the SUBJECT's real size, not the comps' own average — averaging
    # the comps is circular and passes even when a comp is half the subject
    for address in ("1615 Hickory St, 78701", "7895 Birch Ct, 78701"):
        subject_sqft = property_basis(address).sqft
        _, body = _get(handler, "GET /api/realestate/comparables", {"address": address})
        assert body["comparables"]
        for c in body["comparables"]:
            # rooms must be plausible for the comp's own floor area
            assert c["sqft"] / c["beds"] >= 300, f"{c['sqft']}sf with {c['beds']} beds"
            assert (
                c["sqft"] / c["baths"] >= 400
            ), f"{c['sqft']}sf with {c['baths']} baths"
            # and within the appraisal-plausible size window of the subject
            ratio = c["sqft"] / subject_sqft
            assert 0.7 <= ratio <= 1.3, (
                f"{address}: comp {c['sqft']}sf vs subject {subject_sqft}sf "
                f"(ratio {ratio:.2f}) — not a usable comparable"
            )


@pytest.mark.parametrize("handler", ["insurance"], indirect=True)
def test_insurance_fraud_funnel_is_derived(handler):
    """The fraud numbers must form one funnel, not four independent draws.

    The dashboard put "9 confirmed cases" beside a pattern chart whose bars
    summed to 20, because confirmed_fraud and top_fraud_types were drawn apart.
    """
    _, body = _get(handler, "GET /api/insurance/overview")
    m = body["fraud"]["metrics"]
    assert m["flagged_for_review"] <= m["total_claims_screened"]
    # a flagged claim is either confirmed fraud or a false positive
    assert m["confirmed_fraud"] + m["false_positives"] == m["flagged_for_review"]

    patterns = body["fraud"]["top_fraud_types"]
    assert patterns
    assert (
        sum(p["count"] for p in patterns) == m["confirmed_fraud"]
    ), f"pattern bars sum to {sum(p['count'] for p in patterns)}, header says {m['confirmed_fraud']}"
    for p in patterns:
        expected = p["count"] / m["confirmed_fraud"] * 100
        assert p["pct"] == pytest.approx(expected, abs=0.1), p
    # detection_rate_pct is recall over confirmed + missed, and the KPI card
    # frames it as a success rate — a funnel share here would read as a failure
    assert m["detection_rate_pct"] == pytest.approx(
        m["confirmed_fraud"]
        / (m["confirmed_fraud"] + m["missed_fraud_estimate"])
        * 100,
        abs=0.1,
    )
    assert 85 <= m["detection_rate_pct"] <= 100
    assert m["false_positive_rate_pct"] == pytest.approx(
        m["false_positives"] / m["total_claims_screened"] * 100, abs=0.1
    )


@pytest.mark.parametrize(
    "status_filter", ["all", "open", "pending", "closed", "flagged"]
)
@pytest.mark.parametrize("handler", ["insurance"], indirect=True)
def test_insurance_claim_queue_honours_its_own_filter(handler, status_filter):
    """Every row must satisfy the filter the user clicked.

    Coercing only the status left CLOSED rows in the "pending" tab and 0.27-risk
    rows in the "flagged" tab, directly beneath a card reading "score > 0.7".
    """
    _, body = _get(handler, "GET /api/insurance/claims", {"status": status_filter})
    rows = body["claims"]
    assert rows
    pending = {"SUBMITTED", "UNDER_REVIEW", "INVESTIGATION", "ASSESSMENT"}
    for row in rows:
        if status_filter == "closed":
            assert row["status"] == "CLOSED", row
        elif status_filter in ("open", "pending", "flagged"):
            assert row["status"] != "CLOSED", f"{status_filter} tab shows {row}"
        if status_filter == "pending":
            assert row["status"] in pending, row
        if status_filter == "flagged":
            assert row["fraud_risk"] > 0.7, f"flagged tab shows {row['fraud_risk']}"


@pytest.mark.parametrize("handler", ["insurance"], indirect=True)
def test_insurance_claim_priority_follows_risk_and_amount(handler):
    """Priority must be implied by the row's own fraud score and amount.

    An independent draw put a 0.99 fraud score at LOW priority next to a $12,818
    claim marked HIGH, in a queue whose whole purpose is triage order.
    """
    _, body = _get(handler, "GET /api/insurance/claims", {"status": "all"})
    for row in body["claims"]:
        risk, amount, priority = row["fraud_risk"], row["amount"], row["priority"]
        if risk > 0.85 or amount > 60000:
            assert priority == "HIGH", row
        elif risk > 0.5 or amount > 20000:
            assert priority == "MEDIUM", row
        else:
            assert priority == "LOW", row


@pytest.mark.parametrize("handler", ["insurance"], indirect=True)
def test_insurance_reserve_exposure_excludes_closed_claims(handler):
    """A settled claim carries no reserve, and CLOSED rows are not open.

    The cards read "Open Claims 11" and "Reserve Exposure $373.1K" over a list
    that included 2 CLOSED claims worth $120.7K, so neither number was what its
    label said.
    """
    _, body = _get(handler, "GET /api/insurance/claims", {"status": "all"})
    rows = body["claims"]
    open_rows = [r for r in rows if r["status"] != "CLOSED"]
    assert body["open_claims"] == len(open_rows)
    assert body["total_claims"] == len(rows)
    summary = body["summary"]
    assert summary["reserve_exposure"] == pytest.approx(
        sum(r["amount"] for r in open_rows), abs=0.01
    )
    assert summary["avg_open_amount"] == pytest.approx(
        summary["reserve_exposure"] / len(open_rows), abs=0.01
    )
    # the closed rows are still counted in the period total — the two differ
    # whenever any claim closed, which is the point of separating them
    assert summary["total_amount"] == pytest.approx(
        sum(r["amount"] for r in rows), abs=0.01
    )


@pytest.mark.parametrize("handler", ["insurance"], indirect=True)
def test_insurance_settlement_kpis_aggregate_the_claim_mix(handler):
    """The header total must be the sum of the rows printed beneath it.

    "328 settlements - $1.5M paid" sat directly above four rows summing to 232
    claims, because total_settlements was its own randint.
    """
    _, body = _get(handler, "GET /api/insurance/overview")
    kpis = body["settlement"]["kpis"]
    by_type = body["settlement"]["by_claim_type"]
    assert by_type

    counts = sum(t["count"] for t in by_type.values())
    paid = sum(t["count"] * t["avg_amount"] for t in by_type.values())
    assert (
        kpis["total_settlements"] == counts
    ), f"header {kpis['total_settlements']} vs rows {counts}"
    assert kpis["total_amount_paid"] == pytest.approx(paid, rel=1e-6)
    assert kpis["average_settlement"] == pytest.approx(paid / counts, abs=0.01)
    # claim amounts are right-skewed, so the median sits below the mean
    assert kpis["median_settlement"] < kpis["average_settlement"]


def _price_floats(node, path=""):
    """Whole-number floats in money fields — round(x, -3) returns a float, which
    serialises as "415000.0" and renders with a stray decimal."""
    money = ("price", "value", "tax", "cost", "amount", "adj")
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            out += _price_floats(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += _price_floats(v, f"{path}[{i}]")
    elif isinstance(node, float) and node == int(node) and abs(node) >= 1000:
        if any(t in path.lower() for t in money):
            out.append((path, node))
    return out


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_money_fields_are_ints(handler):
    for path, params in (
        ("listings", {"zipcode": "78701"}),
        ("comparables", {"address": "1615 Hickory St, 78701"}),
        ("market", {"zipcode": "78701"}),
    ):
        _, body = _get(handler, f"GET /api/realestate/{path}", params)
        offenders = _price_floats(body, path)
        assert not offenders, f"float money fields: {offenders[:5]}"


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_listing_price_agrees_with_comparables(handler):
    """The same address must not be a $297K listing and a $978K subject.

    Both routes derive size and price basis from toolkit.property_basis, so an
    independently-invented number in either one shows up here as a ratio far
    from 1. The band is wide because comps carry their own adjustments.
    """
    _, listings = _get(handler, "GET /api/realestate/listings", {"zipcode": "78701"})
    assert listings["listings"]
    for row in listings["listings"][:5]:
        _, comps = _get(
            handler, "GET /api/realestate/comparables", {"address": row["address"]}
        )
        indicated = comps["summary"]["median_adjusted_price"]
        ratio = indicated / row["list_price"]
        assert 0.7 <= ratio <= 1.4, (
            f"{row['address']}: list {row['list_price']} vs indicated {indicated} "
            f"(ratio {ratio:.2f}) — routes disagree on the same property"
        )


def test_manufacturing_asset_reads_the_same_across_routes(tmp_path):
    """The fleet row and the drill-down describe one machine, so they must agree.

    EQ-CNC-003 was listed STOPPED at health 34.9 in the fleet table while its
    drill-down said RUNNING at 76.7 — clicking a stopped machine showed it
    running. Both now read toolkit.asset_basis. Asserted through the equipment
    tool module directly because the /equipment route exposes prediction and
    reliability, not the status pane.
    """
    handler = _stage_handler("manufacturing", tmp_path)
    equipment = sys.modules["equipment_tools"]
    _, fleet = _get(handler, "GET /api/manufacturing/overview")
    rows = {r["equipment_id"]: r for r in fleet["fleet"]["equipment"]}
    assert len(rows) == len(equipment.EQUIPMENT_ROSTER)
    for eq_id, row in rows.items():
        detail = equipment.get_equipment_status(eq_id)
        assert detail["health_score"] == row["health_score"], eq_id
        assert detail["status"] == row["status"], eq_id
        assert detail["criticality"] == row["criticality"], eq_id


def test_manufacturing_alerts_quote_the_asset_own_reading(tmp_path):
    """Every alert must be traceable to a threshold on that asset's own sensors.

    Alerts used to be sampled from templates with hard-coded values, so a
    "vibration 14.2 mm/s" alert sat above a sensor chart averaging 6.35 mm/s for
    the same machine, and a health-99 asset could carry a CRITICAL alert.
    """
    handler = _stage_handler("manufacturing", tmp_path)
    equipment = sys.modules["equipment_tools"]
    _, body = _get(handler, "GET /api/manufacturing/overview")
    alerts = body["alerts"]["alerts"]
    for alert in alerts:
        eq_id = alert["equipment_id"]
        detail = equipment.get_equipment_status(eq_id)
        sensors = detail["sensors"]
        if alert["type"] == "HIGH_VIBRATION":
            assert sensors["vibration_mm_s"] > equipment.VIBRATION_WARNING, alert
            assert str(sensors["vibration_mm_s"]) in alert["message"], alert
        elif alert["type"] == "LOW_OIL_PRESSURE":
            assert sensors["oil_pressure_bar"] < equipment.OIL_WARNING, alert
            assert str(sensors["oil_pressure_bar"]) in alert["message"], alert
        elif alert["type"] == "HIGH_TEMPERATURE":
            limit = equipment.asset_type(eq_id)["temp"][1]
            assert sensors["temperature_c"] > limit * equipment.TEMP_WARNING_FRAC, alert
            assert str(sensors["temperature_c"]) in alert["message"], alert
        else:
            assert alert["type"] == "DEGRADED_CONDITION", alert
            assert detail["health_score"] < 75, alert
        # the detail pane raises the same rules, so an alert here has a twin there
        assert alert["type"] in {a["type"] for a in detail["alerts"]}, alert
    # a CRITICAL alert on an asset the fleet calls healthy was the original defect
    rows = {r["equipment_id"]: r for r in body["fleet"]["equipment"]}
    for alert in alerts:
        if alert["severity"] == "CRITICAL":
            assert rows[alert["equipment_id"]]["health_score"] < 90, alert


@pytest.mark.parametrize("sensor", ["vibration", "temperature", "oil_pressure"])
def test_manufacturing_sensor_series_matches_the_status_pane(sensor, tmp_path):
    """The chart's mean must be the reading the status pane and alerts quote.

    A single fleet-wide (35, 110) temperature band clamped the steam turbine's
    186.7C reading to a 109.5C series mean — a 103%-of-range contradiction on
    one screen. Bounds now come from each asset's own envelope.
    """
    handler = _stage_handler("manufacturing", tmp_path)
    equipment = sys.modules["equipment_tools"]
    field = {
        "vibration": "vibration_mm_s",
        "temperature": "temperature_c",
        "oil_pressure": "oil_pressure_bar",
    }[sensor]
    for eq_id, _name, _dept in equipment.EQUIPMENT_ROSTER:
        _, body = _get(
            handler,
            "GET /api/manufacturing/sensor",
            {"equipmentId": eq_id, "sensorType": sensor},
        )
        reading = equipment.get_equipment_status(eq_id)["sensors"][field]
        lo, hi, _unit = equipment._sensor_range(eq_id, sensor)
        assert lo <= reading <= hi, f"{eq_id} {sensor} {reading} outside ({lo}, {hi})"
        # 8% of the plotted range — wide enough for the noise, far tighter than
        # the 103% the clamped turbine produced
        drift = abs(body["statistics"]["mean"] - reading) / (hi - lo)
        assert drift < 0.08, (
            f"{eq_id} {sensor}: chart mean {body['statistics']['mean']} vs "
            f"reading {reading} ({drift:.0%} of range)"
        )
        # The chart's threshold lines must be the numbers the alert rules fire
        # on, whether or not today's fleet happens to breach them: a flat
        # 90%-of-range line put vibration's marker at 16.25 while the alert list
        # raised CRITICAL at 11.0.
        thresholds = body["thresholds"]
        limit = equipment.asset_type(eq_id)["temp"][1]
        expected = {
            "vibration": (
                equipment.VIBRATION_WARNING,
                equipment.VIBRATION_CRITICAL,
                "ABOVE",
            ),
            "oil_pressure": (equipment.OIL_WARNING, equipment.OIL_CRITICAL, "BELOW"),
            "temperature": (
                round(limit * equipment.TEMP_WARNING_FRAC, 1),
                round(limit * equipment.TEMP_CRITICAL_FRAC, 1),
                "ABOVE",
            ),
        }[sensor]
        assert (
            thresholds["warning"],
            thresholds["critical"],
            thresholds["breach_direction"],
        ) == expected, f"{eq_id} {sensor}: {thresholds} vs rule {expected}"
        # and a breach of that line is exactly what raises the alert
        fired = {
            "vibration": "HIGH_VIBRATION",
            "oil_pressure": "LOW_OIL_PRESSURE",
            "temperature": "HIGH_TEMPERATURE",
        }[sensor] in {
            a["type"] for a in equipment.get_equipment_status(eq_id)["alerts"]
        }
        past_line = (
            reading < thresholds["warning"]
            if thresholds["breach_direction"] == "BELOW"
            else reading > thresholds["warning"]
        )
        assert fired == past_line, (
            f"{eq_id} {sensor}: alert={fired} but reading {reading} vs warning "
            f"line {thresholds['warning']} ({thresholds['breach_direction']})"
        )


def test_manufacturing_reliability_rolls_up_its_own_rows(tmp_path):
    """The failure modes must partition the header count and the downtime.

    Three mode counts drawn independently summed to 9 under a "4 failures in 12
    months" header, and total_downtime_hours was failures x a free MTTR draw, so
    the rows totalled 31h beside a 4.2h total.
    """
    handler = _stage_handler("manufacturing", tmp_path)
    equipment = sys.modules["equipment_tools"]
    swings = []
    for eq_id, _name, _dept in equipment.EQUIPMENT_ROSTER:
        _, body = _get(
            handler, "GET /api/manufacturing/equipment", {"equipmentId": eq_id}
        )
        hist = body["reliability"]["failure_history"]
        modes = hist["top_failure_modes"]
        assert sum(m["count"] for m in modes) == hist["total_failures_12m"], eq_id
        assert hist["total_downtime_hours"] == pytest.approx(
            sum(m["count"] * m["avg_repair_hours"] for m in modes), abs=0.15
        ), eq_id
        # MTTR is that downtime per failure, not an unrelated draw
        assert body["reliability"]["reliability_metrics"][
            "mttr_hours"
        ] == pytest.approx(
            hist["total_downtime_hours"] / hist["total_failures_12m"], abs=0.05
        ), eq_id
        # unplanned share is measured against the planned hours printed beside it
        assert hist["unplanned_downtime_pct"] == pytest.approx(
            hist["total_downtime_hours"]
            / (hist["total_downtime_hours"] + hist["planned_downtime_hours"])
            * 100,
            abs=0.05,
        ), eq_id
        # OEE is the product of its own three factors
        oee = body["reliability"]["oee_breakdown"]
        assert oee["oee_pct"] == pytest.approx(
            oee["availability_pct"]
            * oee["performance_rate_pct"]
            * oee["quality_rate_pct"]
            / 10000,
            abs=0.1,
        ), eq_id
        # and a trend label may not contradict the change it labels
        trends = body["reliability"]["trends"]
        for key in ("mtbf", "oee"):
            label, change = trends[f"{key}_trend"], trends[f"{key}_change_pct"]
            if label == "IMPROVING":
                assert change > 0, (eq_id, key, label, change)
            elif label == "DECLINING":
                assert change < 0, (eq_id, key, label, change)
        swings.append(
            (
                body["prediction"]["degradation_trend"]["current_degradation_pct"],
                trends["mtbf_change_pct"],
                trends["oee_change_pct"],
                eq_id,
            )
        )

    # Both change figures derive from the same wear state the degradation card
    # reports, so ranking the fleet by degradation ranks it inversely by either
    # change. Checked across the fleet because the per-asset label assertion
    # above is silent for a STABLE asset, which most of the fleet is on a
    # typical day.
    by_wear = sorted(swings)
    assert [s[1] for s in by_wear] == sorted(
        (s[1] for s in swings), reverse=True
    ), f"mtbf_change_pct does not follow degradation: {by_wear}"
    assert [s[2] for s in by_wear] == sorted(
        (s[2] for s in swings), reverse=True
    ), f"oee_change_pct does not follow degradation: {by_wear}"


def test_manufacturing_prediction_follows_asset_condition(tmp_path):
    """A worse-condition asset must not get the longer remaining life.

    A STOPPED machine at health 34 was given a 98-day RUL and a "World Class 88%
    OEE" beside it. RUL, MTBF and OEE now all derive from the basis wear state,
    so ranking assets by health ranks them the same way by predicted life.
    """
    handler = _stage_handler("manufacturing", tmp_path)
    equipment = sys.modules["equipment_tools"]
    assets = []
    for eq_id, _name, _dept in equipment.EQUIPMENT_ROSTER:
        _, body = _get(
            handler, "GET /api/manufacturing/equipment", {"equipmentId": eq_id}
        )
        detail = equipment.get_equipment_status(eq_id)
        pred = body["prediction"]
        assets.append(
            {
                "id": eq_id,
                "health": detail["health_score"],
                "degradation": pred["degradation_trend"]["current_degradation_pct"],
                "mtbf": body["reliability"]["reliability_metrics"]["mtbf_hours"],
                "oee": body["reliability"]["oee_breakdown"]["oee_pct"],
                "iso_zone": None,
            }
        )
        # degradation and health both track wear, so they must rank inversely
        assert 0 <= pred["degradation_trend"]["current_degradation_pct"] <= 100, eq_id
        # a stopped asset cannot be months from failing
        if detail["status"] == "STOPPED":
            assert pred["primary_prediction"]["remaining_useful_life_days"] <= 30, eq_id
            assert body["reliability"]["oee_breakdown"]["oee_class"] != "World Class"
    by_health = sorted(assets, key=lambda a: a["health"])
    # the sickest asset must not simultaneously carry the best MTBF and OEE
    worst, best = by_health[0], by_health[-1]
    assert worst["degradation"] > best["degradation"], (worst, best)
    assert worst["mtbf"] < best["mtbf"], (worst, best)
    assert worst["oee"] < best["oee"], (worst, best)


def test_manufacturing_vibration_spectrum_fits_its_overall_rms(tmp_path):
    """No spectral peak may exceed the overall RMS it is a component of.

    Peaks drawn independently reached 5 mm/s under a 0.7 mm/s overall reading and
    named an "inner race defect" on a machine whose spectrum was flat, while the
    ISO zone card said "Zone A, newly commissioned" for an asset the alert list
    flagged at 14 mm/s.
    """
    # staged for the side effect: it puts the aliased tool modules on sys.modules
    _stage_handler("manufacturing", tmp_path)
    equipment = sys.modules["equipment_tools"]
    prediction = sys.modules["prediction_tools"]
    for eq_id, _name, _dept in equipment.EQUIPMENT_ROSTER:
        body = prediction.analyze_vibration(eq_id)
        reading = equipment.get_equipment_status(eq_id)["sensors"]["vibration_mm_s"]
        overall = body["overall_vibration"]["velocity_rms_mm_s"]
        assert overall == reading, eq_id
        for peak in body["frequency_peaks"]:
            assert peak["amplitude_mm_s"] <= overall, (eq_id, peak)
            # a peak below the ISO Zone A/B boundary is not evidence of a defect
            if peak["amplitude_mm_s"] <= 1.8:
                assert peak["diagnosis"] == "Normal", (eq_id, peak)
        zone = body["iso_10816_classification"]["zone"]
        expected = (
            "A"
            if overall <= 1.8
            else "B" if overall <= 4.5 else "C" if overall <= 11.2 else "D"
        )
        assert zone == expected, f"{eq_id}: {overall} mm/s reported Zone {zone}"
        # the shaft speed is the one the status pane reports
        if equipment.get_equipment_status(eq_id)["sensors"]["rpm"]:
            assert (
                body["shaft_speed_rpm"]
                == equipment.get_equipment_status(eq_id)["sensors"]["rpm"]
            ), eq_id


@pytest.mark.parametrize("industry", sorted(ALIASES))
def test_simulated_provenance_is_disclosed(industry, tmp_path):
    """Every simulated payload must carry source=simulated (data-honesty rule)."""
    handler = _stage_handler(industry, tmp_path)
    path = _cdk_app_namespace()["DASHBOARD_ROUTES"][industry][0]
    _, body = _get(handler, f"GET /api/{industry}/{path}")
    blobs = [v for v in body.values() if isinstance(v, dict)] or [body]
    for blob in blobs:
        assert blob.get("source") == "simulated", f"{industry}: {list(blob)[:5]}"


# --------------------------------------------------------------------------
# real-estate coherence: one address, and one market, described the same way by
# every route that touches it. Each assertion below is a contradiction that was
# visible on a single dashboard screen before the shared basis existed.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_market_median_is_one_number(handler):
    """The tile, the history chart and the forecast base must be one median.

    Drawn per route, one screen showed a "Median Sale Price $440.1K" tile above a
    history chart plotting $740K-$780K, above a forecast card reading "projected
    from $777.1K" — three independent draws of one market's median price.
    """
    for zipcode in ("78701", "94110", "10001"):
        _, body = _get(handler, "GET /api/realestate/market", {"zipcode": zipcode})
        tile = body["conditions"]["market_snapshot"]["median_sale_price"]
        assert tile == body["trends"]["trends"][-1]["median_sale_price"], zipcode
        assert tile == body["trends"]["current_median_price"], zipcode
        assert tile == body["forecast"]["current_median_price"], zipcode
        # and the headline percentage must match the direction the line moved
        yoy = body["conditions"]["price_trends"]["year_over_year_pct"]
        charted = body["trends"]["summary"]["total_price_change_pct"]
        assert (yoy >= 0) == (charted >= 0), f"{zipcode}: yoy {yoy} vs chart {charted}"
        # the forecast continues the trailing drift rather than inventing one
        projected = body["forecast"]["summary"]["total_price_change_pct"]
        trailing = body["forecast"]["trailing_yoy_pct"]
        assert (projected >= 0) == (
            trailing >= 0
        ), f"{zipcode}: forecast {projected} vs trailing {trailing}"


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_ppsf_implies_a_plausible_home(handler):
    """median / $-per-sqft must be a size a home can be.

    Drawn independently, a $440K median beside $602/sqft implied a 730 sqft
    median home for a market whose own listings averaged 2,400 sqft.
    """
    for zipcode in ("78701", "94110", "10001", "60601"):
        _, body = _get(handler, "GET /api/realestate/market", {"zipcode": zipcode})
        snap = body["conditions"]["market_snapshot"]
        implied = snap["implied_median_sqft"]
        assert implied == round(
            snap["median_sale_price"] / snap["median_price_per_sqft"]
        ), zipcode
        assert 600 <= implied <= 6000, f"{zipcode}: implied median home {implied} sqft"


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_market_type_agrees_with_its_own_evidence(handler):
    """A "Strong Seller's Market" cannot sit beside a sale-to-list below 1.0.

    One card read "Strong Seller's Market" at 1.6 months of supply while
    reporting a 0.944 sale-to-list ratio and 90 days on market — the label and
    the three numbers under it described different markets. The label is stated
    on three routes, so all three must say the same thing.
    """
    # The bands are the handler's own (MarketBasis.market_type): <3 strong
    # seller, <5 seller, <7 balanced, else buyer. Asserting a textbook "seller
    # means under 4 months" would fail on 444 of 3,000 markets that are
    # legitimately seller's markets at 4-5 months — the test has to check the
    # thresholds the code states, not the ones I remember.
    bands = (
        (3.0, "Strong Seller's Market"),
        (5.0, "Seller's Market"),
        (7.0, "Balanced Market"),
        (float("inf"), "Buyer's Market"),
    )
    seen = set()
    # 40 markets, so every band is exercised rather than whichever four the
    # first sample happened to hit.
    for zipcode in (f"{10000 + i * 37}" for i in range(40)):
        _, body = _get(handler, "GET /api/realestate/market", {"zipcode": zipcode})
        cond = body["conditions"]
        label = cond["market_indicators"]["market_type"]
        seen.add(label)
        assert body["forecast"]["market_type"] == label, zipcode
        assert body["trends"]["market_type"] == label, zipcode
        months = cond["market_snapshot"]["months_of_supply"]
        expected = next(name for limit, name in bands if months < limit)
        assert label == expected, f"{zipcode}: {label} at {months} months of supply"
        # Sale-to-list is leverage: tight supply bids above asking, slack cuts.
        stl = cond["market_indicators"]["sale_to_list_ratio"]
        assert (stl >= 1.0) == (
            months <= 6.0
        ), f"{zipcode}: {label} at {months}mo with sale-to-list {stl}"
        drivers = " ".join(body["forecast"]["positive_drivers"])
        risks = " ".join(body["forecast"]["risk_factors"])
        if months >= 6.0:
            # an oversupplied market must not be handed tight inventory as a
            # tailwind on the same card that calls it oversupplied
            assert (
                "Tight inventory" not in drivers
            ), f"{zipcode}: {months}mo listing tight inventory as a positive driver"
            assert "Elevated inventory" in risks, f"{zipcode}: {months}mo, {risks}"
        if months < 4.0:
            assert "Elevated inventory" not in risks, f"{zipcode}: {months}mo, {risks}"
    # The sample must actually span the bands, or the assertions above are only
    # checking one branch.
    assert len(seen) >= 3, f"only saw {seen} — sample does not span the bands"


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_listings_are_priced_in_their_own_market(handler):
    """Listings must average near the $/sqft the market tile above them shows.

    The listings table averaged $312/sqft directly beneath a Market Pulse tile
    reading "$421 / Sq Ft" for the same zipcode, because the property basis drew
    its price level from a flat $180-500 band regardless of market.
    """
    for zipcode in ("78701", "94110", "10001"):
        _, market = _get(handler, "GET /api/realestate/market", {"zipcode": zipcode})
        _, body = _get(handler, "GET /api/realestate/listings", {"zipcode": zipcode})
        market_ppsf = market["conditions"]["market_snapshot"]["median_price_per_sqft"]
        assert body["market_median_price_per_sqft"] == market_ppsf, zipcode
        assert body["listings"], zipcode
        avg = body["summary"]["avg_price_per_sqft"]
        assert (
            abs(avg - market_ppsf) / market_ppsf <= 0.25
        ), f"{zipcode}: listings average ${avg}/sqft under a ${market_ppsf}/sqft market"
        for listing in body["listings"]:
            # each row's price is its own size times its own rate
            assert (
                abs(listing["list_price"] / listing["sqft"] - listing["price_per_sqft"])
                <= 1.0
            ), listing
            assert listing["days_on_market"] <= (
                market["conditions"]["market_snapshot"]["average_days_on_market"] * 2.5
            ), listing


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_comparables_agree_with_the_listing(handler):
    """Comps for a listed address must bracket the price that listing shows.

    The comps route drew its own price level, so clicking a $373K listing opened
    a comparables panel indicating $205K for the same address.
    """
    for zipcode in ("78701", "94110"):
        _, listings = _get(
            handler, "GET /api/realestate/listings", {"zipcode": zipcode}
        )
        row = listings["listings"][0]
        _, body = _get(
            handler, "GET /api/realestate/comparables", {"address": row["address"]}
        )
        subject = body["subject_property"]
        assert subject["sqft"] == row["sqft"], row["address"]
        # Not exact equality: the listing's rate is its price rounded to the
        # nearest $1,000 divided by its size, so it can sit up to $500/sqft away
        # from the basis rate the comps use. Tolerance is that rounding, nothing
        # looser — at 1,118 sqft that is $0.45.
        assert subject["price_per_sqft"] == pytest.approx(
            row["price_per_sqft"], abs=500 / row["sqft"]
        ), row["address"]
        assert subject["year_built"] == row["year_built"], row["address"]
        # the comp set must bracket, not contradict, the listing's own price
        adjusted = [c["adjusted_price"] for c in body["comparables"]]
        assert min(adjusted) <= row["list_price"] * 1.35, (
            f"{row['address']}: listed at {row['list_price']} but every comp "
            f"adjusts above {min(adjusted)}"
        )
        assert max(adjusted) >= row["list_price"] * 0.65, (
            f"{row['address']}: listed at {row['list_price']} but every comp "
            f"adjusts below {max(adjusted)}"
        )


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_comp_similarity_ranks_by_real_closeness(handler):
    """The similarity column must measure similarity, and the table sorts by it.

    Drawn over (70, 98), it awarded 96% to the comp carrying the largest
    adjustments in the table and 72% to the one matching on every dimension —
    visible at a glance, because the table is sorted by that column.
    """
    top_gaps, bottom_gaps = [], []
    for i in range(12):
        address = f"{200 + i * 7} Cedar Ln, 78701"
        _, body = _get(handler, "GET /api/realestate/comparables", {"address": address})
        rows = body["comparables"]
        scores = [c["similarity_score"] for c in rows]
        assert scores == sorted(scores, reverse=True), f"{address}: {scores}"
        subject_sqft = body["subject_property"]["sqft"]
        top_gaps.append(abs(rows[0]["sqft"] - subject_sqft) / subject_sqft)
        bottom_gaps.append(abs(rows[-1]["sqft"] - subject_sqft) / subject_sqft)
    # A single address proves nothing: a score unrelated to closeness still puts
    # the best comp on top about half the time. Averaged over 12 subjects the
    # top-ranked comp must be markedly closer in size than the bottom-ranked one.
    mean_top = sum(top_gaps) / len(top_gaps)
    mean_bottom = sum(bottom_gaps) / len(bottom_gaps)
    assert mean_top < mean_bottom * 0.6, (
        f"top-ranked comps average {mean_top:.3f} size gap, bottom-ranked "
        f"{mean_bottom:.3f} — similarity is not ranking by closeness"
    )


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_comp_adjustments_are_signed_against_their_own_row(handler):
    """Each adjustment must have the sign the figures in its own row imply.

    A comp smaller than the subject is adjusted upward, never downward, and the
    total is the sum of the parts shown beside it.
    """
    for address in ("1615 Hickory St, 78701", "7895 Birch Ct, 94110"):
        _, body = _get(handler, "GET /api/realestate/comparables", {"address": address})
        subject = body["subject_property"]
        for c in body["comparables"]:
            adj = c["adjustments"]
            assert (adj["sqft"] >= 0) == (
                c["sqft"] <= subject["sqft"]
            ), f"{address}: {c['sqft']}sf vs {subject['sqft']}sf adjusted {adj['sqft']}"
            assert (
                adj["total"]
                == adj["sqft"] + adj["bedrooms"] + adj["bathrooms"] + adj["time"]
            ), c
            assert c["adjusted_price"] == round(
                round(c["sale_price"] + adj["total"], -3)
            ), c


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_chart_header_agrees_with_the_yoy_tile(handler):
    """The chart's own "% over period" must equal the YoY tile above it.

    Both measure twelve months of one market. They disagreed by up to 6.3 points
    for two compounding reasons: the walk's month-to-month jitter accumulated
    instead of cancelling, and twelve monthly points span only eleven intervals,
    so the header measured eleven months of drift against the tile's twelve. One
    screen read "YoY +8.8%" above a chart headed "+8.1% over period".
    """
    for zipcode in ("78701", "94110", "10001", "60601", "33101"):
        _, body = _get(handler, "GET /api/realestate/market", {"zipcode": zipcode})
        yoy = body["conditions"]["price_trends"]["year_over_year_pct"]
        charted = body["trends"]["summary"]["total_price_change_pct"]
        assert charted == pytest.approx(yoy, abs=0.3), (
            f"{zipcode}: tile says {yoy}% YoY, its own chart says {charted}% "
            "over the same twelve months"
        )
        # and the span really is twelve months of intervals, not eleven
        trends = body["trends"]["trends"]
        assert len(trends) == 13, f"{zipcode}: {len(trends)} points spans a year"
        first, last = trends[0]["date"], trends[-1]["date"]
        assert (
            int(last[:4]) * 12 + int(last[5:]) - (int(first[:4]) * 12 + int(first[5:]))
            == 12
        ), f"{zipcode}: {first}..{last} is not twelve months apart"


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_type_medians_decompose_the_headline_median(handler):
    """Median-by-type is a breakdown, so it must weight back to the headline.

    Drawn as three free multipliers of the market median, the card share-weighted
    to $468K under a $528K headline — 83 of 300 markets blended more than 5%
    below the number the same screen calls the median sale price.
    """
    for zipcode in ("78701", "94110", "10001", "60601", "33101", "98101"):
        _, body = _get(handler, "GET /api/realestate/market", {"zipcode": zipcode})
        headline = body["conditions"]["market_snapshot"]["median_sale_price"]
        types = body["conditions"]["property_types"]
        shares = sum(v["pct_of_sales"] for v in types.values())
        assert shares == pytest.approx(100.0, abs=0.15), f"{zipcode}: shares {shares}"
        blend = sum(v["median_price"] * v["pct_of_sales"] for v in types.values()) / 100
        # tolerance is the rounding of three medians to whole dollars, nothing
        # looser — a free-multiplier version misses this by 15%
        assert blend == pytest.approx(
            headline, rel=0.005
        ), f"{zipcode}: types blend to {blend:.0f} under a {headline} headline"
        # single-family carries the premium and condos the discount, always
        assert (
            types["single_family"]["median_price"]
            > types["townhouse"]["median_price"]
            > types["condo"]["median_price"]
        ), {k: v["median_price"] for k, v in types.items()}


@pytest.mark.parametrize("handler", ["realestate"], indirect=True)
def test_realestate_comp_median_ppsf_is_a_median_of_the_rows(handler):
    """The tile labelled "Median $/Sq Ft" must be a median of the table's rows.

    Computed as a mean of the same rows, the tile showed $263 for a table whose
    rates were 233/247/256/256/290/299 — a figure no ordering of those rows
    produces, up to $24/sqft off the true median over 200 addresses.
    """
    for i in range(20):
        address = f"{300 + i * 11} Oak Dr, 78701"
        _, body = _get(handler, "GET /api/realestate/comparables", {"address": address})
        rates = sorted(c["price_per_sqft"] for c in body["comparables"])
        reported = body["summary"]["median_price_per_sqft"]
        assert reported == rates[len(rates) // 2], f"{address}: {reported} vs {rates}"
        assert reported in rates, f"{address}: {reported} is not one of {rates}"
