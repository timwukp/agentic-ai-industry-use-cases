"""Healthcare dashboard_api routes — mirrors the Lambda packaging aliases."""

import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
HC = REPO / "tools" / "healthcare"

# alias module name -> source handler dir (same map as infra/cdk/app.py)
ALIASES = {
    "analytics_tools": "analytics",
    "scheduling_tools": "scheduling",
    "records_tools": "records",
    "clinical_tools": "clinical",
}


@pytest.fixture(scope="module")
def handler(tmp_path_factory):
    """Stage the lambda bundle the way industry_stack._stage does."""
    bundle = tmp_path_factory.mktemp("hc-dashboard")
    shutil.copy(HC / "dashboard_api" / "handler.py", bundle / "handler.py")
    shutil.copytree(REPO / "tools" / "shared" / "toolkit", bundle / "toolkit")
    for alias, src in ALIASES.items():
        shutil.copy(HC / src / "handler.py", bundle / f"{alias}.py")
    sys.path.insert(0, str(bundle))
    try:
        for mod in ["handler", *ALIASES]:
            sys.modules.pop(mod, None)
        yield importlib.import_module("handler")
    finally:
        sys.path.pop(0)
        for mod in ["handler", *ALIASES]:
            sys.modules.pop(mod, None)


def _get(handler, route, params=None):
    resp = handler.lambda_handler(
        {"routeKey": route, "queryStringParameters": params or {}}, None
    )
    return resp["statusCode"], json.loads(resp["body"])


def test_population_route(handler):
    status, body = _get(handler, "GET /api/healthcare/population")
    assert status == 200
    assert {
        "practice_panel",
        "chronic_disease_prevalence",
        "quality_measures_hedis",
        "utilization_metrics",
    } <= set(body)


def test_patient_composite_has_all_five_keys(handler):
    status, body = _get(
        handler, "GET /api/healthcare/patient", {"patientId": "PT-1001"}
    )
    assert status == 200
    assert {"summary", "analytics", "readmission", "care_gaps", "appointments"} == set(
        body
    )
    assert body["summary"]["demographics"]["name"]
    assert body["care_gaps"]["care_gaps"]
    assert body["readmission"]["risk_score"] >= 5


def test_labs_route(handler):
    status, body = _get(
        handler, "GET /api/healthcare/labs", {"patientId": "PT-1001", "days": "60"}
    )
    assert status == 200
    assert {"labs", "medications"} == set(body)
    assert body["labs"]["lookback_days"] == 60
    assert body["medications"]["medications"]


@pytest.mark.parametrize("risk_type", ["cardiovascular", "diabetes", "falls"])
def test_risk_route_all_types(handler, risk_type):
    status, body = _get(
        handler, "GET /api/healthcare/risk", {"patientId": "PT-1001", "type": risk_type}
    )
    assert status == 200
    assert body["risk_model"]
    assert "score" in body


def test_risk_route_bad_type_surfaces_tool_error(handler):
    status, body = _get(handler, "GET /api/healthcare/risk", {"type": "astrology"})
    assert status == 200  # tool_error payload, not HTTP error
    assert "error" in body
    assert "supported_risk_types" in body


def test_availability_default_is_real_provider(handler):
    status, body = _get(handler, "GET /api/healthcare/availability")
    assert status == 200
    assert body["provider_id"] == "DR-CHEN"
    assert body["provider"]["name"] == "Dr. Sarah Chen, MD"


def test_unknown_route_404(handler):
    status, body = _get(handler, "GET /api/healthcare/nope")
    assert status == 404


def test_determinism_same_patient_same_body(handler):
    _, a = _get(handler, "GET /api/healthcare/patient", {"patientId": "PT-42"})
    _, b = _get(handler, "GET /api/healthcare/patient", {"patientId": "PT-42"})
    assert a == b
