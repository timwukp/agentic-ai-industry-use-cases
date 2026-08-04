import importlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "finance" / "risk"))
risk = importlib.import_module("handler")
sys.path.pop(0)


def test_var_math():
    res = risk.calculate_var(1_000_000, 0.95, 1, 0.18)
    # z * daily_vol: 1.645 * 0.18/sqrt(252) ≈ 1.865%
    assert abs(res["var"]["percentage"] - 1.87) < 0.05
    assert (
        res["all_levels"]["var_99"]["var_amount"]
        > res["all_levels"]["var_95"]["var_amount"]
    )


def test_stress_all_and_single():
    res = risk.stress_test_portfolio(500_000, "all")
    assert len(res["scenarios"]) == 5
    assert res["worst_case"]["scenario"] == "2008_financial_crisis"
    single = risk.stress_test_portfolio(500_000, "covid_crash_2020")
    assert single["scenarios"]["covid_crash_2020"]["estimated_loss"] == -170_000.0
    assert "error" in risk.stress_test_portfolio(500_000, "asteroid")


def test_analyze_positions():
    res = risk.analyze_portfolio_risk(
        '[{"symbol": "AAPL", "value": 50000}, {"symbol": "JPM", "value": 50000}]'
    )
    assert res["num_positions"] == 2
    assert abs(sum(p["weight_pct"] for p in res["positions"]) - 100) < 0.1
    # deterministic: same call, same result
    assert res == risk.analyze_portfolio_risk(
        '[{"symbol": "AAPL", "value": 50000}, {"symbol": "JPM", "value": 50000}]'
    )
    assert "error" in risk.analyze_portfolio_risk("nope")
    assert "error" in risk.analyze_portfolio_risk("[]")


def test_monte_carlo_deterministic_and_sane():
    r1 = risk.monte_carlo_simulation(100_000, 0.08, 0.15, 10, 500)
    r2 = risk.monte_carlo_simulation(100_000, 0.08, 0.15, 10, 500)
    assert r1 == r2
    pct = r1["results"]["percentiles"]
    assert pct["p5"] < pct["p50"] < pct["p95"]
    assert 0 <= r1["results"]["probability_of_loss"] <= 100
