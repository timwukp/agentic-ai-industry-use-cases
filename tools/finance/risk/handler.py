"""Gateway target: risk — VaR, stress tests, portfolio risk, Monte Carlo.

Volatility/beta inputs are deterministic per symbol (toolkit.MarketSim), so the
same portfolio always yields the same risk numbers on a given day.
"""

import math
import random

from toolkit import MarketSim, tool_ok, tool_error
from toolkit.dispatch import dispatch
from toolkit.responses import parse_json_arg

Z_SCORES = {0.90: 1.282, 0.95: 1.645, 0.99: 2.326}

STRESS_SCENARIOS = {
    "2008_financial_crisis": {
        "drawdown": -0.54,
        "duration_months": 17,
        "recovery_months": 49,
    },
    "covid_crash_2020": {"drawdown": -0.34, "duration_months": 1, "recovery_months": 5},
    "dot_com_bubble": {"drawdown": -0.49, "duration_months": 30, "recovery_months": 56},
    "black_monday_1987": {
        "drawdown": -0.22,
        "duration_months": 0.1,
        "recovery_months": 2,
    },
    "interest_rate_shock": {
        "drawdown": -0.20,
        "duration_months": 6,
        "recovery_months": 12,
    },
}


def calculate_var(
    portfolio_value: float,
    confidence_level: float = 0.95,
    time_horizon_days: int = 1,
    annual_volatility: float = 0.18,
) -> dict:
    portfolio_value = float(portfolio_value)
    z = Z_SCORES.get(float(confidence_level), 1.645)
    daily_vol = float(annual_volatility) / math.sqrt(252)
    period_vol = daily_vol * math.sqrt(int(time_horizon_days))
    var_amount = portfolio_value * z * period_vol
    all_levels = {
        f"var_{int(c * 100)}": {
            "confidence": c,
            "var_amount": round(portfolio_value * zv * period_vol, 2),
            "var_pct": round(zv * period_vol * 100, 2),
        }
        for c, zv in Z_SCORES.items()
    }
    return tool_ok(
        {
            "portfolio_value": portfolio_value,
            "requested_confidence": confidence_level,
            "time_horizon_days": time_horizon_days,
            "annual_volatility_pct": round(float(annual_volatility) * 100, 2),
            "var": {
                "amount": round(var_amount, 2),
                "percentage": round(z * period_vol * 100, 2),
                "interpretation": (
                    f"With {float(confidence_level) * 100:.0f}% confidence, the portfolio will not "
                    f"lose more than ${var_amount:,.2f} over the next {time_horizon_days} trading day(s)."
                ),
            },
            "all_levels": all_levels,
            "method": "parametric_variance_covariance",
        }
    )


def stress_test_portfolio(portfolio_value: float, scenario: str = "all") -> dict:
    portfolio_value = float(portfolio_value)
    if scenario == "all":
        selected = STRESS_SCENARIOS
    elif scenario in STRESS_SCENARIOS:
        selected = {scenario: STRESS_SCENARIOS[scenario]}
    else:
        return tool_error(
            f"Unknown scenario: {scenario}",
            available=sorted(STRESS_SCENARIOS) + ["all"],
        )
    results = {}
    for name, params in selected.items():
        loss = portfolio_value * params["drawdown"]
        results[name] = {
            "estimated_loss": round(loss, 2),
            "drawdown_pct": params["drawdown"] * 100,
            "crisis_duration_months": params["duration_months"],
            "estimated_recovery_months": params["recovery_months"],
            "portfolio_value_at_trough": round(portfolio_value + loss, 2),
        }
    worst_name = min(results, key=lambda k: results[k]["estimated_loss"])
    return tool_ok(
        {
            "portfolio_value": portfolio_value,
            "scenarios": results,
            "worst_case": {
                "scenario": worst_name,
                "loss": results[worst_name]["estimated_loss"],
            },
            "recommendation": (
                "Consider hedging strategies (puts, inverse ETFs) if stress losses "
                "exceed risk tolerance."
            ),
        }
    )


def analyze_portfolio_risk(positions: str) -> dict:
    pos_list, err = parse_json_arg(positions, "positions")
    if err:
        return tool_error(err)
    if not isinstance(pos_list, list) or not pos_list:
        return tool_error("positions must be a non-empty JSON array")
    sim = MarketSim()
    total_value = sum(float(p.get("value", 0)) for p in pos_list)
    if total_value <= 0:
        return tool_error("Total position value must be positive")
    analysis = []
    for pos in pos_list:
        symbol = pos.get("symbol", "?")
        value = float(pos.get("value", 0))
        weight = value / total_value
        vol = sim.annual_volatility(symbol)
        analysis.append(
            {
                "symbol": symbol,
                "value": value,
                "weight_pct": round(weight * 100, 2),
                "beta": sim.beta(symbol),
                "annual_volatility_pct": round(vol * 100, 1),
            }
        )
    portfolio_beta = sum(a["beta"] * a["weight_pct"] / 100 for a in analysis)
    # portfolio vol: weighted average vol with a flat 0.6 average pairwise correlation
    avg_corr = 0.6
    w_vols = [
        (a["weight_pct"] / 100) * (a["annual_volatility_pct"] / 100) for a in analysis
    ]
    port_var = sum(wv**2 for wv in w_vols) + avg_corr * (
        sum(w_vols) ** 2 - sum(wv**2 for wv in w_vols)
    )
    port_vol = math.sqrt(max(port_var, 0))
    return tool_ok(
        {
            "total_value": total_value,
            "num_positions": len(analysis),
            "portfolio_metrics": {
                "beta": round(portfolio_beta, 2),
                "annual_volatility_pct": round(port_vol * 100, 1),
                "assumed_avg_correlation": avg_corr,
            },
            "concentration_risk": {
                "top_position_weight_pct": round(
                    max(a["weight_pct"] for a in analysis), 2
                ),
                "herfindahl_index": round(
                    sum((a["weight_pct"] / 100) ** 2 for a in analysis), 4
                ),
            },
            "positions": analysis,
        },
        simulated=True,
    )


def monte_carlo_simulation(
    portfolio_value: float,
    annual_return: float = 0.08,
    annual_volatility: float = 0.15,
    years: int = 10,
    num_simulations: int = 1000,
) -> dict:
    portfolio_value = float(portfolio_value)
    annual_return, annual_volatility = float(annual_return), float(annual_volatility)
    years = min(int(years), 50)
    n = min(int(num_simulations), 5000)
    rng = random.Random(
        f"mc|{portfolio_value}|{annual_return}|{annual_volatility}|{years}|{n}"
    )
    # GBM sampled annually (sufficient for percentile outcomes, 250x faster than daily)
    finals = []
    for _ in range(n):
        value = portfolio_value
        for _ in range(years):
            value *= math.exp(
                rng.gauss(annual_return - annual_volatility**2 / 2, annual_volatility)
            )
        finals.append(value)
    finals.sort()
    percentiles = {
        f"p{p}": round(finals[int(n * p / 100)], 2) for p in (5, 10, 25, 50, 75, 90, 95)
    }
    prob_loss = sum(1 for v in finals if v < portfolio_value) / n
    prob_double = sum(1 for v in finals if v >= portfolio_value * 2) / n
    return tool_ok(
        {
            "parameters": {
                "initial_value": portfolio_value,
                "annual_return": annual_return,
                "annual_volatility": annual_volatility,
                "years": years,
                "num_simulations": n,
            },
            "results": {
                "mean_final_value": round(sum(finals) / n, 2),
                "median_final_value": percentiles["p50"],
                "percentiles": percentiles,
                "probability_of_loss": round(prob_loss * 100, 1),
                "probability_of_doubling": round(prob_double * 100, 1),
                "best_case": round(finals[-1], 2),
                "worst_case": round(finals[0], 2),
            },
            "interpretation": (
                f"Median outcome after {years} years: ${percentiles['p50']:,.2f}. "
                f"{prob_loss * 100:.1f}% chance of loss, {prob_double * 100:.1f}% chance of doubling."
            ),
        }
    )


TOOLS = {
    "calculate_var": calculate_var,
    "stress_test_portfolio": stress_test_portfolio,
    "analyze_portfolio_risk": analyze_portfolio_risk,
    "monte_carlo_simulation": monte_carlo_simulation,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
