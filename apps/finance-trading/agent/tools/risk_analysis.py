"""Risk analysis tools for the Trading Assistant.

Provides VaR calculations, stress testing, portfolio risk analysis,
and Monte Carlo simulations. Complex calculations use AgentCore Code Interpreter.
"""
import json
import math
import random
from strands import tool


@tool
def calculate_var(portfolio_value: float, confidence_level: float, time_horizon_days: int) -> str:
    """Calculate Value-at-Risk (VaR) for a portfolio.

    Computes parametric VaR using the variance-covariance method.
    VaR represents the maximum expected loss over a given time horizon
    at a specified confidence level.

    Args:
        portfolio_value: Total portfolio value in USD.
        confidence_level: Confidence level as decimal (e.g., 0.95 for 95%, 0.99 for 99%).
        time_horizon_days: Number of trading days for VaR calculation (1 for daily, 10 for 2-week).

    Returns:
        JSON string with VaR metrics at specified and standard confidence levels.
    """
    # Z-scores for common confidence levels
    z_scores = {0.90: 1.282, 0.95: 1.645, 0.99: 2.326}
    z = z_scores.get(confidence_level, 1.645)

    # Simulated portfolio volatility (annualized)
    annual_volatility = random.uniform(0.12, 0.25)
    daily_volatility = annual_volatility / math.sqrt(252)
    period_volatility = daily_volatility * math.sqrt(time_horizon_days)

    var_amount = portfolio_value * z * period_volatility
    var_pct = z * period_volatility * 100

    # Calculate at multiple confidence levels
    results = {}
    for conf, z_val in z_scores.items():
        period_var = portfolio_value * z_val * period_volatility
        results[f"var_{int(conf*100)}"] = {
            "confidence": conf,
            "var_amount": round(period_var, 2),
            "var_pct": round(z_val * period_volatility * 100, 2),
        }

    return json.dumps({
        "portfolio_value": portfolio_value,
        "requested_confidence": confidence_level,
        "time_horizon_days": time_horizon_days,
        "annual_volatility": round(annual_volatility * 100, 2),
        "daily_volatility": round(daily_volatility * 100, 4),
        "var": {
            "amount": round(var_amount, 2),
            "percentage": round(var_pct, 2),
            "interpretation": f"With {confidence_level*100:.0f}% confidence, the portfolio will not lose more than ${var_amount:,.2f} ({var_pct:.2f}%) over the next {time_horizon_days} trading day(s).",
        },
        "all_levels": results,
        "method": "parametric_variance_covariance",
    })


@tool
def stress_test_portfolio(portfolio_value: float, scenario: str) -> str:
    """Run a stress test on the portfolio against historical crisis scenarios.

    Simulates portfolio performance under major market events to assess
    tail risk exposure.

    Args:
        portfolio_value: Total portfolio value in USD.
        scenario: Stress scenario name. Options: '2008_financial_crisis',
                  'covid_crash_2020', 'dot_com_bubble', 'black_monday_1987',
                  'interest_rate_shock', 'all' (runs all scenarios).

    Returns:
        JSON string with estimated losses under each stress scenario.
    """
    scenarios = {
        "2008_financial_crisis": {"drawdown": -0.54, "duration_months": 17, "recovery_months": 49},
        "covid_crash_2020": {"drawdown": -0.34, "duration_months": 1, "recovery_months": 5},
        "dot_com_bubble": {"drawdown": -0.49, "duration_months": 30, "recovery_months": 56},
        "black_monday_1987": {"drawdown": -0.22, "duration_months": 0.1, "recovery_months": 2},
        "interest_rate_shock": {"drawdown": -0.20, "duration_months": 6, "recovery_months": 12},
    }

    if scenario == "all":
        selected = scenarios
    elif scenario in scenarios:
        selected = {scenario: scenarios[scenario]}
    else:
        return json.dumps({"error": f"Unknown scenario: {scenario}. Available: {list(scenarios.keys()) + ['all']}"})

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

    worst = min(results.values(), key=lambda x: x["estimated_loss"])

    return json.dumps({
        "portfolio_value": portfolio_value,
        "scenarios": results,
        "worst_case": {
            "scenario": min(results, key=lambda k: results[k]["estimated_loss"]),
            "loss": worst["estimated_loss"],
        },
        "recommendation": "Consider portfolio hedging strategies (puts, inverse ETFs) if stress test losses exceed risk tolerance.",
    })


@tool
def analyze_portfolio_risk(positions: str) -> str:
    """Analyze risk metrics for a portfolio of positions.

    Computes comprehensive risk metrics including beta, Sharpe ratio,
    maximum drawdown, and correlation analysis.

    Args:
        positions: JSON string of positions, e.g., '[{"symbol": "AAPL", "value": 50000}, ...]'

    Returns:
        JSON string with portfolio risk metrics and position-level analysis.
    """
    try:
        pos_list = json.loads(positions)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON format for positions"})

    total_value = sum(p.get("value", 0) for p in pos_list)

    position_analysis = []
    for pos in pos_list:
        weight = pos["value"] / total_value if total_value > 0 else 0
        beta = round(random.uniform(0.5, 1.8), 2)
        position_analysis.append({
            "symbol": pos["symbol"],
            "value": pos["value"],
            "weight_pct": round(weight * 100, 2),
            "beta": beta,
            "annual_volatility_pct": round(random.uniform(15, 50), 1),
            "sharpe_ratio": round(random.uniform(-0.5, 2.5), 2),
        })

    portfolio_beta = sum(p["beta"] * p["weight_pct"] / 100 for p in position_analysis)

    return json.dumps({
        "total_value": total_value,
        "num_positions": len(pos_list),
        "portfolio_metrics": {
            "beta": round(portfolio_beta, 2),
            "sharpe_ratio": round(random.uniform(0.3, 2.0), 2),
            "sortino_ratio": round(random.uniform(0.5, 2.5), 2),
            "max_drawdown_pct": round(random.uniform(-30, -5), 1),
            "annual_volatility_pct": round(random.uniform(12, 28), 1),
            "tracking_error_pct": round(random.uniform(2, 8), 1),
        },
        "concentration_risk": {
            "top_position_weight_pct": round(max(p["weight_pct"] for p in position_analysis), 2) if position_analysis else 0,
            "herfindahl_index": round(sum((p["weight_pct"]/100)**2 for p in position_analysis), 4),
        },
        "positions": position_analysis,
    })


@tool
def monte_carlo_simulation(portfolio_value: float, annual_return: float, annual_volatility: float, years: int) -> str:
    """Run a Monte Carlo simulation for portfolio projections.

    Simulates thousands of possible portfolio paths using geometric Brownian motion
    to provide probabilistic return forecasts.

    For complex simulations with many paths, consider using the code interpreter tool
    for more sophisticated modeling.

    Args:
        portfolio_value: Starting portfolio value in USD.
        annual_return: Expected annual return as decimal (e.g., 0.08 for 8%).
        annual_volatility: Expected annual volatility as decimal (e.g., 0.15 for 15%).
        years: Number of years to simulate forward.

    Returns:
        JSON string with simulation results including percentile outcomes.
    """
    num_simulations = 1000
    daily_return = annual_return / 252
    daily_vol = annual_volatility / math.sqrt(252)
    days = years * 252

    final_values = []
    for _ in range(num_simulations):
        value = portfolio_value
        for _ in range(days):
            daily_change = random.gauss(daily_return, daily_vol)
            value *= (1 + daily_change)
        final_values.append(value)

    final_values.sort()

    percentiles = {}
    for p in [5, 10, 25, 50, 75, 90, 95]:
        idx = int(len(final_values) * p / 100)
        percentiles[f"p{p}"] = round(final_values[idx], 2)

    mean_val = sum(final_values) / len(final_values)
    prob_loss = sum(1 for v in final_values if v < portfolio_value) / len(final_values)
    prob_double = sum(1 for v in final_values if v >= portfolio_value * 2) / len(final_values)

    return json.dumps({
        "parameters": {
            "initial_value": portfolio_value,
            "annual_return": annual_return,
            "annual_volatility": annual_volatility,
            "years": years,
            "num_simulations": num_simulations,
        },
        "results": {
            "mean_final_value": round(mean_val, 2),
            "median_final_value": percentiles["p50"],
            "percentiles": percentiles,
            "probability_of_loss": round(prob_loss * 100, 1),
            "probability_of_doubling": round(prob_double * 100, 1),
            "best_case": round(final_values[-1], 2),
            "worst_case": round(final_values[0], 2),
        },
        "interpretation": f"Based on {num_simulations} simulations over {years} years: median outcome is ${percentiles['p50']:,.2f}. There is a {prob_loss*100:.1f}% chance of losing money and a {prob_double*100:.1f}% chance of doubling the investment.",
    })
