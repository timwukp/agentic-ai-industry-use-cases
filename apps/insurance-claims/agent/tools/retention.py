from strands import tool
import json
import random
from datetime import datetime, timedelta


@tool
def predict_churn_risk(customer_id: str) -> str:
    """Predict customer churn probability with contributing factors.

    Analyzes customer engagement, satisfaction signals, competitive positioning,
    and lifecycle stage to predict renewal likelihood.

    Args:
        customer_id: The customer identifier to evaluate for churn risk.

    Returns:
        JSON string with churn probability, risk level, and contributing factors.
    """
    churn_probability = round(random.uniform(0.05, 0.85), 3)

    if churn_probability > 0.6:
        risk_level = "HIGH"
    elif churn_probability > 0.3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    contributing_factors = []
    all_factors = [
        {"factor": "Premium increase at last renewal", "impact": round(random.uniform(0.1, 0.3), 2)},
        {"factor": "Recent claim denial", "impact": round(random.uniform(0.15, 0.35), 2)},
        {"factor": "Low engagement with digital services", "impact": round(random.uniform(0.05, 0.15), 2)},
        {"factor": "No bundled policies", "impact": round(random.uniform(0.05, 0.2), 2)},
        {"factor": "Competitor promotional offer received", "impact": round(random.uniform(0.1, 0.25), 2)},
        {"factor": "Long call center wait times", "impact": round(random.uniform(0.05, 0.15), 2)},
        {"factor": "Policy approaching anniversary", "impact": round(random.uniform(0.03, 0.1), 2)},
        {"factor": "Life event detected (move, marriage, new vehicle)", "impact": round(random.uniform(0.05, 0.2), 2)},
    ]
    num_factors = random.randint(2, 5)
    contributing_factors = random.sample(all_factors, num_factors)

    return json.dumps({
        "customer_id": customer_id,
        "churn_probability": churn_probability,
        "risk_level": risk_level,
        "contributing_factors": contributing_factors,
        "customer_metrics": {
            "tenure_years": round(random.uniform(0.5, 15), 1),
            "lifetime_value": round(random.uniform(5000, 100000), 2),
            "policies_held": random.randint(1, 5),
            "claims_in_last_year": random.randint(0, 3),
            "nps_score": random.randint(1, 10),
            "last_interaction_days_ago": random.randint(1, 180),
        },
        "recommended_intervention": random.choice([
            "Proactive outreach from retention specialist",
            "Personalized discount offer",
            "Bundle opportunity presentation",
            "Service recovery for recent issue",
            "Loyalty reward acknowledgment",
        ]),
        "predicted_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_renewal_offer(customer_id: str) -> str:
    """Generate a personalized renewal offer for a customer.

    Creates a tailored renewal package considering customer value, risk level,
    competitive positioning, and retention priority.

    Args:
        customer_id: The customer identifier to generate a renewal offer for.

    Returns:
        JSON string with personalized renewal offer details and pricing options.
    """
    current_premium = round(random.uniform(1000, 8000), 2)
    base_adjustment_pct = round(random.uniform(-5, 15), 1)
    retention_discount_pct = round(random.uniform(0, 12), 1)

    standard_renewal = round(current_premium * (1 + base_adjustment_pct / 100), 2)
    discounted_renewal = round(standard_renewal * (1 - retention_discount_pct / 100), 2)

    offer_id = f"REN-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    options = [
        {
            "option": "Standard Renewal",
            "premium": standard_renewal,
            "change_pct": base_adjustment_pct,
            "coverage_changes": "No changes to current coverage",
        },
        {
            "option": "Loyalty Package",
            "premium": discounted_renewal,
            "change_pct": round((discounted_renewal / current_premium - 1) * 100, 1),
            "coverage_changes": "Current coverage with loyalty discount applied",
        },
        {
            "option": "Enhanced Coverage",
            "premium": round(standard_renewal * 1.1, 2),
            "change_pct": round((standard_renewal * 1.1 / current_premium - 1) * 100, 1),
            "coverage_changes": "Increased limits with additional endorsements",
        },
    ]

    incentives = random.sample([
        "First month free on annual plan",
        "Waived administrative fee",
        "Free home safety inspection",
        "Complimentary roadside assistance for 1 year",
        "Gift card for claims-free year",
        "Referral bonus credited to account",
    ], random.randint(1, 3))

    return json.dumps({
        "offer_id": offer_id,
        "customer_id": customer_id,
        "current_premium": current_premium,
        "renewal_options": options,
        "recommended_option": "Loyalty Package",
        "incentives": incentives,
        "valid_until": (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d"),
        "personalization_factors": {
            "customer_segment": random.choice(["High Value", "Growth Potential", "Standard", "At Risk"]),
            "competitive_sensitivity": random.choice(["HIGH", "MEDIUM", "LOW"]),
            "price_elasticity": round(random.uniform(0.3, 1.5), 2),
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def analyze_customer_lifecycle(customer_id: str) -> str:
    """Analyze customer lifecycle stage and value trajectory.

    Evaluates where the customer is in their relationship lifecycle and
    projects future value based on current engagement and growth patterns.

    Args:
        customer_id: The customer identifier to analyze.

    Returns:
        JSON string with lifecycle stage, value trajectory, and growth opportunities.
    """
    stages = ["ACQUISITION", "ONBOARDING", "GROWTH", "MATURITY", "AT_RISK", "DORMANT"]
    current_stage = random.choice(stages)

    tenure_months = random.randint(1, 180)
    current_annual_value = round(random.uniform(1000, 15000), 2)
    policies_held = random.randint(1, 6)
    max_potential_policies = random.randint(policies_held, 8)

    value_trajectory = random.choice(["GROWING", "STABLE", "DECLINING"])

    cross_sell_opportunities = random.sample([
        {"product": "Auto Insurance", "propensity_score": round(random.uniform(0.3, 0.9), 2)},
        {"product": "Home Insurance", "propensity_score": round(random.uniform(0.3, 0.9), 2)},
        {"product": "Life Insurance", "propensity_score": round(random.uniform(0.2, 0.8), 2)},
        {"product": "Umbrella Policy", "propensity_score": round(random.uniform(0.2, 0.7), 2)},
        {"product": "Pet Insurance", "propensity_score": round(random.uniform(0.1, 0.5), 2)},
        {"product": "Travel Insurance", "propensity_score": round(random.uniform(0.1, 0.6), 2)},
    ], random.randint(2, 4))

    return json.dumps({
        "customer_id": customer_id,
        "lifecycle_stage": current_stage,
        "tenure_months": tenure_months,
        "value_metrics": {
            "current_annual_value": current_annual_value,
            "lifetime_value_to_date": round(current_annual_value * tenure_months / 12, 2),
            "projected_lifetime_value": round(current_annual_value * random.uniform(5, 15), 2),
            "value_trajectory": value_trajectory,
        },
        "relationship_depth": {
            "policies_held": policies_held,
            "max_potential_policies": max_potential_policies,
            "wallet_share_pct": round(policies_held / max_potential_policies * 100, 1),
            "product_penetration": round(policies_held / max_potential_policies, 2),
        },
        "engagement_score": round(random.uniform(0, 1), 2),
        "satisfaction_indicators": {
            "nps_score": random.randint(0, 10),
            "last_survey_sentiment": random.choice(["POSITIVE", "NEUTRAL", "NEGATIVE"]),
            "complaints_last_12m": random.randint(0, 3),
        },
        "cross_sell_opportunities": cross_sell_opportunities,
        "next_best_action": random.choice([
            "Schedule annual review call",
            "Present bundling opportunity",
            "Send personalized coverage recommendation",
            "Trigger loyalty milestone recognition",
            "Initiate win-back campaign",
        ]),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def compare_competitive_pricing(policy_type: str, coverage: str) -> str:
    """Compare pricing against market competitors for given policy and coverage.

    Benchmarks current pricing against estimated competitor offerings to
    understand market positioning and price sensitivity.

    Args:
        policy_type: Type of insurance (e.g., 'AUTO', 'HOME', 'LIFE', 'HEALTH').
        coverage: Coverage level description (e.g., '500k_liability', 'standard', 'comprehensive').

    Returns:
        JSON string with competitive pricing comparison and market positioning.
    """
    our_premium = round(random.uniform(1000, 6000), 2)

    competitors = [
        {"name": "Competitor A (National Carrier)", "premium": round(our_premium * random.uniform(0.85, 1.2), 2)},
        {"name": "Competitor B (Regional Carrier)", "premium": round(our_premium * random.uniform(0.8, 1.15), 2)},
        {"name": "Competitor C (Direct/Online)", "premium": round(our_premium * random.uniform(0.75, 1.1), 2)},
        {"name": "Competitor D (Mutual)", "premium": round(our_premium * random.uniform(0.9, 1.25), 2)},
        {"name": "Competitor E (Insurtech)", "premium": round(our_premium * random.uniform(0.7, 1.05), 2)},
    ]

    market_avg = round(sum(c["premium"] for c in competitors) / len(competitors), 2)
    our_position_vs_avg = round((our_premium / market_avg - 1) * 100, 1)

    cheaper_count = sum(1 for c in competitors if c["premium"] < our_premium)
    market_rank = cheaper_count + 1

    for comp in competitors:
        comp["difference_pct"] = round((comp["premium"] / our_premium - 1) * 100, 1)
        comp["cheaper_than_us"] = comp["premium"] < our_premium

    return json.dumps({
        "policy_type": policy_type,
        "coverage": coverage,
        "our_pricing": {
            "annual_premium": our_premium,
            "market_position": f"{market_rank} of {len(competitors) + 1}",
            "vs_market_avg_pct": our_position_vs_avg,
        },
        "competitors": competitors,
        "market_analysis": {
            "market_average": market_avg,
            "lowest_price": round(min(c["premium"] for c in competitors), 2),
            "highest_price": round(max(c["premium"] for c in competitors), 2),
            "price_range_pct": round(
                (max(c["premium"] for c in competitors) - min(c["premium"] for c in competitors))
                / min(c["premium"] for c in competitors) * 100, 1
            ),
        },
        "recommendation": (
            "Competitively positioned" if abs(our_position_vs_avg) <= 5
            else "Consider price adjustment to improve competitiveness" if our_position_vs_avg > 5
            else "Strong price advantage - explore value-add opportunities"
        ),
        "compared_at": datetime.utcnow().isoformat() + "Z",
    })
