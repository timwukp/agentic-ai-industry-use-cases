from strands import tool
import json
import random
from datetime import datetime, timedelta


@tool
def predict_loss_probability(policy_id: str) -> str:
    """Predict probability of loss for a policy based on risk indicators.

    Uses historical loss data, current risk factors, and environmental conditions
    to estimate the likelihood and potential severity of a loss event.

    Args:
        policy_id: The policy identifier to evaluate for loss probability.

    Returns:
        JSON string with loss probability, severity estimates, and contributing factors.
    """
    loss_probability = round(random.uniform(0.01, 0.35), 4)
    expected_severity = round(random.uniform(5000, 150000), 2)

    contributing_factors = []
    all_factors = [
        {"factor": "Weather exposure (hurricane/tornado zone)", "impact": round(random.uniform(0.1, 0.9), 2)},
        {"factor": "Property age exceeds 30 years", "impact": round(random.uniform(0.1, 0.5), 2)},
        {"factor": "Prior claims history", "impact": round(random.uniform(0.2, 0.7), 2)},
        {"factor": "High crime area", "impact": round(random.uniform(0.1, 0.6), 2)},
        {"factor": "Wildfire proximity", "impact": round(random.uniform(0.1, 0.8), 2)},
        {"factor": "Aging electrical/plumbing systems", "impact": round(random.uniform(0.1, 0.4), 2)},
        {"factor": "Flood plain adjacency", "impact": round(random.uniform(0.2, 0.7), 2)},
        {"factor": "High traffic area (auto)", "impact": round(random.uniform(0.1, 0.5), 2)},
    ]
    contributing_factors = random.sample(all_factors, random.randint(2, 5))

    if loss_probability > 0.2:
        risk_tier = "HIGH"
    elif loss_probability > 0.1:
        risk_tier = "ELEVATED"
    elif loss_probability > 0.05:
        risk_tier = "MODERATE"
    else:
        risk_tier = "LOW"

    return json.dumps({
        "policy_id": policy_id,
        "loss_probability": loss_probability,
        "risk_tier": risk_tier,
        "severity_estimate": {
            "expected_loss": expected_severity,
            "best_case": round(expected_severity * 0.3, 2),
            "worst_case": round(expected_severity * 3.0, 2),
            "confidence_interval_90": [
                round(expected_severity * 0.5, 2),
                round(expected_severity * 2.0, 2),
            ],
        },
        "contributing_factors": contributing_factors,
        "time_horizon_days": 365,
        "model_confidence": round(random.uniform(0.7, 0.95), 2),
        "predicted_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_prevention_alert(policy_id: str) -> str:
    """Generate a proactive risk prevention alert for a policyholder.

    Creates actionable alerts based on identified risk factors that the
    policyholder can address to reduce their exposure to loss events.

    Args:
        policy_id: The policy identifier to generate a prevention alert for.

    Returns:
        JSON string with prevention alert details, urgency level, and recommended actions.
    """
    alert_types = [
        {
            "type": "WEATHER_WARNING",
            "title": "Severe Weather Approaching",
            "description": "Major storm system expected in your area within 72 hours",
            "urgency": "HIGH",
            "actions": [
                "Secure outdoor furniture and equipment",
                "Clear gutters and drainage systems",
                "Document property condition with photos/video",
                "Review emergency supply kit",
            ],
        },
        {
            "type": "MAINTENANCE_DUE",
            "title": "Preventive Maintenance Recommended",
            "description": "Based on property age, key systems may need inspection",
            "urgency": "MEDIUM",
            "actions": [
                "Schedule HVAC system inspection",
                "Check water heater for signs of corrosion",
                "Inspect roof for damaged or missing shingles",
                "Test smoke detectors and carbon monoxide alarms",
            ],
        },
        {
            "type": "THEFT_RISK",
            "title": "Elevated Theft Risk in Area",
            "description": "Recent increase in property crimes reported in your neighborhood",
            "urgency": "MEDIUM",
            "actions": [
                "Verify security system is armed and functional",
                "Keep outdoor areas well-lit",
                "Do not leave packages unattended",
                "Report suspicious activity to local authorities",
            ],
        },
        {
            "type": "WILDFIRE_RISK",
            "title": "Elevated Wildfire Conditions",
            "description": "High fire risk conditions detected in your region",
            "urgency": "HIGH",
            "actions": [
                "Create defensible space around property",
                "Clear dry vegetation within 30 feet of structures",
                "Prepare evacuation plan and grab-and-go bag",
                "Ensure address is clearly visible for emergency responders",
            ],
        },
        {
            "type": "WATER_DAMAGE_RISK",
            "title": "Water Damage Prevention Advisory",
            "description": "Seasonal conditions increase risk of water intrusion",
            "urgency": "LOW",
            "actions": [
                "Inspect basement for signs of moisture",
                "Check sump pump operation",
                "Verify downspouts direct water away from foundation",
                "Consider installing water leak sensors",
            ],
        },
    ]

    alert = random.choice(alert_types)
    alert_id = f"ALT-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    return json.dumps({
        "alert_id": alert_id,
        "policy_id": policy_id,
        "alert_type": alert["type"],
        "title": alert["title"],
        "description": alert["description"],
        "urgency": alert["urgency"],
        "recommended_actions": alert["actions"],
        "potential_savings": {
            "estimated_loss_avoided": round(random.uniform(5000, 75000), 2),
            "premium_reduction_potential_pct": round(random.uniform(2, 10), 1),
        },
        "response_deadline": (datetime.utcnow() + timedelta(days=random.randint(1, 14))).strftime("%Y-%m-%d"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def analyze_loss_patterns(category: str, period: str) -> str:
    """Analyze historical loss patterns by category for a given period.

    Identifies trends, seasonal patterns, and emerging risk clusters
    across the book of business for a specific loss category.

    Args:
        category: The loss category to analyze (e.g., 'fire', 'water', 'theft', 'auto', 'liability').
        period: The analysis period (e.g., 'Q1-2024', 'FY-2023', '2024-H1').

    Returns:
        JSON string with loss pattern analysis including trends, distributions, and insights.
    """
    total_losses = random.randint(50, 500)
    total_amount = round(random.uniform(500000, 10000000), 2)
    avg_loss = round(total_amount / total_losses, 2)

    monthly_trend = []
    for i in range(6):
        month_date = datetime.utcnow() - timedelta(days=30 * (5 - i))
        monthly_trend.append({
            "month": month_date.strftime("%Y-%m"),
            "count": random.randint(5, 80),
            "total_amount": round(random.uniform(50000, 1500000), 2),
        })

    severity_distribution = {
        "minor_under_5k": round(random.uniform(30, 50), 1),
        "moderate_5k_25k": round(random.uniform(25, 40), 1),
        "major_25k_100k": round(random.uniform(10, 20), 1),
        "catastrophic_over_100k": round(random.uniform(2, 10), 1),
    }

    top_causes = random.sample([
        {"cause": "Pipe burst/plumbing failure", "pct": round(random.uniform(10, 25), 1)},
        {"cause": "Electrical fault", "pct": round(random.uniform(8, 18), 1)},
        {"cause": "Weather event (wind/hail)", "pct": round(random.uniform(15, 30), 1)},
        {"cause": "Vehicle collision", "pct": round(random.uniform(10, 20), 1)},
        {"cause": "Theft/burglary", "pct": round(random.uniform(5, 15), 1)},
        {"cause": "Slip and fall", "pct": round(random.uniform(5, 12), 1)},
        {"cause": "Appliance failure", "pct": round(random.uniform(5, 10), 1)},
    ], 4)

    return json.dumps({
        "category": category,
        "period": period,
        "summary": {
            "total_losses": total_losses,
            "total_amount": total_amount,
            "average_loss": avg_loss,
            "median_loss": round(avg_loss * random.uniform(0.5, 0.8), 2),
            "loss_ratio_pct": round(random.uniform(40, 75), 1),
        },
        "trend": {
            "direction": random.choice(["INCREASING", "DECREASING", "STABLE"]),
            "change_pct": round(random.uniform(-20, 30), 1),
            "monthly_data": monthly_trend,
        },
        "severity_distribution_pct": severity_distribution,
        "top_causes": top_causes,
        "seasonal_pattern": random.choice([
            "Higher frequency in winter months (pipe bursts, ice damage)",
            "Summer peak (storms, hail, wildfire)",
            "No significant seasonal pattern",
            "Holiday period spike (theft, unoccupied homes)",
        ]),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def recommend_risk_mitigation(policy_id: str) -> str:
    """Recommend specific risk mitigation actions for a policy.

    Generates personalized risk reduction recommendations based on the
    policy's specific risk profile, historical patterns, and available
    mitigation options.

    Args:
        policy_id: The policy identifier to generate mitigation recommendations for.

    Returns:
        JSON string with prioritized risk mitigation recommendations and expected impact.
    """
    all_recommendations = [
        {
            "action": "Install smart water leak detection system",
            "category": "WATER_DAMAGE",
            "cost_estimate": round(random.uniform(200, 800), 2),
            "risk_reduction_pct": round(random.uniform(15, 35), 1),
            "premium_discount_pct": round(random.uniform(3, 8), 1),
            "priority": "HIGH",
            "implementation_days": random.randint(1, 7),
        },
        {
            "action": "Upgrade to impact-resistant roofing",
            "category": "STORM_DAMAGE",
            "cost_estimate": round(random.uniform(8000, 20000), 2),
            "risk_reduction_pct": round(random.uniform(20, 40), 1),
            "premium_discount_pct": round(random.uniform(5, 15), 1),
            "priority": "MEDIUM",
            "implementation_days": random.randint(3, 14),
        },
        {
            "action": "Install monitored security system with cameras",
            "category": "THEFT",
            "cost_estimate": round(random.uniform(500, 2000), 2),
            "risk_reduction_pct": round(random.uniform(25, 50), 1),
            "premium_discount_pct": round(random.uniform(5, 12), 1),
            "priority": "HIGH",
            "implementation_days": random.randint(1, 5),
        },
        {
            "action": "Install whole-house surge protector",
            "category": "ELECTRICAL",
            "cost_estimate": round(random.uniform(200, 500), 2),
            "risk_reduction_pct": round(random.uniform(10, 25), 1),
            "premium_discount_pct": round(random.uniform(2, 5), 1),
            "priority": "LOW",
            "implementation_days": random.randint(1, 3),
        },
        {
            "action": "Create defensible space and brush clearing",
            "category": "WILDFIRE",
            "cost_estimate": round(random.uniform(1000, 5000), 2),
            "risk_reduction_pct": round(random.uniform(30, 60), 1),
            "premium_discount_pct": round(random.uniform(5, 20), 1),
            "priority": "HIGH",
            "implementation_days": random.randint(2, 10),
        },
        {
            "action": "Install backup sump pump with battery",
            "category": "FLOOD",
            "cost_estimate": round(random.uniform(400, 1200), 2),
            "risk_reduction_pct": round(random.uniform(15, 30), 1),
            "premium_discount_pct": round(random.uniform(3, 7), 1),
            "priority": "MEDIUM",
            "implementation_days": random.randint(1, 5),
        },
    ]

    num_recommendations = random.randint(3, 5)
    recommendations = random.sample(all_recommendations, num_recommendations)

    total_cost = sum(r["cost_estimate"] for r in recommendations)
    total_risk_reduction = min(sum(r["risk_reduction_pct"] for r in recommendations), 75)
    total_premium_savings = min(sum(r["premium_discount_pct"] for r in recommendations), 25)

    return json.dumps({
        "policy_id": policy_id,
        "recommendations": recommendations,
        "summary": {
            "total_recommendations": num_recommendations,
            "total_estimated_cost": round(total_cost, 2),
            "combined_risk_reduction_pct": round(total_risk_reduction, 1),
            "estimated_premium_savings_pct": round(total_premium_savings, 1),
            "roi_estimate": round(total_premium_savings / (total_cost / 1000) if total_cost > 0 else 0, 2),
        },
        "next_review_date": (datetime.utcnow() + timedelta(days=90)).strftime("%Y-%m-%d"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })
