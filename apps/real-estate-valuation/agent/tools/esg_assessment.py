from strands import tool
import json
import random
from datetime import datetime, timedelta


@tool
def analyze_energy_performance(property_id: str) -> str:
    """Analyze building energy performance and benchmarks.

    Evaluates energy consumption patterns, Energy Star scores, and
    comparison against peers to identify performance gaps and
    improvement opportunities.

    Args:
        property_id: The property identifier to analyze energy performance for.

    Returns:
        JSON string with energy performance metrics, benchmarks, and efficiency recommendations.
    """
    building_type = random.choice(["Office", "Retail", "Industrial", "Multifamily", "Mixed-Use"])
    square_footage = random.randint(20000, 500000)
    energy_star_score = random.randint(20, 99)

    annual_kwh = round(square_footage * random.uniform(15, 40), 0)
    annual_therms = round(square_footage * random.uniform(0.05, 0.3), 0)
    eui = round((annual_kwh * 3.412 + annual_therms * 100) / square_footage, 1)

    peer_eui = round(eui * random.uniform(0.7, 1.3), 1)

    monthly_consumption = []
    for i in range(12):
        month_date = datetime.utcnow() - timedelta(days=30 * (11 - i))
        seasonal_factor = 1 + 0.3 * abs(i - 6) / 6
        monthly_consumption.append({
            "month": month_date.strftime("%Y-%m"),
            "kwh": round(annual_kwh / 12 * seasonal_factor * random.uniform(0.9, 1.1), 0),
            "therms": round(annual_therms / 12 * (2 - seasonal_factor) * random.uniform(0.8, 1.2), 0),
        })

    return json.dumps({
        "property_id": property_id,
        "building_type": building_type,
        "square_footage": square_footage,
        "energy_performance": {
            "energy_star_score": energy_star_score,
            "energy_use_intensity_kbtu_sf": eui,
            "annual_electricity_kwh": annual_kwh,
            "annual_gas_therms": annual_therms,
            "annual_energy_cost": round(annual_kwh * 0.12 + annual_therms * 1.2, 2),
            "cost_per_sf": round((annual_kwh * 0.12 + annual_therms * 1.2) / square_footage, 2),
        },
        "benchmarking": {
            "peer_average_eui": peer_eui,
            "performance_vs_peer_pct": round((peer_eui - eui) / peer_eui * 100, 1),
            "energy_star_percentile": energy_star_score,
            "certification_eligible": energy_star_score >= 75,
        },
        "monthly_consumption": monthly_consumption[-6:],
        "improvement_opportunities": random.sample([
            {"measure": "HVAC system optimization", "savings_pct": round(random.uniform(10, 25), 1)},
            {"measure": "Building envelope improvements", "savings_pct": round(random.uniform(5, 15), 1)},
            {"measure": "Lighting controls upgrade", "savings_pct": round(random.uniform(8, 20), 1)},
            {"measure": "Demand response participation", "savings_pct": round(random.uniform(3, 10), 1)},
        ], random.randint(2, 4)),
        "certifications": {
            "energy_star": energy_star_score >= 75,
            "leed_eligible": random.choice([True, False]),
            "local_benchmarking_compliant": random.choice([True, True, False]),
        },
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def calculate_retrofit_roi(property_id: str, upgrade_type: str) -> str:
    """Calculate ROI for a green building retrofit.

    Models the financial return of energy efficiency or sustainability
    upgrades including utility savings, incentives, green premium on
    value, and tenant attraction benefits.

    Args:
        property_id: The property identifier to calculate retrofit ROI for.
        upgrade_type: Type of green upgrade (e.g., 'solar', 'hvac', 'envelope', 'lighting', 'water').

    Returns:
        JSON string with detailed ROI analysis including payback period and NPV.
    """
    upgrade_details = {
        "solar": {
            "name": "Rooftop Solar PV Installation",
            "capex_range": (200000, 2000000),
            "annual_savings_pct": (20, 40),
            "useful_life_years": 25,
            "incentive_pct": (20, 30),
        },
        "hvac": {
            "name": "High-Efficiency HVAC Replacement",
            "capex_range": (150000, 1500000),
            "annual_savings_pct": (15, 30),
            "useful_life_years": 15,
            "incentive_pct": (5, 15),
        },
        "envelope": {
            "name": "Building Envelope Upgrade (Windows/Insulation)",
            "capex_range": (100000, 1000000),
            "annual_savings_pct": (10, 25),
            "useful_life_years": 20,
            "incentive_pct": (5, 10),
        },
        "lighting": {
            "name": "LED Lighting with Smart Controls",
            "capex_range": (50000, 500000),
            "annual_savings_pct": (20, 40),
            "useful_life_years": 10,
            "incentive_pct": (10, 20),
        },
        "water": {
            "name": "Water Conservation and Recycling System",
            "capex_range": (75000, 500000),
            "annual_savings_pct": (15, 35),
            "useful_life_years": 15,
            "incentive_pct": (5, 15),
        },
    }

    details = upgrade_details.get(upgrade_type, upgrade_details["hvac"])
    capex = round(random.uniform(*details["capex_range"]), 2)
    annual_savings_pct = round(random.uniform(*details["annual_savings_pct"]), 1)
    current_annual_cost = round(random.uniform(100000, 800000), 2)
    annual_savings = round(current_annual_cost * annual_savings_pct / 100, 2)
    incentive_pct = round(random.uniform(*details["incentive_pct"]), 1)
    incentive_amount = round(capex * incentive_pct / 100, 2)
    net_capex = round(capex - incentive_amount, 2)

    simple_payback = round(net_capex / annual_savings, 1) if annual_savings > 0 else 99
    discount_rate = 0.07
    npv = round(sum(
        annual_savings / (1 + discount_rate) ** year
        for year in range(1, details["useful_life_years"] + 1)
    ) - net_capex, 2)
    irr = round(random.uniform(8, 25), 1)

    green_premium_pct = round(random.uniform(2, 8), 1)
    property_value = round(random.uniform(5000000, 50000000), 2)
    value_increase = round(property_value * green_premium_pct / 100, 2)

    return json.dumps({
        "property_id": property_id,
        "upgrade_type": upgrade_type,
        "upgrade_name": details["name"],
        "financial_analysis": {
            "total_capex": capex,
            "incentives_and_rebates": incentive_amount,
            "incentive_pct": incentive_pct,
            "net_investment": net_capex,
            "annual_utility_savings": annual_savings,
            "annual_savings_pct": annual_savings_pct,
        },
        "returns": {
            "simple_payback_years": simple_payback,
            "npv": npv,
            "irr_pct": irr,
            "useful_life_years": details["useful_life_years"],
            "total_lifetime_savings": round(annual_savings * details["useful_life_years"], 2),
        },
        "value_impact": {
            "green_premium_pct": green_premium_pct,
            "estimated_value_increase": value_increase,
            "cap_rate_compression_bps": random.randint(5, 25),
        },
        "non_financial_benefits": random.sample([
            "Improved tenant satisfaction and retention",
            "Enhanced marketability and leasing velocity",
            "Regulatory compliance (building performance standards)",
            "Carbon reduction for ESG reporting",
            "Resilience to energy price volatility",
        ], 3),
        "risk_factors": [
            "Energy price volatility may affect savings projections",
            "Technology may require maintenance beyond estimates",
            "Incentive programs subject to change or expiration",
        ],
        "calculated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_gresb_report(portfolio_id: str) -> str:
    """Generate a GRESB-aligned ESG performance report for a real estate portfolio.

    Produces a report aligned with Global Real Estate Sustainability Benchmark
    (GRESB) assessment criteria covering management, performance, and development.

    Args:
        portfolio_id: The portfolio identifier to generate the GRESB report for.

    Returns:
        JSON string with GRESB-aligned metrics across management and performance dimensions.
    """
    overall_score = random.randint(50, 95)
    num_assets = random.randint(5, 50)

    management_score = random.randint(40, 100)
    performance_score = random.randint(40, 100)

    return json.dumps({
        "portfolio_id": portfolio_id,
        "report_type": "GRESB Standing Investment",
        "overall_score": overall_score,
        "star_rating": min(5, max(1, overall_score // 20)),
        "peer_ranking": f"{random.randint(1, 30)} of {random.randint(30, 100)} in peer group",
        "management_component": {
            "score": management_score,
            "leadership": {
                "esg_policy_in_place": True,
                "board_oversight": True,
                "dedicated_esg_staff": random.choice([True, True, False]),
                "third_party_assurance": random.choice([True, False]),
            },
            "policies": {
                "environmental_policy": True,
                "social_policy": True,
                "governance_policy": True,
                "supplier_code_of_conduct": random.choice([True, False]),
            },
            "reporting_and_disclosure": {
                "frameworks_used": random.sample(["GRI", "TCFD", "SASB", "CDP", "UN PRI"], random.randint(2, 4)),
                "external_assurance": random.choice([True, False]),
                "public_disclosure": True,
            },
        },
        "performance_component": {
            "score": performance_score,
            "energy": {
                "like_for_like_change_pct": round(random.uniform(-10, 5), 1),
                "renewable_energy_pct": round(random.uniform(10, 60), 1),
                "coverage_pct": round(random.uniform(70, 100), 1),
            },
            "ghg_emissions": {
                "scope_1_2_change_pct": round(random.uniform(-15, 5), 1),
                "scope_3_estimated": random.choice([True, False]),
                "net_zero_target": random.choice([True, True, False]),
            },
            "water": {
                "like_for_like_change_pct": round(random.uniform(-8, 5), 1),
                "coverage_pct": round(random.uniform(60, 95), 1),
            },
            "waste": {
                "diversion_rate_pct": round(random.uniform(30, 80), 1),
                "coverage_pct": round(random.uniform(50, 90), 1),
            },
            "certifications": {
                "assets_certified_pct": round(random.uniform(20, 80), 1),
                "certification_types": random.sample(["LEED", "BREEAM", "Energy Star", "WELL", "Fitwel"], random.randint(1, 3)),
            },
        },
        "portfolio_summary": {
            "total_assets": num_assets,
            "total_floor_area_sf": num_assets * random.randint(50000, 200000),
            "asset_types": random.sample(["Office", "Retail", "Industrial", "Multifamily", "Mixed-Use"], random.randint(2, 4)),
        },
        "improvement_areas": random.sample([
            "Increase renewable energy procurement",
            "Improve waste data coverage and diversion rates",
            "Pursue additional green building certifications",
            "Enhance Scope 3 emissions tracking",
            "Implement tenant engagement programs",
        ], random.randint(2, 4)),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def assess_climate_risk(property_id: str) -> str:
    """Assess physical and transition climate risks for a property.

    Evaluates both physical risks (flooding, heat stress, storms) and
    transition risks (regulation, market shifts, technology) that may
    impact property value and operations under different climate scenarios.

    Args:
        property_id: The property identifier to assess climate risk for.

    Returns:
        JSON string with physical and transition risk assessment and adaptation recommendations.
    """
    overall_risk = random.choice(["LOW", "MODERATE", "HIGH", "VERY_HIGH"])

    physical_risks = {
        "flood_risk": {
            "rating": random.choice(["MINIMAL", "LOW", "MODERATE", "HIGH"]),
            "fema_zone": random.choice(["X", "X500", "AE", "VE"]),
            "sea_level_rise_exposure": random.choice([True, False]),
            "projected_annual_loss": round(random.uniform(0, 500000), 2),
        },
        "heat_stress": {
            "rating": random.choice(["LOW", "MODERATE", "HIGH"]),
            "cooling_degree_days_increase_pct": round(random.uniform(5, 40), 1),
            "hvac_cost_impact_pct": round(random.uniform(5, 25), 1),
        },
        "wind_storm": {
            "rating": random.choice(["LOW", "MODERATE", "HIGH"]),
            "hurricane_exposure": random.choice([True, False]),
            "tornado_risk_zone": random.choice(["LOW", "MODERATE", "HIGH"]),
        },
        "wildfire": {
            "rating": random.choice(["MINIMAL", "LOW", "MODERATE", "HIGH"]),
            "wui_classification": random.choice(["Urban", "Suburban", "Interface", "Intermix"]),
        },
        "water_stress": {
            "rating": random.choice(["LOW", "MEDIUM", "HIGH"]),
            "baseline_water_stress": random.choice(["Low", "Low-Medium", "Medium-High", "High"]),
        },
    }

    transition_risks = {
        "regulatory": {
            "building_performance_standards": random.choice(["ENACTED", "PROPOSED", "NONE"]),
            "carbon_pricing_exposure": random.choice([True, False]),
            "compliance_cost_annual": round(random.uniform(0, 200000), 2),
            "stranding_risk_year": random.choice([2030, 2035, 2040, None]),
        },
        "market": {
            "green_premium_demand": random.choice(["STRONG", "MODERATE", "WEAK"]),
            "brown_discount_risk_pct": round(random.uniform(0, 15), 1),
            "tenant_esg_requirements_trend": "INCREASING",
        },
        "technology": {
            "electrification_readiness": random.choice(["HIGH", "MEDIUM", "LOW"]),
            "obsolescence_risk": random.choice(["LOW", "MEDIUM", "HIGH"]),
        },
    }

    adaptation_measures = random.sample([
        {"measure": "Elevate critical infrastructure above flood level", "cost": round(random.uniform(50000, 500000), 2)},
        {"measure": "Install flood barriers and sump systems", "cost": round(random.uniform(25000, 200000), 2)},
        {"measure": "Upgrade HVAC for increased cooling capacity", "cost": round(random.uniform(100000, 1000000), 2)},
        {"measure": "Improve stormwater management systems", "cost": round(random.uniform(50000, 300000), 2)},
        {"measure": "Install on-site renewable energy and storage", "cost": round(random.uniform(200000, 2000000), 2)},
        {"measure": "Electrify building systems to reduce carbon", "cost": round(random.uniform(150000, 1500000), 2)},
    ], random.randint(3, 5))

    return json.dumps({
        "property_id": property_id,
        "overall_climate_risk": overall_risk,
        "scenario_used": random.choice(["RCP 4.5 (moderate)", "RCP 8.5 (high emissions)", "SSP2-4.5"]),
        "time_horizon_years": random.choice([10, 20, 30]),
        "physical_risks": physical_risks,
        "transition_risks": transition_risks,
        "value_at_risk": {
            "current_property_value": round(random.uniform(5000000, 100000000), 2),
            "climate_adjusted_value_impact_pct": round(random.uniform(-20, -1), 1),
            "insurance_cost_increase_pct": round(random.uniform(5, 50), 1),
        },
        "adaptation_measures": adaptation_measures,
        "resilience_score": round(random.uniform(30, 90), 1),
        "assessed_at": datetime.utcnow().isoformat() + "Z",
    })
