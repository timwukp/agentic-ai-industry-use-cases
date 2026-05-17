from strands import tool
import json
import random
from datetime import datetime, timedelta


@tool
def extract_lease_terms(lease_id: str) -> str:
    """Extract key terms from a commercial lease agreement.

    Parses and extracts all material business terms from a commercial lease
    including rent structure, escalations, options, and obligations.

    Args:
        lease_id: The lease identifier to extract terms from.

    Returns:
        JSON string with extracted lease terms organized by category.
    """
    base_rent_psf = round(random.uniform(15, 85), 2)
    square_footage = random.randint(1000, 50000)
    annual_rent = round(base_rent_psf * square_footage, 2)

    lease_start = datetime.utcnow() - timedelta(days=random.randint(365, 3650))
    lease_term_years = random.choice([3, 5, 7, 10, 15])
    lease_end = lease_start + timedelta(days=lease_term_years * 365)

    return json.dumps({
        "lease_id": lease_id,
        "extraction_status": "COMPLETE",
        "premises": {
            "address": f"{random.randint(100, 9999)} {random.choice(['Main', 'Commerce', 'Park', 'Technology'])} "
                       f"{random.choice(['Street', 'Avenue', 'Boulevard', 'Drive'])}",
            "suite": f"Suite {random.randint(100, 5000)}",
            "rentable_sf": square_footage,
            "usable_sf": int(square_footage * random.uniform(0.85, 0.95)),
            "floor": random.randint(1, 30),
        },
        "financial_terms": {
            "base_rent_psf": base_rent_psf,
            "annual_base_rent": annual_rent,
            "monthly_base_rent": round(annual_rent / 12, 2),
            "rent_escalation": {
                "type": random.choice(["FIXED", "CPI", "MARKET"]),
                "rate_pct": round(random.uniform(2, 4), 1),
                "frequency": "Annual",
            },
            "expense_structure": random.choice(["NNN", "MODIFIED_GROSS", "FULL_SERVICE", "INDUSTRIAL_GROSS"]),
            "cam_estimate_psf": round(random.uniform(5, 20), 2),
            "tenant_improvement_allowance_psf": round(random.uniform(0, 80), 2),
        },
        "term": {
            "commencement_date": lease_start.strftime("%Y-%m-%d"),
            "expiration_date": lease_end.strftime("%Y-%m-%d"),
            "term_years": lease_term_years,
            "remaining_term_months": max(0, int((lease_end - datetime.utcnow()).days / 30)),
            "free_rent_months": random.randint(0, 6),
        },
        "options": {
            "renewal_options": random.randint(0, 2),
            "renewal_term_years": random.choice([3, 5]),
            "renewal_rate": random.choice(["Fair Market Value", "CPI Adjusted", "Fixed 3% increase"]),
            "expansion_option": random.choice([True, False]),
            "early_termination": random.choice([True, False, False]),
            "termination_fee_months": random.randint(3, 12) if random.random() > 0.5 else None,
        },
        "obligations": {
            "security_deposit": round(annual_rent / 12 * random.randint(1, 3), 2),
            "insurance_requirements": ["General Liability", "Property", "Workers Comp"],
            "maintenance_responsibilities": random.choice([
                "Tenant responsible for interior only",
                "Landlord responsible for structure and systems",
                "NNN - Tenant responsible for all maintenance",
            ]),
        },
        "extracted_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def track_critical_dates(portfolio_id: str) -> str:
    """Track all critical dates across a lease portfolio.

    Monitors and alerts on upcoming critical dates including expirations,
    option exercise deadlines, rent escalations, and notice periods.

    Args:
        portfolio_id: The portfolio identifier to track critical dates for.

    Returns:
        JSON string with upcoming critical dates sorted by urgency.
    """
    num_leases = random.randint(10, 50)
    critical_dates = []

    date_types = [
        "Lease Expiration",
        "Renewal Option Exercise Deadline",
        "Rent Escalation Date",
        "Early Termination Notice Deadline",
        "Expansion Option Exercise",
        "Insurance Certificate Renewal",
        "Operating Expense Reconciliation Due",
        "Tenant Improvement Completion Deadline",
        "CAM Audit Right Expiration",
        "Security Deposit Reduction Date",
    ]

    for _ in range(random.randint(8, 15)):
        days_until = random.randint(-30, 365)
        date_type = random.choice(date_types)
        event_date = datetime.utcnow() + timedelta(days=days_until)

        if days_until < 0:
            status = "OVERDUE"
            urgency = "CRITICAL"
        elif days_until <= 30:
            status = "IMMINENT"
            urgency = "HIGH"
        elif days_until <= 90:
            status = "APPROACHING"
            urgency = "MEDIUM"
        else:
            status = "SCHEDULED"
            urgency = "LOW"

        critical_dates.append({
            "lease_id": f"LSE-{random.randint(1000, 9999)}",
            "tenant": random.choice(["Acme Corp", "TechStart Inc", "Global Retail LLC",
                                     "MedGroup Associates", "DataFlow Systems", "Green Energy Co"]),
            "date_type": date_type,
            "event_date": event_date.strftime("%Y-%m-%d"),
            "days_until": days_until,
            "status": status,
            "urgency": urgency,
            "action_required": random.choice([
                "Notify tenant of upcoming deadline",
                "Prepare renewal proposal",
                "Calculate escalation amount",
                "Send notice letter",
                "Review and exercise/waive option",
            ]),
        })

    critical_dates.sort(key=lambda x: x["days_until"])

    overdue = sum(1 for d in critical_dates if d["status"] == "OVERDUE")
    imminent = sum(1 for d in critical_dates if d["status"] == "IMMINENT")

    return json.dumps({
        "portfolio_id": portfolio_id,
        "total_leases": num_leases,
        "critical_dates": critical_dates,
        "summary": {
            "total_critical_dates": len(critical_dates),
            "overdue": overdue,
            "imminent_30_days": imminent,
            "approaching_90_days": sum(1 for d in critical_dates if d["status"] == "APPROACHING"),
            "scheduled": sum(1 for d in critical_dates if d["status"] == "SCHEDULED"),
        },
        "immediate_attention_required": overdue + imminent,
        "tracked_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def calculate_lease_liability(lease_id: str) -> str:
    """Calculate ASC 842/IFRS 16 right-of-use asset and lease liability.

    Computes the lease accounting entries required under ASC 842 (US GAAP)
    or IFRS 16 including present value calculations, amortization schedules,
    and disclosure requirements.

    Args:
        lease_id: The lease identifier to calculate liability for.

    Returns:
        JSON string with lease liability calculations and accounting entries.
    """
    remaining_months = random.randint(12, 120)
    monthly_payment = round(random.uniform(5000, 100000), 2)
    annual_escalation_pct = round(random.uniform(2, 4), 1)
    discount_rate = round(random.uniform(4, 8), 2)

    total_undiscounted_payments = 0
    payment_schedule = []
    current_payment = monthly_payment
    for year in range(1, min(remaining_months // 12 + 2, 11)):
        annual_payment = round(current_payment * 12, 2)
        total_undiscounted_payments += annual_payment
        payment_schedule.append({
            "year": year,
            "annual_payment": annual_payment,
            "monthly_payment": round(current_payment, 2),
        })
        current_payment *= (1 + annual_escalation_pct / 100)

    discount_factor = 1 / (1 + discount_rate / 100)
    present_value = sum(
        p["annual_payment"] * (discount_factor ** p["year"]) for p in payment_schedule
    )
    present_value = round(present_value, 2)

    initial_rou_asset = present_value
    initial_direct_costs = round(random.uniform(5000, 50000), 2)
    rou_asset = round(initial_rou_asset + initial_direct_costs, 2)

    return json.dumps({
        "lease_id": lease_id,
        "accounting_standard": random.choice(["ASC 842", "IFRS 16"]),
        "lease_classification": random.choice(["OPERATING", "FINANCE"]),
        "calculation_inputs": {
            "remaining_lease_term_months": remaining_months,
            "monthly_base_payment": monthly_payment,
            "annual_escalation_pct": annual_escalation_pct,
            "discount_rate_pct": discount_rate,
            "initial_direct_costs": initial_direct_costs,
        },
        "lease_liability": {
            "initial_measurement": present_value,
            "current_balance": round(present_value * random.uniform(0.7, 1.0), 2),
            "current_portion": round(payment_schedule[0]["annual_payment"] * 0.9, 2) if payment_schedule else 0,
            "non_current_portion": round(present_value * random.uniform(0.5, 0.85), 2),
        },
        "right_of_use_asset": {
            "initial_measurement": rou_asset,
            "accumulated_amortization": round(rou_asset * random.uniform(0.05, 0.4), 2),
            "carrying_value": round(rou_asset * random.uniform(0.6, 0.95), 2),
        },
        "payment_schedule_summary": payment_schedule[:5],
        "total_undiscounted_payments": round(total_undiscounted_payments, 2),
        "disclosure_requirements": {
            "weighted_avg_remaining_term_years": round(remaining_months / 12, 1),
            "weighted_avg_discount_rate_pct": discount_rate,
            "variable_lease_payments": round(random.uniform(0, monthly_payment * 3), 2),
        },
        "calculated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def predict_tenant_churn(tenant_id: str) -> str:
    """Predict tenant churn probability for a commercial lease tenant.

    Analyzes tenant financial health, market conditions, space utilization,
    and relationship signals to predict the likelihood of non-renewal
    or early termination.

    Args:
        tenant_id: The tenant identifier to predict churn risk for.

    Returns:
        JSON string with churn probability, risk factors, and retention recommendations.
    """
    churn_probability = round(random.uniform(0.05, 0.75), 3)

    if churn_probability > 0.5:
        risk_level = "HIGH"
    elif churn_probability > 0.25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    risk_factors = random.sample([
        {"factor": "Tenant business revenue declining", "impact": round(random.uniform(0.1, 0.3), 2)},
        {"factor": "Space utilization below 60%", "impact": round(random.uniform(0.1, 0.25), 2)},
        {"factor": "Above-market rent relative to comparable spaces", "impact": round(random.uniform(0.1, 0.2), 2)},
        {"factor": "Lease expiration within 12 months", "impact": round(random.uniform(0.05, 0.15), 2)},
        {"factor": "Recent organizational restructuring", "impact": round(random.uniform(0.1, 0.25), 2)},
        {"factor": "Multiple maintenance complaints unresolved", "impact": round(random.uniform(0.05, 0.15), 2)},
        {"factor": "Competitor offering significant incentives nearby", "impact": round(random.uniform(0.1, 0.2), 2)},
        {"factor": "Remote work policy reducing space needs", "impact": round(random.uniform(0.1, 0.25), 2)},
    ], random.randint(2, 5))

    tenant_health = {
        "credit_rating": random.choice(["AAA", "AA", "A", "BBB", "BB", "B"]),
        "payment_history": random.choice(["ALWAYS_ON_TIME", "OCCASIONALLY_LATE", "FREQUENTLY_LATE"]),
        "years_as_tenant": round(random.uniform(1, 15), 1),
        "space_utilization_pct": round(random.uniform(40, 95), 1),
        "sublease_inquiries": random.choice([True, False, False, False]),
    }

    retention_strategies = []
    if churn_probability > 0.3:
        retention_strategies = random.sample([
            "Offer early renewal with below-market escalation",
            "Propose space reconfiguration to match current needs",
            "Provide tenant improvement allowance for renewal",
            "Implement dedicated property management contact",
            "Offer flexible expansion/contraction rights",
            "Create customized amenity package",
        ], random.randint(2, 4))

    return json.dumps({
        "tenant_id": tenant_id,
        "churn_probability": churn_probability,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "tenant_health_indicators": tenant_health,
        "financial_impact_if_churns": {
            "annual_revenue_at_risk": round(random.uniform(50000, 2000000), 2),
            "estimated_downtime_months": random.randint(3, 18),
            "re_leasing_cost": round(random.uniform(20000, 500000), 2),
            "ti_for_new_tenant": round(random.uniform(50000, 1000000), 2),
        },
        "retention_strategies": retention_strategies,
        "recommended_action": (
            "Initiate proactive renewal discussion immediately" if risk_level == "HIGH"
            else "Schedule tenant satisfaction meeting" if risk_level == "MEDIUM"
            else "Standard relationship maintenance"
        ),
        "predicted_at": datetime.utcnow().isoformat() + "Z",
    })
