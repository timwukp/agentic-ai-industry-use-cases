from strands import tool
import json, random
from datetime import datetime


@tool
def calculate_cap_rate(purchase_price: float, annual_noi: float) -> str:
    """Calculate capitalization rate and related investment metrics.

    Computes cap rate, gross rent multiplier, and price per unit for
    investment property analysis.

    Args:
        purchase_price: Property purchase price or current market value in dollars.
        annual_noi: Annual Net Operating Income in dollars (gross income minus operating expenses).

    Returns:
        JSON with cap rate, GRM, price per unit, and market comparison.
    """
    if purchase_price <= 0:
        return json.dumps({"error": "Purchase price must be positive."})
    if annual_noi < 0:
        return json.dumps({"error": "Annual NOI cannot be negative."})

    cap_rate = round((annual_noi / purchase_price) * 100, 2)

    gross_income = annual_noi / random.uniform(0.55, 0.75)
    grm = round(purchase_price / gross_income, 2) if gross_income > 0 else 0

    units = random.randint(1, 20)
    price_per_unit = round(purchase_price / units, 2)
    noi_per_unit = round(annual_noi / units, 2)

    market_avg_cap = round(random.uniform(4.0, 8.0), 2)

    if cap_rate > market_avg_cap + 1:
        assessment = "Above-market cap rate suggests potentially higher risk or undervalued property. Good value opportunity if risks are manageable."
    elif cap_rate < market_avg_cap - 1:
        assessment = "Below-market cap rate indicates premium property or potential overpayment. Typical of prime locations with lower risk."
    else:
        assessment = "Cap rate is in line with market averages. Risk-return profile is consistent with local market conditions."

    return json.dumps({
        "purchase_price": purchase_price,
        "annual_noi": annual_noi,
        "cap_rate_pct": cap_rate,
        "gross_rent_multiplier": grm,
        "estimated_gross_income": round(gross_income, 2),
        "operating_expense_ratio": round((1 - annual_noi / gross_income) * 100, 1) if gross_income > 0 else 0,
        "per_unit_analysis": {
            "estimated_units": units,
            "price_per_unit": price_per_unit,
            "noi_per_unit": noi_per_unit,
        },
        "market_comparison": {
            "market_avg_cap_rate": market_avg_cap,
            "difference_from_market": round(cap_rate - market_avg_cap, 2),
            "assessment": assessment,
        },
        "valuation_at_market_cap": round(annual_noi / (market_avg_cap / 100), 0) if market_avg_cap > 0 else 0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def analyze_rental_income(address: str, property_type: str) -> str:
    """Analyze rental income potential for a property.

    Estimates achievable rent, vacancy rates, operating expenses,
    net operating income, and projected cash flow.

    Args:
        address: Property address to analyze.
        property_type: Type of property ('single_family', 'condo', 'townhouse', 'multi_family', 'duplex').

    Returns:
        JSON with estimated rent, vacancy rate, operating expenses, NOI, and cash flow analysis.
    """
    rent_ranges = {
        "single_family": (1500, 5000),
        "condo": (1200, 4000),
        "townhouse": (1400, 4500),
        "multi_family": (800, 2500),
        "duplex": (1000, 3000),
    }

    rent_range = rent_ranges.get(property_type, (1200, 3500))
    monthly_rent = random.randint(*rent_range)
    units = random.randint(2, 8) if property_type in ("multi_family", "duplex") else 1
    total_monthly_rent = monthly_rent * units
    annual_gross_rent = total_monthly_rent * 12

    vacancy_rate = round(random.uniform(3, 10), 1)
    effective_gross_income = round(annual_gross_rent * (1 - vacancy_rate / 100), 2)
    other_income = round(random.uniform(0, annual_gross_rent * 0.05), 2)
    total_effective_income = round(effective_gross_income + other_income, 2)

    property_tax = round(annual_gross_rent * random.uniform(0.08, 0.18), 2)
    insurance = round(annual_gross_rent * random.uniform(0.03, 0.08), 2)
    maintenance = round(annual_gross_rent * random.uniform(0.05, 0.12), 2)
    property_management = round(annual_gross_rent * random.uniform(0.06, 0.10), 2)
    utilities = round(random.uniform(0, annual_gross_rent * 0.05), 2)
    reserves = round(annual_gross_rent * random.uniform(0.03, 0.07), 2)
    hoa = round(random.uniform(0, 500) * 12, 2) if property_type in ("condo", "townhouse") else 0

    total_expenses = round(property_tax + insurance + maintenance + property_management + utilities + reserves + hoa, 2)
    expense_ratio = round((total_expenses / annual_gross_rent) * 100, 1)
    noi = round(total_effective_income - total_expenses, 2)
    monthly_noi = round(noi / 12, 2)

    estimated_value = round(random.uniform(250000, 1200000), 0)
    annual_mortgage = round(estimated_value * 0.75 * 0.065 / (1 - (1 + 0.065 / 12) ** -360) * 12, 2)
    annual_cash_flow = round(noi - annual_mortgage, 2)

    return json.dumps({
        "address": address,
        "property_type": property_type,
        "units": units,
        "rental_income": {
            "estimated_monthly_rent_per_unit": monthly_rent,
            "total_monthly_rent": total_monthly_rent,
            "annual_gross_rent": annual_gross_rent,
            "vacancy_rate_pct": vacancy_rate,
            "effective_gross_income": effective_gross_income,
            "other_income": other_income,
            "total_effective_income": total_effective_income,
        },
        "operating_expenses": {
            "property_tax": property_tax,
            "insurance": insurance,
            "maintenance_repairs": maintenance,
            "property_management": property_management,
            "utilities": utilities,
            "capital_reserves": reserves,
            "hoa_fees": hoa,
            "total_expenses": total_expenses,
            "expense_ratio_pct": expense_ratio,
        },
        "net_operating_income": {
            "annual_noi": noi,
            "monthly_noi": monthly_noi,
        },
        "cash_flow_estimate": {
            "estimated_property_value": estimated_value,
            "estimated_annual_mortgage": annual_mortgage,
            "annual_cash_flow": annual_cash_flow,
            "monthly_cash_flow": round(annual_cash_flow / 12, 2),
        },
        "rent_comparables": {
            "market_avg_rent": round(monthly_rent * random.uniform(0.9, 1.1), 0),
            "rent_range_low": round(monthly_rent * 0.85, 0),
            "rent_range_high": round(monthly_rent * 1.15, 0),
            "rent_trend_yoy_pct": round(random.uniform(1, 8), 1),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def calculate_roi(purchase_price: float, down_payment_pct: float, interest_rate: float, rental_income: float, expenses: float) -> str:
    """Calculate comprehensive return on investment metrics for a property.

    Computes cash-on-cash return, projected IRR, equity buildup, mortgage
    analysis, and estimated tax benefits.

    Args:
        purchase_price: Total property purchase price in dollars.
        down_payment_pct: Down payment percentage (e.g., 20.0 for 20%).
        interest_rate: Annual mortgage interest rate percentage (e.g., 6.5 for 6.5%).
        rental_income: Expected annual gross rental income in dollars.
        expenses: Expected annual operating expenses in dollars.

    Returns:
        JSON with cash-on-cash return, IRR, equity buildup, tax benefits, and 5-year projection.
    """
    if purchase_price <= 0:
        return json.dumps({"error": "Purchase price must be positive."})
    if down_payment_pct <= 0 or down_payment_pct > 100:
        return json.dumps({"error": "Down payment percentage must be between 0 and 100."})

    down_payment = round(purchase_price * (down_payment_pct / 100), 2)
    loan_amount = round(purchase_price - down_payment, 2)
    closing_costs = round(purchase_price * random.uniform(0.02, 0.04), 2)
    total_cash_invested = round(down_payment + closing_costs, 2)

    monthly_rate = (interest_rate / 100) / 12
    num_payments = 360
    if loan_amount > 0 and monthly_rate > 0:
        monthly_payment = round(loan_amount * (monthly_rate * (1 + monthly_rate) ** num_payments) / ((1 + monthly_rate) ** num_payments - 1), 2)
    else:
        monthly_payment = 0
    annual_mortgage = round(monthly_payment * 12, 2)

    noi = round(rental_income - expenses, 2)
    annual_cash_flow = round(noi - annual_mortgage, 2)
    monthly_cash_flow = round(annual_cash_flow / 12, 2)

    cash_on_cash = round((annual_cash_flow / total_cash_invested) * 100, 2) if total_cash_invested > 0 else 0

    year1_interest = round(loan_amount * (interest_rate / 100), 2)
    year1_principal = round(annual_mortgage - year1_interest, 2)

    appreciation_rate = round(random.uniform(2, 6), 1)
    depreciation_annual = round(purchase_price * 0.8 / 27.5, 2)

    projections = []
    cumulative_cash_flow = 0
    balance = loan_amount
    property_value = purchase_price
    for year in range(1, 6):
        property_value = round(property_value * (1 + appreciation_rate / 100), 0)
        year_interest = round(balance * (interest_rate / 100), 2)
        year_principal = round(annual_mortgage - year_interest, 2)
        balance = round(max(0, balance - year_principal), 2)
        equity = round(property_value - balance, 0)
        year_cash_flow = round(annual_cash_flow * (1 + 0.02 * year), 2)
        cumulative_cash_flow += year_cash_flow
        tax_benefit = round(depreciation_annual * random.uniform(0.22, 0.37), 2)

        projections.append({
            "year": year,
            "property_value": property_value,
            "loan_balance": balance,
            "equity": equity,
            "annual_cash_flow": year_cash_flow,
            "cumulative_cash_flow": round(cumulative_cash_flow, 2),
            "estimated_tax_benefit": tax_benefit,
            "total_return": round(year_cash_flow + (property_value - purchase_price) / year + year_principal + tax_benefit, 2),
        })

    total_5yr_return = round(
        cumulative_cash_flow + (projections[-1]["property_value"] - purchase_price) + (loan_amount - projections[-1]["loan_balance"]),
        2,
    )
    annualized_roi = round((total_5yr_return / total_cash_invested / 5) * 100, 2) if total_cash_invested > 0 else 0

    return json.dumps({
        "purchase_analysis": {
            "purchase_price": purchase_price,
            "down_payment": down_payment,
            "down_payment_pct": down_payment_pct,
            "loan_amount": loan_amount,
            "closing_costs": closing_costs,
            "total_cash_invested": total_cash_invested,
        },
        "mortgage": {
            "interest_rate_pct": interest_rate,
            "term_years": 30,
            "monthly_payment": monthly_payment,
            "annual_payment": annual_mortgage,
            "year1_interest": year1_interest,
            "year1_principal": year1_principal,
        },
        "income_analysis": {
            "annual_gross_income": rental_income,
            "annual_expenses": expenses,
            "annual_noi": noi,
            "annual_mortgage_payment": annual_mortgage,
            "annual_cash_flow": annual_cash_flow,
            "monthly_cash_flow": monthly_cash_flow,
        },
        "returns": {
            "cash_on_cash_return_pct": cash_on_cash,
            "cap_rate_pct": round((noi / purchase_price) * 100, 2),
            "annualized_total_roi_pct": annualized_roi,
            "appreciation_rate_assumed_pct": appreciation_rate,
        },
        "tax_benefits": {
            "annual_depreciation": depreciation_annual,
            "depreciation_schedule_years": 27.5,
            "estimated_annual_tax_savings": round(depreciation_annual * 0.28, 2),
        },
        "five_year_projection": projections,
        "total_5yr_return": total_5yr_return,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_investment_comparison(properties: str) -> str:
    """Compare multiple investment properties side by side.

    Evaluates and ranks properties based on key investment metrics including
    cap rate, cash-on-cash return, NOI, and risk-adjusted returns.

    Args:
        properties: JSON string of property addresses/details to compare. Format: [{"address": "123 Main St", "price": 500000}, ...].

    Returns:
        JSON with side-by-side comparison of investment metrics and ranking.
    """
    try:
        props = json.loads(properties) if isinstance(properties, str) else properties
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON format for properties. Expected: [{\"address\": \"...\", \"price\": ...}, ...]"})

    if not isinstance(props, list) or len(props) == 0:
        return json.dumps({"error": "At least one property is required for comparison."})

    comparisons = []
    for prop in props:
        address = prop.get("address", "Unknown Address")
        price = prop.get("price", random.randint(200000, 1000000))

        monthly_rent = round(price * random.uniform(0.005, 0.01), 0)
        annual_rent = monthly_rent * 12
        vacancy_rate = round(random.uniform(3, 10), 1)
        effective_income = round(annual_rent * (1 - vacancy_rate / 100), 2)
        expense_ratio = round(random.uniform(30, 50), 1)
        expenses = round(effective_income * (expense_ratio / 100), 2)
        noi = round(effective_income - expenses, 2)
        cap_rate = round((noi / price) * 100, 2) if price > 0 else 0

        down = price * 0.25
        loan = price - down
        annual_mortgage = round(loan * 0.065 / (1 - (1 + 0.065 / 12) ** -360) * 12, 2)
        cash_flow = round(noi - annual_mortgage, 2)
        coc_return = round((cash_flow / down) * 100, 2) if down > 0 else 0
        appreciation = round(random.uniform(2, 7), 1)
        total_return = round(coc_return + appreciation, 1)

        risk_score = random.randint(1, 10)
        risk_label = "Low" if risk_score <= 3 else "Medium" if risk_score <= 6 else "High"

        comparisons.append({
            "address": address,
            "purchase_price": price,
            "estimated_monthly_rent": monthly_rent,
            "annual_gross_income": annual_rent,
            "vacancy_rate_pct": vacancy_rate,
            "expense_ratio_pct": expense_ratio,
            "annual_noi": noi,
            "cap_rate_pct": cap_rate,
            "annual_cash_flow": cash_flow,
            "monthly_cash_flow": round(cash_flow / 12, 2),
            "cash_on_cash_return_pct": coc_return,
            "estimated_appreciation_pct": appreciation,
            "total_estimated_return_pct": total_return,
            "price_to_rent_ratio": round(price / annual_rent, 1) if annual_rent > 0 else 0,
            "risk_score": risk_score,
            "risk_level": risk_label,
        })

    comparisons.sort(key=lambda c: c["total_estimated_return_pct"], reverse=True)
    for rank, comp in enumerate(comparisons, 1):
        comp["rank"] = rank

    best = comparisons[0]

    return json.dumps({
        "property_count": len(comparisons),
        "comparisons": comparisons,
        "recommendation": {
            "best_overall": best["address"],
            "highest_cap_rate": max(comparisons, key=lambda c: c["cap_rate_pct"])["address"],
            "highest_cash_flow": max(comparisons, key=lambda c: c["annual_cash_flow"])["address"],
            "lowest_risk": min(comparisons, key=lambda c: c["risk_score"])["address"],
            "best_appreciation": max(comparisons, key=lambda c: c["estimated_appreciation_pct"])["address"],
        },
        "summary": {
            "avg_cap_rate": round(sum(c["cap_rate_pct"] for c in comparisons) / len(comparisons), 2),
            "avg_coc_return": round(sum(c["cash_on_cash_return_pct"] for c in comparisons) / len(comparisons), 2),
            "total_capital_required": sum(round(c["purchase_price"] * 0.25, 0) for c in comparisons),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
