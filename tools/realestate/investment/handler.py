"""Gateway target: investment — cap rate, rental income, ROI, property comparison.

Financial formulas (mortgage amortization, cap rate, cash-on-cash) are exact;
market assumptions (rents, vacancy, appreciation) are deterministic simulations
seeded from the function inputs.
"""
import hashlib
import random

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch
from toolkit.responses import parse_json_arg

RENT_RANGES = {
    "single_family": (1500, 5000),
    "condo": (1200, 4000),
    "townhouse": (1400, 4500),
    "multi_family": (800, 2500),
    "duplex": (1000, 3000),
}


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _annual_mortgage(loan: float, rate_pct: float, years: int = 30) -> float:
    monthly_rate = rate_pct / 100 / 12
    n = years * 12
    if loan <= 0 or monthly_rate <= 0:
        return 0.0
    monthly = loan * (monthly_rate * (1 + monthly_rate) ** n) / ((1 + monthly_rate) ** n - 1)
    return round(monthly * 12, 2)


def calculate_cap_rate(purchase_price: float, annual_noi: float) -> dict:
    purchase_price, annual_noi = float(purchase_price), float(annual_noi)
    if purchase_price <= 0:
        return tool_error("Purchase price must be positive.")
    if annual_noi < 0:
        return tool_error("Annual NOI cannot be negative.")

    r = _rng("cap_rate", purchase_price, annual_noi)
    cap_rate = round(annual_noi / purchase_price * 100, 2)
    gross_income = annual_noi / r.uniform(0.55, 0.75)
    grm = round(purchase_price / gross_income, 2) if gross_income > 0 else 0
    units = r.randint(1, 20)
    market_avg_cap = round(r.uniform(4.0, 8.0), 2)

    if cap_rate > market_avg_cap + 1:
        assessment = ("Above-market cap rate suggests potentially higher risk or undervalued "
                      "property. Good value opportunity if risks are manageable.")
    elif cap_rate < market_avg_cap - 1:
        assessment = ("Below-market cap rate indicates premium property or potential "
                      "overpayment. Typical of prime locations with lower risk.")
    else:
        assessment = ("Cap rate is in line with market averages. Risk-return profile is "
                      "consistent with local market conditions.")

    return tool_ok({
        "purchase_price": purchase_price,
        "annual_noi": annual_noi,
        "cap_rate_pct": cap_rate,
        "gross_rent_multiplier": grm,
        "estimated_gross_income": round(gross_income, 2),
        "operating_expense_ratio": (round((1 - annual_noi / gross_income) * 100, 1)
                                    if gross_income > 0 else 0),
        "per_unit_analysis": {
            "estimated_units": units,
            "price_per_unit": round(purchase_price / units, 2),
            "noi_per_unit": round(annual_noi / units, 2),
        },
        "market_comparison": {
            "market_avg_cap_rate": market_avg_cap,
            "difference_from_market": round(cap_rate - market_avg_cap, 2),
            "assessment": assessment,
        },
        "valuation_at_market_cap": (round(annual_noi / (market_avg_cap / 100))
                                    if market_avg_cap > 0 else 0),
    }, simulated=True)


def analyze_rental_income(address: str, property_type: str) -> dict:
    property_type = property_type.lower()
    if property_type not in RENT_RANGES:
        return tool_error(f"Invalid property_type: {property_type}", valid=sorted(RENT_RANGES))
    r = _rng("rental_income", address.lower(), property_type)

    monthly_rent = r.randint(*RENT_RANGES[property_type])
    units = r.randint(2, 8) if property_type in ("multi_family", "duplex") else 1
    total_monthly_rent = monthly_rent * units
    annual_gross_rent = total_monthly_rent * 12

    vacancy_rate = round(r.uniform(3, 10), 1)
    effective_gross_income = round(annual_gross_rent * (1 - vacancy_rate / 100), 2)
    other_income = round(r.uniform(0, annual_gross_rent * 0.05), 2)
    total_effective_income = round(effective_gross_income + other_income, 2)

    property_tax = round(annual_gross_rent * r.uniform(0.08, 0.18), 2)
    insurance = round(annual_gross_rent * r.uniform(0.03, 0.08), 2)
    maintenance = round(annual_gross_rent * r.uniform(0.05, 0.12), 2)
    property_management = round(annual_gross_rent * r.uniform(0.06, 0.10), 2)
    utilities = round(r.uniform(0, annual_gross_rent * 0.05), 2)
    reserves = round(annual_gross_rent * r.uniform(0.03, 0.07), 2)
    hoa = round(r.uniform(0, 500) * 12, 2) if property_type in ("condo", "townhouse") else 0

    total_expenses = round(property_tax + insurance + maintenance + property_management
                           + utilities + reserves + hoa, 2)
    noi = round(total_effective_income - total_expenses, 2)

    estimated_value = round(r.uniform(250000, 1200000))
    annual_mortgage = _annual_mortgage(estimated_value * 0.75, 6.5)
    annual_cash_flow = round(noi - annual_mortgage, 2)

    return tool_ok({
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
            "expense_ratio_pct": round(total_expenses / annual_gross_rent * 100, 1),
        },
        "net_operating_income": {
            "annual_noi": noi,
            "monthly_noi": round(noi / 12, 2),
        },
        "cash_flow_estimate": {
            "estimated_property_value": estimated_value,
            "estimated_annual_mortgage": annual_mortgage,
            "annual_cash_flow": annual_cash_flow,
            "monthly_cash_flow": round(annual_cash_flow / 12, 2),
        },
        "rent_comparables": {
            "market_avg_rent": round(monthly_rent * r.uniform(0.9, 1.1)),
            "rent_range_low": round(monthly_rent * 0.85),
            "rent_range_high": round(monthly_rent * 1.15),
            "rent_trend_yoy_pct": round(r.uniform(1, 8), 1),
        },
    }, simulated=True)


def calculate_roi(purchase_price: float, down_payment_pct: float, interest_rate: float,
                  rental_income: float, expenses: float) -> dict:
    purchase_price = float(purchase_price)
    down_payment_pct, interest_rate = float(down_payment_pct), float(interest_rate)
    rental_income, expenses = float(rental_income), float(expenses)
    if purchase_price <= 0:
        return tool_error("Purchase price must be positive.")
    if down_payment_pct <= 0 or down_payment_pct > 100:
        return tool_error("Down payment percentage must be between 0 and 100.")

    r = _rng("roi", purchase_price, down_payment_pct, interest_rate,
             rental_income, expenses)
    down_payment = round(purchase_price * down_payment_pct / 100, 2)
    loan_amount = round(purchase_price - down_payment, 2)
    closing_costs = round(purchase_price * r.uniform(0.02, 0.04), 2)
    total_cash_invested = round(down_payment + closing_costs, 2)

    annual_mortgage = _annual_mortgage(loan_amount, interest_rate)
    monthly_payment = round(annual_mortgage / 12, 2)

    noi = round(rental_income - expenses, 2)
    annual_cash_flow = round(noi - annual_mortgage, 2)
    cash_on_cash = (round(annual_cash_flow / total_cash_invested * 100, 2)
                    if total_cash_invested > 0 else 0)

    year1_interest = round(loan_amount * interest_rate / 100, 2)
    year1_principal = round(annual_mortgage - year1_interest, 2)
    appreciation_rate = round(r.uniform(2, 6), 1)
    depreciation_annual = round(purchase_price * 0.8 / 27.5, 2)

    projections = []
    cumulative_cash_flow = 0.0
    balance = loan_amount
    property_value = purchase_price
    for year in range(1, 6):
        property_value = round(property_value * (1 + appreciation_rate / 100))
        year_interest = round(balance * interest_rate / 100, 2)
        year_principal = round(annual_mortgage - year_interest, 2)
        balance = round(max(0, balance - year_principal), 2)
        year_cash_flow = round(annual_cash_flow * (1 + 0.02 * year), 2)
        cumulative_cash_flow += year_cash_flow
        projections.append({
            "year": year,
            "property_value": property_value,
            "loan_balance": balance,
            "equity": round(property_value - balance),
            "annual_cash_flow": year_cash_flow,
            "cumulative_cash_flow": round(cumulative_cash_flow, 2),
            "estimated_tax_benefit": round(depreciation_annual * 0.28, 2),
        })

    total_5yr_return = round(cumulative_cash_flow
                             + (projections[-1]["property_value"] - purchase_price)
                             + (loan_amount - projections[-1]["loan_balance"]), 2)
    annualized_roi = (round(total_5yr_return / total_cash_invested / 5 * 100, 2)
                      if total_cash_invested > 0 else 0)

    return tool_ok({
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
            "monthly_cash_flow": round(annual_cash_flow / 12, 2),
        },
        "returns": {
            "cash_on_cash_return_pct": cash_on_cash,
            "cap_rate_pct": round(noi / purchase_price * 100, 2),
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
    }, simulated=True)


def get_investment_comparison(properties: str) -> dict:
    props, err = parse_json_arg(properties, "properties")
    if err:
        return tool_error(err)
    if not isinstance(props, list) or not props:
        return tool_error("At least one property is required for comparison.")

    comparisons = []
    for prop in props:
        address = prop.get("address", "Unknown Address")
        r = _rng("invest_compare", address.lower(), prop.get("price", ""))
        price = float(prop.get("price", r.randint(200000, 1000000)))

        monthly_rent = round(price * r.uniform(0.005, 0.01))
        annual_rent = monthly_rent * 12
        vacancy_rate = round(r.uniform(3, 10), 1)
        effective_income = round(annual_rent * (1 - vacancy_rate / 100), 2)
        expense_ratio = round(r.uniform(30, 50), 1)
        expenses = round(effective_income * expense_ratio / 100, 2)
        noi = round(effective_income - expenses, 2)
        cap_rate = round(noi / price * 100, 2) if price > 0 else 0

        down = price * 0.25
        annual_mortgage = _annual_mortgage(price - down, 6.5)
        cash_flow = round(noi - annual_mortgage, 2)
        coc_return = round(cash_flow / down * 100, 2) if down > 0 else 0
        appreciation = round(r.uniform(2, 7), 1)
        risk_score = r.randint(1, 10)

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
            "total_estimated_return_pct": round(coc_return + appreciation, 1),
            "price_to_rent_ratio": round(price / annual_rent, 1) if annual_rent > 0 else 0,
            "risk_score": risk_score,
            "risk_level": "Low" if risk_score <= 3 else "Medium" if risk_score <= 6 else "High",
        })

    comparisons.sort(key=lambda c: c["total_estimated_return_pct"], reverse=True)
    for rank, comp in enumerate(comparisons, 1):
        comp["rank"] = rank

    return tool_ok({
        "property_count": len(comparisons),
        "comparisons": comparisons,
        "recommendation": {
            "best_overall": comparisons[0]["address"],
            "highest_cap_rate": max(comparisons, key=lambda c: c["cap_rate_pct"])["address"],
            "highest_cash_flow": max(comparisons, key=lambda c: c["annual_cash_flow"])["address"],
            "lowest_risk": min(comparisons, key=lambda c: c["risk_score"])["address"],
        },
        "summary": {
            "avg_cap_rate": round(sum(c["cap_rate_pct"] for c in comparisons)
                                  / len(comparisons), 2),
            "avg_coc_return": round(sum(c["cash_on_cash_return_pct"] for c in comparisons)
                                    / len(comparisons), 2),
            "total_capital_required": round(sum(c["purchase_price"] * 0.25
                                                for c in comparisons)),
        },
    }, simulated=True)


TOOLS = {
    "calculate_cap_rate": calculate_cap_rate,
    "analyze_rental_income": analyze_rental_income,
    "calculate_roi": calculate_roi,
    "get_investment_comparison": get_investment_comparison,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
