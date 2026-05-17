"""Returns management tools for the Retail Inventory Assistant.

Provides return reason analysis, disposition determination, return probability
prediction, and return fraud detection for reverse logistics optimization.
"""

import json
import random
from datetime import datetime

from strands import tool


@tool
def analyze_return_reason(return_id: str) -> str:
    """Analyze return reason and categorize into actionable buckets.

    Evaluates the return request to determine root cause classification
    (quality defect, fit/sizing issue, preference change, or potential fraud)
    and recommends appropriate processing path.

    Args:
        return_id: The unique identifier of the return to analyze.

    Returns:
        JSON string with return reason classification, confidence score, and processing recommendation.
    """
    categories = ["QUALITY_DEFECT", "FIT_SIZING", "PREFERENCE_CHANGE", "DAMAGED_IN_TRANSIT", "WRONG_ITEM", "FRAUD"]
    primary_category = random.choice(categories[:-1])  # fraud less likely
    if random.random() > 0.9:
        primary_category = "FRAUD"

    confidence = round(random.uniform(0.7, 0.99), 3)

    sub_reasons = {
        "QUALITY_DEFECT": ["Material defect", "Manufacturing flaw", "Color mismatch", "Premature wear"],
        "FIT_SIZING": ["Too small", "Too large", "Inconsistent with size chart", "Different from photos"],
        "PREFERENCE_CHANGE": ["Changed mind", "Found better option", "No longer needed", "Gift not wanted"],
        "DAMAGED_IN_TRANSIT": ["Crushed packaging", "Water damage", "Missing components", "Broken seal"],
        "WRONG_ITEM": ["Incorrect size sent", "Wrong color", "Wrong product entirely", "Missing items from order"],
        "FRAUD": ["Wardrobing suspected", "Empty box return", "Counterfeit swap", "Serial number mismatch"],
    }

    return json.dumps({
        "return_id": return_id,
        "primary_category": primary_category,
        "confidence": confidence,
        "sub_reason": random.choice(sub_reasons[primary_category]),
        "customer_stated_reason": random.choice([
            "Item did not match description",
            "Does not fit properly",
            "Quality not as expected",
            "Arrived damaged",
            "Changed my mind",
        ]),
        "processing_recommendation": {
            "action": "FULL_REFUND" if primary_category in ["QUALITY_DEFECT", "WRONG_ITEM", "DAMAGED_IN_TRANSIT"]
            else "EXCHANGE_OFFER" if primary_category == "FIT_SIZING"
            else "INVESTIGATE" if primary_category == "FRAUD"
            else "STANDARD_RETURN",
            "priority": "HIGH" if primary_category in ["FRAUD", "QUALITY_DEFECT"] else "STANDARD",
            "requires_inspection": primary_category in ["QUALITY_DEFECT", "FRAUD", "DAMAGED_IN_TRANSIT"],
        },
        "product_feedback": {
            "quality_signal": primary_category == "QUALITY_DEFECT",
            "sizing_signal": primary_category == "FIT_SIZING",
            "description_accuracy_flag": primary_category == "PREFERENCE_CHANGE",
        },
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def determine_disposition(return_id: str) -> str:
    """Determine optimal disposition path for a returned item.

    Evaluates item condition, product value, market demand, and logistics
    costs to recommend the best disposition action (resell, refurbish,
    liquidate, or donate).

    Args:
        return_id: The return identifier to determine disposition for.

    Returns:
        JSON string with disposition recommendation, value recovery estimate, and logistics details.
    """
    item_condition = random.choice(["NEW_UNOPENED", "LIKE_NEW", "GOOD", "FAIR", "POOR", "DAMAGED"])
    original_price = round(random.uniform(15, 500), 2)

    condition_multipliers = {
        "NEW_UNOPENED": 0.95,
        "LIKE_NEW": 0.80,
        "GOOD": 0.60,
        "FAIR": 0.35,
        "POOR": 0.15,
        "DAMAGED": 0.05,
    }

    recovery_value = round(original_price * condition_multipliers[item_condition], 2)

    if item_condition in ["NEW_UNOPENED", "LIKE_NEW"]:
        disposition = "RESELL_AS_NEW" if item_condition == "NEW_UNOPENED" else "RESELL_OPEN_BOX"
    elif item_condition == "GOOD":
        disposition = random.choice(["RESELL_REFURBISHED", "LIQUIDATE_BULK"])
    elif item_condition == "FAIR":
        disposition = random.choice(["LIQUIDATE_BULK", "DONATE"])
    else:
        disposition = random.choice(["RECYCLE", "DISPOSE", "DONATE"])

    processing_cost = round(random.uniform(2, 25), 2)
    net_recovery = round(recovery_value - processing_cost, 2)

    return json.dumps({
        "return_id": return_id,
        "item_condition": item_condition,
        "original_price": original_price,
        "disposition": disposition,
        "value_recovery": {
            "estimated_recovery_value": recovery_value,
            "recovery_pct": round(condition_multipliers[item_condition] * 100, 1),
            "processing_cost": processing_cost,
            "net_recovery_value": net_recovery,
        },
        "logistics": {
            "destination": random.choice([
                "Primary warehouse - returns processing",
                "Secondary market channel",
                "Liquidation partner",
                "Donation center",
                "Recycling facility",
            ]),
            "estimated_processing_days": random.randint(1, 10),
            "requires_refurbishment": item_condition in ["GOOD", "FAIR"],
            "refurbishment_cost": round(random.uniform(5, 50), 2) if item_condition in ["GOOD", "FAIR"] else 0,
        },
        "determined_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def predict_return_probability(order_id: str) -> str:
    """Predict return probability for an order before shipment.

    Analyzes order characteristics, customer history, product attributes,
    and seasonal factors to estimate the likelihood of return.

    Args:
        order_id: The order identifier to predict return probability for.

    Returns:
        JSON string with return probability, risk factors, and intervention recommendations.
    """
    return_probability = round(random.uniform(0.05, 0.60), 3)

    if return_probability > 0.4:
        risk_level = "HIGH"
    elif return_probability > 0.2:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    risk_factors = random.sample([
        {"factor": "Category has high return rate (apparel)", "weight": round(random.uniform(0.1, 0.3), 2)},
        {"factor": "Customer has above-average return history", "weight": round(random.uniform(0.1, 0.25), 2)},
        {"factor": "Multiple sizes ordered (bracketing behavior)", "weight": round(random.uniform(0.15, 0.35), 2)},
        {"factor": "First-time purchase of this brand", "weight": round(random.uniform(0.05, 0.15), 2)},
        {"factor": "Product has inconsistent reviews on fit", "weight": round(random.uniform(0.05, 0.2), 2)},
        {"factor": "Promotional/impulse purchase indicator", "weight": round(random.uniform(0.05, 0.15), 2)},
        {"factor": "Gift purchase (higher preference returns)", "weight": round(random.uniform(0.05, 0.15), 2)},
    ], random.randint(2, 5))

    interventions = []
    if return_probability > 0.3:
        interventions = random.sample([
            "Show enhanced size guide before checkout",
            "Display customer reviews mentioning fit",
            "Offer virtual try-on tool",
            "Suggest alternative product with lower return rate",
            "Include personalized fit recommendation",
        ], random.randint(1, 3))

    order_value = round(random.uniform(25, 500), 2)
    expected_return_cost = round(order_value * return_probability * 0.3, 2)

    return json.dumps({
        "order_id": order_id,
        "return_probability": return_probability,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "order_details": {
            "order_value": order_value,
            "items_count": random.randint(1, 5),
            "category": random.choice(["Apparel", "Electronics", "Home & Garden", "Footwear", "Accessories"]),
        },
        "financial_impact": {
            "expected_return_cost": expected_return_cost,
            "shipping_cost_at_risk": round(random.uniform(5, 15), 2),
            "restocking_cost_estimate": round(random.uniform(3, 20), 2),
        },
        "recommended_interventions": interventions,
        "predicted_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def detect_return_fraud(customer_id: str, return_id: str) -> str:
    """Detect potential return fraud patterns for a customer and return.

    Analyzes customer return behavior, item characteristics, and known fraud
    patterns to identify potentially fraudulent return activity.

    Args:
        customer_id: The customer identifier to evaluate.
        return_id: The specific return request to assess.

    Returns:
        JSON string with fraud risk score, detected patterns, and recommended action.
    """
    fraud_score = round(random.uniform(0, 1), 3)

    fraud_patterns = []
    all_patterns = [
        {"pattern": "Wardrobing - item shows signs of use (tags reattached)", "severity": "HIGH"},
        {"pattern": "Frequent returns of high-value items", "severity": "HIGH"},
        {"pattern": "Serial returner - return rate exceeds 50%", "severity": "MEDIUM"},
        {"pattern": "Return timing coincides with event dates", "severity": "MEDIUM"},
        {"pattern": "Price switching - tags from lower-priced item", "severity": "HIGH"},
        {"pattern": "Empty box/missing item claims on delivery", "severity": "HIGH"},
        {"pattern": "Multiple accounts linked to same address", "severity": "MEDIUM"},
        {"pattern": "Returns concentrated in high-value categories only", "severity": "LOW"},
    ]

    num_patterns = max(0, int(fraud_score * 4))
    fraud_patterns = random.sample(all_patterns, min(num_patterns, len(all_patterns)))

    if fraud_score > 0.7:
        recommendation = "BLOCK_RETURN"
        action_level = "ESCALATE_TO_FRAUD_TEAM"
    elif fraud_score > 0.4:
        recommendation = "REQUIRE_INSPECTION"
        action_level = "ENHANCED_REVIEW"
    else:
        recommendation = "APPROVE_RETURN"
        action_level = "STANDARD_PROCESSING"

    return json.dumps({
        "customer_id": customer_id,
        "return_id": return_id,
        "fraud_risk_score": fraud_score,
        "recommendation": recommendation,
        "action_level": action_level,
        "detected_patterns": fraud_patterns,
        "customer_return_profile": {
            "total_orders_12m": random.randint(5, 50),
            "total_returns_12m": random.randint(1, 25),
            "return_rate_pct": round(random.uniform(10, 60), 1),
            "total_refund_amount_12m": round(random.uniform(100, 5000), 2),
            "avg_return_value": round(random.uniform(30, 200), 2),
        },
        "policy_actions_available": [
            "Ban from returns",
            "Require photo evidence",
            "Mandatory in-store return",
            "Reduce return window",
            "Charge restocking fee",
        ],
        "assessed_at": datetime.utcnow().isoformat() + "Z",
    })
