"""Single source of truth for per-industry deploy metadata.

Finance is bespoke (own stack with DynamoDB + dashboard API); the rest share
the parameterized IndustryStack and differ only in names/targets.
"""

# tools/<industry>/schemas/<stem>.json ; gateway target names must match
# ([0-9a-zA-Z][-]?)+ — no underscores, so each entry maps target -> schema stem.
INDUSTRIES = {
    "finance": {
        "harness_dir": "finance-trading",
        "stack": "AgenticFinanceTools",
        "gateway_name": "finance-trading-gw",
        "targets": {
            "market-data": ("market_data", "ToolLambdaMarketDataArn"),
            "portfolio": ("portfolio", "ToolLambdaPortfolioArn"),
            "risk": ("risk", "ToolLambdaRiskArn"),
            "trading": ("trading", "ToolLambdaTradingArn"),
            "kb": ("kb", "ToolLambdaKbSearchArn"),
        },
    },
    "healthcare": {
        "harness_dir": "healthcare-medical",
        "stack": "AgenticHealthcareTools",
        "gateway_name": "healthcare-medical-gw",
        "targets": {
            "records": ("records", "ToolLambdaRecordsArn"),
            "clinical": ("clinical", "ToolLambdaClinicalArn"),
            "scheduling": ("scheduling", "ToolLambdaSchedulingArn"),
            "analytics": ("analytics", "ToolLambdaAnalyticsArn"),
            "kb": ("kb", "ToolLambdaKbSearchArn"),
        },
    },
    "insurance": {
        "harness_dir": "insurance-claims",
        "stack": "AgenticInsuranceTools",
        "gateway_name": "insurance-claims-gw",
        "targets": {
            "claims": ("claims", "ToolLambdaClaimsArn"),
            "fraud-detection": ("fraud_detection", "ToolLambdaFraudDetectionArn"),
            "policy": ("policy", "ToolLambdaPolicyArn"),
            "settlement": ("settlement", "ToolLambdaSettlementArn"),
            "kb": ("kb", "ToolLambdaKbSearchArn"),
        },
    },
    "retail": {
        "harness_dir": "retail-inventory",
        "stack": "AgenticRetailTools",
        "gateway_name": "retail-inventory-gw",
        "targets": {
            "inventory": ("inventory", "ToolLambdaInventoryArn"),
            "demand-forecast": ("demand_forecast", "ToolLambdaDemandForecastArn"),
            "supplier": ("supplier", "ToolLambdaSupplierArn"),
            "pricing": ("pricing", "ToolLambdaPricingArn"),
            "kb": ("kb", "ToolLambdaKbSearchArn"),
        },
    },
    "manufacturing": {
        "harness_dir": "manufacturing-maintenance",
        "stack": "AgenticManufacturingTools",
        "gateway_name": "manufacturing-maintenance-gw",
        "targets": {
            "equipment": ("equipment", "ToolLambdaEquipmentArn"),
            "prediction": ("prediction", "ToolLambdaPredictionArn"),
            "maintenance": ("maintenance", "ToolLambdaMaintenanceArn"),
            "parts": ("parts", "ToolLambdaPartsArn"),
            "kb": ("kb", "ToolLambdaKbSearchArn"),
        },
    },
    "realestate": {
        "harness_dir": "real-estate-valuation",
        "stack": "AgenticRealestateTools",
        "gateway_name": "real-estate-valuation-gw",
        "targets": {
            "valuation": ("valuation", "ToolLambdaValuationArn"),
            "market": ("market", "ToolLambdaMarketArn"),
            "investment": ("investment", "ToolLambdaInvestmentArn"),
            "property": ("property", "ToolLambdaPropertyArn"),
            "kb": ("kb", "ToolLambdaKbSearchArn"),
        },
    },
}
