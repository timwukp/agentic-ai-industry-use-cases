#!/usr/bin/env python3
"""CDK Application entry point for all industry agentic AI infrastructure."""
import os
import aws_cdk as cdk
from shared_stack import SharedInfraStack
from stacks.finance_stack import FinanceTradingStack
from stacks.insurance_stack import InsuranceClaimsStack
from stacks.retail_stack import RetailInventoryStack
from stacks.healthcare_stack import HealthcareMedicalStack
from stacks.manufacturing_stack import ManufacturingMaintenanceStack
from stacks.realestate_stack import RealEstateValuationStack

app = cdk.App()

env = cdk.Environment(
    account=os.getenv("CDK_DEFAULT_ACCOUNT"),
    region=os.getenv("CDK_DEFAULT_REGION", "us-west-2"),
)

# Shared infrastructure (VPC, WAF, KMS)
shared = SharedInfraStack(app, "SharedInfra", env=env)

# Finance Trading Assistant
FinanceTradingStack(
    app,
    "FinanceTrading",
    env=env,
    vpc=shared.vpc,
)

# Insurance Claims Processing
InsuranceClaimsStack(
    app,
    "InsuranceClaims",
    env=env,
    vpc=shared.vpc,
)

# Retail Inventory Management
RetailInventoryStack(
    app,
    "RetailInventory",
    env=env,
    vpc=shared.vpc,
)

# Healthcare Medical Records
HealthcareMedicalStack(
    app,
    "HealthcareMedical",
    env=env,
    vpc=shared.vpc,
)

# Manufacturing Predictive Maintenance
ManufacturingMaintenanceStack(
    app,
    "ManufacturingMaintenance",
    env=env,
    vpc=shared.vpc,
)

# Real Estate Property Valuation
RealEstateValuationStack(
    app,
    "RealEstateValuation",
    env=env,
    vpc=shared.vpc,
)

app.synth()
