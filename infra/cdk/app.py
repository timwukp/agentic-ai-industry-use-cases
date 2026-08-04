#!/usr/bin/env python3
"""CDK app: AgentCore Harness rebuild — flagship finance-trading.

Durable infra only. AgentCore resources (gateway, harness, memory,
observability) are created by deploy/deploy.py after these stacks.
"""
import os

import aws_cdk as cdk

from stacks.shared_security_stack import SharedSecurityStack
from stacks.auth_stack import AuthStack
from stacks.finance_data_stack import FinanceDataStack
from stacks.finance_tools_stack import FinanceToolsStack
from stacks.industry_stack import IndustryStack
from stacks.api_stack import ApiStack
from stacks.web_stack import WebStack

# Non-finance industries all deploy through the parameterized IndustryStack.
# Add an entry here + `cdk deploy Agentic<Name>Tools` to bring one online.
INDUSTRIES = {
    "healthcare": ["records", "clinical", "scheduling", "analytics", "kb_search"],
    "insurance": ["claims", "fraud_detection", "policy", "settlement", "kb_search"],
    "retail": ["inventory", "demand_forecast", "supplier", "pricing", "kb_search"],
    "manufacturing": ["equipment", "prediction", "maintenance", "parts", "kb_search"],
    "realestate": ["valuation", "market", "investment", "property", "kb_search"],
}

app = cdk.App()

env = cdk.Environment(
    account=os.getenv("CDK_DEFAULT_ACCOUNT"),
    region=os.getenv("CDK_DEFAULT_REGION", "us-east-1"),
)

shared = SharedSecurityStack(app, "AgenticSharedSecurity", env=env)

auth = AuthStack(app, "AgenticAuth", env=env)

data = FinanceDataStack(app, "AgenticFinanceData", env=env, kms_key=shared.kms_key)

tools = FinanceToolsStack(
    app,
    "AgenticFinanceTools",
    env=env,
    kms_key=shared.kms_key,
    portfolio_table=data.portfolio_table,
    orders_table=data.orders_table,
)

api = ApiStack(
    app,
    "AgenticApi",
    env=env,
    user_pool=auth.user_pool,
    user_pool_client=auth.user_pool_client,
    dashboard_lambda=tools.dashboard_lambda,
)

WebStack(
    app,
    "AgenticWeb",
    env=env,
    web_acl_arn=shared.web_acl_arn,
)

# industries with a dashboard_api handler expose REST widgets too
DASHBOARD_MODULES = {
    "healthcare": {"analytics_tools": "analytics", "scheduling_tools": "scheduling"},
}

industry_stacks = {}
for industry, targets in INDUSTRIES.items():
    industry_stacks[industry] = IndustryStack(
        app,
        f"Agentic{industry.title()}Tools",
        env=env,
        industry=industry,
        targets=targets,
        kms_key=shared.kms_key,
        dashboard_modules=DASHBOARD_MODULES.get(industry),
    )

api.add_industry_routes(
    "healthcare",
    ["population", "patient", "availability"],
    industry_stacks["healthcare"].dashboard_lambda,
)

app.synth()
