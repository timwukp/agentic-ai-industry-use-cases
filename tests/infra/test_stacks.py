"""CDK assertions: the security regressions from the old repo stay fixed."""

import json
import sys
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "infra" / "cdk"))

from stacks.shared_security_stack import SharedSecurityStack  # noqa: E402
from stacks.auth_stack import AuthStack  # noqa: E402
from stacks.finance_data_stack import FinanceDataStack  # noqa: E402
from stacks.finance_tools_stack import FinanceToolsStack  # noqa: E402
from stacks.web_stack import WebStack  # noqa: E402

# Dummy synth-only account (AWS's documented example id) — not a real account.
ENV = cdk.Environment(account="123456789012", region="us-east-1")


@pytest.fixture(scope="module")
def templates():
    app = cdk.App()
    shared = SharedSecurityStack(app, "S", env=ENV)
    auth = AuthStack(app, "A", env=ENV)
    data = FinanceDataStack(app, "D", env=ENV, kms_key=shared.kms_key)
    tools = FinanceToolsStack(
        app,
        "T",
        env=ENV,
        kms_key=shared.kms_key,
        portfolio_table=data.portfolio_table,
        orders_table=data.orders_table,
        market_snapshots_table=data.market_snapshots_table,
        market_lake_bucket=data.market_lake_bucket,
    )
    web = WebStack(
        app,
        "W",
        env=ENV,
        web_acl_arn="arn:aws:wafv2:us-east-1:123456789012:global/webacl/x/y",
    )
    return {
        name: Template.from_stack(stack)
        for name, stack in [
            ("shared", shared),
            ("auth", auth),
            ("data", data),
            ("tools", tools),
            ("web", web),
        ]
    }


def test_waf_is_attached_to_cloudfront(templates):
    templates["web"].has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {
                    "WebACLId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/x/y",
                }
            )
        },
    )


def test_no_wrong_agentcore_principal(templates):
    """Old repo bug: roles trusted bedrock.amazonaws.com for AgentCore."""
    roles = templates["tools"].find_resources("AWS::IAM::Role")
    for name, role in roles.items():
        for stmt in role["Properties"]["AssumeRolePolicyDocument"]["Statement"]:
            principal = stmt.get("Principal", {}).get("Service", "")
            if "agentcore" in name.lower() or name.startswith(
                ("GatewayRole", "HarnessRole")
            ):
                assert principal == "bedrock-agentcore.amazonaws.com", name


def test_harness_and_gateway_roles_exist(templates):
    roles = templates["tools"].find_resources("AWS::IAM::Role")
    services = {
        s.get("Principal", {}).get("Service")
        for r in roles.values()
        for s in r["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    }
    assert "bedrock-agentcore.amazonaws.com" in services


def test_tables_use_kms_and_pitr(templates):
    tables = templates["data"].find_resources("AWS::DynamoDB::Table")
    assert len(tables) == 3  # portfolio, orders, market snapshots
    for t in tables.values():
        assert t["Properties"]["SSESpecification"]["SSEType"] == "KMS"
        assert t["Properties"]["PointInTimeRecoverySpecification"][
            "PointInTimeRecoveryEnabled"
        ]


def test_kb_uses_s3_vectors(templates):
    templates["tools"].has_resource_properties(
        "AWS::Bedrock::KnowledgeBase",
        {
            "StorageConfiguration": Match.object_like({"Type": "S3_VECTORS"}),
        },
    )
    templates["tools"].resource_count_is("AWS::S3Vectors::VectorBucket", 1)
    templates["tools"].resource_count_is("AWS::S3Vectors::Index", 1)


def test_cognito_hardening(templates):
    templates["auth"].has_resource_properties(
        "AWS::Cognito::UserPool",
        {
            "Policies": {"PasswordPolicy": Match.object_like({"MinimumLength": 12})},
            "MfaConfiguration": "OPTIONAL",
        },
    )
    # SPA client: no secret
    clients = templates["auth"].find_resources("AWS::Cognito::UserPoolClient")
    for c in clients.values():
        assert c["Properties"].get("GenerateSecret") is not True


def test_six_tool_lambdas(templates):
    fns = templates["tools"].find_resources("AWS::Lambda::Function")
    tool_fns = [
        f
        for f in fns.values()
        if f["Properties"].get("FunctionName", "").startswith("finance-tool-")
    ]
    assert len(tool_fns) == 6  # 5 original targets + market_live


def test_market_collector_scheduled(templates):
    """The collector exists outside the finance-tool- prefix and every job
    has a schedule; without a schedule the live-data layer silently never
    collects (no deploy path = no component)."""
    fns = templates["tools"].find_resources("AWS::Lambda::Function")
    collectors = [
        f
        for f in fns.values()
        if f["Properties"].get("FunctionName", "") == "finance-market-collector"
    ]
    assert len(collectors) == 1

    schedules = templates["tools"].find_resources("AWS::Scheduler::Schedule")
    jobs = sorted(
        json.loads(s["Properties"]["Target"]["Input"])["job"]
        for s in schedules.values()
    )
    assert jobs == ["daily", "fundamentals", "index", "quotes"]
    for s in schedules.values():
        assert s["Properties"]["ScheduleExpressionTimezone"] == "America/New_York"


def test_site_buckets_private(templates):
    for tpl in (templates["web"], templates["tools"]):
        for b in tpl.find_resources("AWS::S3::Bucket").values():
            cfg = b["Properties"]["PublicAccessBlockConfiguration"]
            assert cfg["BlockPublicAcls"] and cfg["RestrictPublicBuckets"]


def test_no_vpc_created(templates):
    """Cost guard: harness is PUBLIC mode, no NAT needed."""
    for tpl in templates.values():
        assert not tpl.find_resources("AWS::EC2::VPC")
