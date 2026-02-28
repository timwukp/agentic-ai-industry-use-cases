"""Shared infrastructure stack: VPC, WAF, KMS keys, CloudWatch log groups.

Follows AWS Well-Architected Framework:
- Security: VPC isolation, KMS encryption, WAF protection
- Reliability: Multi-AZ VPC, NAT gateways
- Cost Optimization: Shared resources across all industry apps
"""
import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
    aws_kms as kms,
    aws_logs as logs,
    aws_wafv2 as wafv2,
)
from constructs import Construct


class SharedInfraStack(cdk.Stack):
    """Shared infrastructure used by all industry agentic AI applications."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # VPC with public and private subnets across 2 AZs
        self.vpc = ec2.Vpc(
            self,
            "AgenticAIVpc",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="Isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                ),
            ],
        )

        # VPC Flow Logs for network monitoring
        self.vpc.add_flow_log("FlowLog")

        # KMS key for encryption at rest
        self.encryption_key = kms.Key(
            self,
            "AgenticAIKey",
            alias="agenticai/encryption",
            enable_key_rotation=True,
            description="Encryption key for Agentic AI industry applications",
        )

        # CloudWatch Log Group for centralized logging
        self.log_group = logs.LogGroup(
            self,
            "AgenticAILogs",
            log_group_name="/agenticai/shared",
            retention=logs.RetentionDays.THREE_MONTHS,
            encryption_key=self.encryption_key,
        )

        # WAF WebACL for CloudFront protection
        self.web_acl = wafv2.CfnWebACL(
            self,
            "AgenticAIWAF",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            scope="CLOUDFRONT",
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AgenticAIWAF",
                sampled_requests_enabled=True,
            ),
            rules=[
                # Rate limiting: 2000 requests per 5 minutes per IP
                wafv2.CfnWebACL.RuleProperty(
                    name="RateLimit",
                    priority=1,
                    action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            limit=2000,
                            aggregate_key_type="IP",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="RateLimit",
                        sampled_requests_enabled=True,
                    ),
                ),
                # AWS Managed Rules - Common Rule Set
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesCommon",
                    priority=2,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWSManagedRulesCommon",
                        sampled_requests_enabled=True,
                    ),
                ),
                # AWS Managed Rules - Known Bad Inputs
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesKnownBadInputs",
                    priority=3,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesKnownBadInputsRuleSet",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWSManagedRulesKnownBadInputs",
                        sampled_requests_enabled=True,
                    ),
                ),
            ],
        )

        # Outputs
        cdk.CfnOutput(self, "VpcId", value=self.vpc.vpc_id)
        cdk.CfnOutput(self, "EncryptionKeyArn", value=self.encryption_key.key_arn)
        cdk.CfnOutput(self, "WebAclArn", value=self.web_acl.attr_arn)
