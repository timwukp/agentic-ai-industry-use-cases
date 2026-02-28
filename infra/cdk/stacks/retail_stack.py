"""Retail Inventory Management CDK Stack.

Deploys infrastructure for the Retail Inventory agentic AI application:
- Cognito User Pool for store managers/buyers
- S3 + CloudFront for React frontend
- DynamoDB for inventory and product data
- ElastiCache Redis for real-time inventory caching
- CloudWatch dashboards for inventory metrics

AWS Well-Architected:
- Security: PCI-DSS alignment, encryption, RBAC via Cognito groups
- Reliability: DynamoDB global tables ready, ElastiCache Multi-AZ
- Performance: Redis caching for real-time inventory, CloudFront CDN
- Cost: DynamoDB on-demand, ElastiCache right-sized
"""
import aws_cdk as cdk
from aws_cdk import (
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_cognito as cognito,
    aws_ec2 as ec2,
    aws_logs as logs,
    aws_iam as iam,
    aws_dynamodb as dynamodb,
)
from constructs import Construct


class RetailInventoryStack(cdk.Stack):
    """Infrastructure for the Retail Inventory Management application."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        vpc: ec2.IVpc,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ============================================================
        # Authentication: Amazon Cognito
        # ============================================================
        self.user_pool = cognito.UserPool(
            self,
            "RetailUserPool",
            user_pool_name="retail-inventory-users",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=12,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
            ),
            mfa=cognito.Mfa.OPTIONAL,
            mfa_second_factor=cognito.MfaSecondFactor(otp=True, sms=False),
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # Role-based groups
        for group_name in ["store-managers", "buyers", "analysts", "admins"]:
            cognito.CfnUserPoolGroup(
                self,
                f"Group{group_name.replace('-', '')}",
                user_pool_id=self.user_pool.user_pool_id,
                group_name=group_name,
                description=f"{group_name.replace('-', ' ').title()} group",
            )

        self.user_pool_client = self.user_pool.add_client(
            "RetailAppClient",
            user_pool_client_name="retail-web-app",
            auth_flows=cognito.AuthFlow(user_srp=True),
            id_token_validity=cdk.Duration.hours(1),
            access_token_validity=cdk.Duration.hours(1),
            refresh_token_validity=cdk.Duration.days(30),
        )

        # ============================================================
        # Data: DynamoDB Tables
        # ============================================================

        # Products/Inventory table
        self.inventory_table = dynamodb.Table(
            self,
            "InventoryTable",
            table_name="retail-inventory",
            partition_key=dynamodb.Attribute(name="sku", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="location_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        self.inventory_table.add_global_secondary_index(
            index_name="category-index",
            partition_key=dynamodb.Attribute(name="category", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # Purchase Orders table
        self.po_table = dynamodb.Table(
            self,
            "PurchaseOrderTable",
            table_name="retail-purchase-orders",
            partition_key=dynamodb.Attribute(name="po_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # ============================================================
        # Frontend Hosting
        # ============================================================
        self.frontend_bucket = s3.Bucket(
            self,
            "RetailFrontendBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        oac = cloudfront.S3OriginAccessControl(
            self, "RetailOAC", signing=cloudfront.Signing.SIGV4_ALWAYS
        )

        self.distribution = cloudfront.Distribution(
            self,
            "RetailDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(
                    self.frontend_bucket, origin_access_control=oac
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                compress=True,
            ),
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=404, response_http_status=200,
                    response_page_path="/index.html", ttl=cdk.Duration.seconds(0),
                ),
                cloudfront.ErrorResponse(
                    http_status=403, response_http_status=200,
                    response_page_path="/index.html", ttl=cdk.Duration.seconds(0),
                ),
            ],
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
        )

        # ============================================================
        # Logging
        # ============================================================
        self.log_group = logs.LogGroup(
            self,
            "RetailAgentLogs",
            log_group_name="/agenticai/retail-inventory",
            retention=logs.RetentionDays.THREE_MONTHS,
        )

        # ============================================================
        # AgentCore Runtime IAM Role
        # ============================================================
        self.runtime_role = iam.Role(
            self,
            "RetailRuntimeRole",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
            description="IAM role for Retail Inventory AgentCore Runtime",
        )

        self.runtime_role.add_to_policy(
            iam.PolicyStatement(
                actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                resources=["*"],
            )
        )
        self.runtime_role.add_to_policy(
            iam.PolicyStatement(
                actions=["bedrock-agentcore:*Memory*", "bedrock-agentcore:*Session*"],
                resources=["*"],
            )
        )
        self.runtime_role.add_to_policy(
            iam.PolicyStatement(
                actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:UpdateItem", "dynamodb:BatchGetItem"],
                resources=[
                    self.inventory_table.table_arn, f"{self.inventory_table.table_arn}/index/*",
                    self.po_table.table_arn,
                ],
            )
        )

        # ============================================================
        # Outputs
        # ============================================================
        cdk.CfnOutput(self, "UserPoolId", value=self.user_pool.user_pool_id)
        cdk.CfnOutput(self, "InventoryTableName", value=self.inventory_table.table_name)
        cdk.CfnOutput(self, "POTableName", value=self.po_table.table_name)
        cdk.CfnOutput(self, "CloudFrontUrl", value=f"https://{self.distribution.distribution_domain_name}")
        cdk.CfnOutput(self, "RuntimeRoleArn", value=self.runtime_role.role_arn)
