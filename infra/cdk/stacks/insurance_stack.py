"""Insurance Claims Processing CDK Stack.

Deploys infrastructure for the Insurance Claims agentic AI application:
- Cognito User Pool with HIPAA-compliant settings
- S3 + CloudFront for React frontend
- DynamoDB for claims data (encrypted, point-in-time recovery)
- CloudWatch dashboards for claims processing metrics

AWS Well-Architected:
- Security: HIPAA compliance, encryption at rest/transit, MFA, audit logging
- Reliability: DynamoDB multi-AZ, CloudFront multi-edge
- Performance: DynamoDB on-demand, CloudFront CDN
- Cost: DynamoDB on-demand billing, S3 Intelligent Tiering
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


class InsuranceClaimsStack(cdk.Stack):
    """Infrastructure for the Insurance Claims Processing application."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        vpc: ec2.IVpc,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ============================================================
        # Authentication: Amazon Cognito (HIPAA-compliant)
        # ============================================================
        self.user_pool = cognito.UserPool(
            self,
            "ClaimsUserPool",
            user_pool_name="insurance-claims-users",
            self_sign_up_enabled=False,  # Admin-created users only for HIPAA
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=14,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
                temp_password_validity=cdk.Duration.days(1),
            ),
            mfa=cognito.Mfa.REQUIRED,
            mfa_second_factor=cognito.MfaSecondFactor(otp=True, sms=False),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            advanced_security_mode=cognito.AdvancedSecurityMode.ENFORCED,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # Custom attributes for role-based access
        self.user_pool.add_custom_attribute(
            cognito.StringAttribute(name="role", mutable=True, min_len=2, max_len=50)
        )
        self.user_pool.add_custom_attribute(
            cognito.StringAttribute(name="adjuster_id", mutable=True, min_len=0, max_len=20)
        )

        self.user_pool_client = self.user_pool.add_client(
            "ClaimsAppClient",
            user_pool_client_name="claims-web-app",
            auth_flows=cognito.AuthFlow(user_srp=True, user_password=False),
            id_token_validity=cdk.Duration.minutes(30),
            access_token_validity=cdk.Duration.minutes(30),
            refresh_token_validity=cdk.Duration.days(7),
        )

        # ============================================================
        # Claims Data: DynamoDB (HIPAA-eligible, encrypted)
        # ============================================================
        self.claims_table = dynamodb.Table(
            self,
            "ClaimsTable",
            table_name="insurance-claims",
            partition_key=dynamodb.Attribute(
                name="claim_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # GSI for policy lookup
        self.claims_table.add_global_secondary_index(
            index_name="policy-index",
            partition_key=dynamodb.Attribute(
                name="policy_number", type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # GSI for status filtering
        self.claims_table.add_global_secondary_index(
            index_name="status-index",
            partition_key=dynamodb.Attribute(
                name="status", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at", type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # ============================================================
        # Frontend Hosting: S3 + CloudFront
        # ============================================================
        self.frontend_bucket = s3.Bucket(
            self,
            "ClaimsFrontendBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        oac = cloudfront.S3OriginAccessControl(
            self, "ClaimsOAC", signing=cloudfront.Signing.SIGV4_ALWAYS
        )

        self.distribution = cloudfront.Distribution(
            self,
            "ClaimsDistribution",
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
        # Logging & Monitoring
        # ============================================================
        self.log_group = logs.LogGroup(
            self,
            "ClaimsAgentLogs",
            log_group_name="/agenticai/insurance-claims",
            retention=logs.RetentionDays.ONE_YEAR,  # HIPAA: longer retention
        )

        # ============================================================
        # AgentCore Runtime IAM Role
        # ============================================================
        self.runtime_role = iam.Role(
            self,
            "ClaimsRuntimeRole",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
            description="IAM role for Insurance Claims AgentCore Runtime",
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
                actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:UpdateItem"],
                resources=[self.claims_table.table_arn, f"{self.claims_table.table_arn}/index/*"],
            )
        )
        self.runtime_role.add_to_policy(
            iam.PolicyStatement(
                actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[self.log_group.log_group_arn + ":*"],
            )
        )

        # ============================================================
        # Outputs
        # ============================================================
        cdk.CfnOutput(self, "UserPoolId", value=self.user_pool.user_pool_id)
        cdk.CfnOutput(self, "UserPoolClientId", value=self.user_pool_client.user_pool_client_id)
        cdk.CfnOutput(self, "ClaimsTableName", value=self.claims_table.table_name)
        cdk.CfnOutput(self, "FrontendBucketName", value=self.frontend_bucket.bucket_name)
        cdk.CfnOutput(self, "CloudFrontUrl", value=f"https://{self.distribution.distribution_domain_name}")
        cdk.CfnOutput(self, "RuntimeRoleArn", value=self.runtime_role.role_arn)
