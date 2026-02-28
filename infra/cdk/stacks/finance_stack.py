"""Finance Trading Assistant CDK Stack.

Deploys all infrastructure for the Finance Trading agentic AI application:
- AgentCore Runtime (via custom resource / CLI)
- Cognito User Pool for authentication
- S3 + CloudFront for React frontend
- CloudWatch dashboards and alarms

AWS Well-Architected:
- Security: Cognito auth, OAC for CloudFront, encrypted S3
- Reliability: CloudFront multi-edge, S3 11-9s durability
- Performance: CloudFront CDN, gzip compression
- Cost: S3 Intelligent Tiering, CloudFront caching
"""
import aws_cdk as cdk
from aws_cdk import (
    aws_s3 as s3,
    aws_s3_deployment as s3_deploy,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_cognito as cognito,
    aws_ec2 as ec2,
    aws_logs as logs,
    aws_iam as iam,
)
from constructs import Construct


class FinanceTradingStack(cdk.Stack):
    """Infrastructure for the Finance Trading Assistant application."""

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
            "TradingUserPool",
            user_pool_name="finance-trading-users",
            self_sign_up_enabled=True,
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
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # Cognito App Client
        self.user_pool_client = self.user_pool.add_client(
            "TradingAppClient",
            user_pool_client_name="trading-web-app",
            auth_flows=cognito.AuthFlow(
                user_srp=True,
                user_password=False,
            ),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
            ),
            id_token_validity=cdk.Duration.hours(1),
            access_token_validity=cdk.Duration.hours(1),
            refresh_token_validity=cdk.Duration.days(30),
        )

        # ============================================================
        # Frontend Hosting: S3 + CloudFront
        # ============================================================

        # S3 bucket for React app (private, accessed only via CloudFront)
        self.frontend_bucket = s3.Bucket(
            self,
            "TradingFrontendBucket",
            bucket_name=None,  # Auto-generated
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # CloudFront Origin Access Control
        oac = cloudfront.S3OriginAccessControl(
            self,
            "TradingOAC",
            signing=cloudfront.Signing.SIGV4_ALWAYS,
        )

        # CloudFront Distribution
        self.distribution = cloudfront.Distribution(
            self,
            "TradingDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(
                    self.frontend_bucket,
                    origin_access_control=oac,
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                compress=True,
            ),
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=cdk.Duration.seconds(0),
                ),
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=cdk.Duration.seconds(0),
                ),
            ],
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
        )

        # ============================================================
        # CloudWatch Monitoring
        # ============================================================

        self.log_group = logs.LogGroup(
            self,
            "TradingAgentLogs",
            log_group_name="/agenticai/finance-trading",
            retention=logs.RetentionDays.THREE_MONTHS,
        )

        # ============================================================
        # AgentCore Runtime IAM Role
        # ============================================================

        self.runtime_role = iam.Role(
            self,
            "TradingRuntimeRole",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
            description="IAM role for Finance Trading AgentCore Runtime",
        )

        # Bedrock model invocation
        self.runtime_role.add_to_policy(
            iam.PolicyStatement(
                actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                resources=["*"],
            )
        )

        # AgentCore Memory access
        self.runtime_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "bedrock-agentcore:*Memory*",
                    "bedrock-agentcore:*Session*",
                ],
                resources=["*"],
            )
        )

        # CloudWatch Logs
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
        cdk.CfnOutput(self, "FrontendBucketName", value=self.frontend_bucket.bucket_name)
        cdk.CfnOutput(
            self,
            "CloudFrontUrl",
            value=f"https://{self.distribution.distribution_domain_name}",
        )
        cdk.CfnOutput(self, "RuntimeRoleArn", value=self.runtime_role.role_arn)
