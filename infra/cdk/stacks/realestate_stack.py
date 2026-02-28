"""Real Estate Property Valuation CDK Stack.

Infrastructure for property valuation and market analysis.

AWS Well-Architected:
- Security: Cognito auth, encrypted data, RBAC
- Reliability: DynamoDB, CloudFront
- Performance: CloudFront CDN, DynamoDB on-demand
- Cost: Serverless, on-demand billing
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


class RealEstateValuationStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, vpc: ec2.IVpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Cognito
        self.user_pool = cognito.UserPool(
            self, "RealEstateUserPool", user_pool_name="realestate-valuation-users",
            self_sign_up_enabled=True,
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=12, require_lowercase=True, require_uppercase=True,
                require_digits=True, require_symbols=True,
            ),
            mfa=cognito.Mfa.OPTIONAL,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )
        for group in ["agents", "brokers", "appraisers", "investors"]:
            cognito.CfnUserPoolGroup(
                self, f"Group{group}", user_pool_id=self.user_pool.user_pool_id, group_name=group,
            )
        self.user_pool_client = self.user_pool.add_client(
            "RealEstateAppClient", user_pool_client_name="realestate-web-app",
            auth_flows=cognito.AuthFlow(user_srp=True),
            id_token_validity=cdk.Duration.hours(2),
            refresh_token_validity=cdk.Duration.days(30),
        )

        # Properties table
        self.properties_table = dynamodb.Table(
            self, "PropertiesTable", table_name="realestate-properties",
            partition_key=dynamodb.Attribute(name="property_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )
        self.properties_table.add_global_secondary_index(
            index_name="zipcode-index",
            partition_key=dynamodb.Attribute(name="zipcode", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="estimated_value", type=dynamodb.AttributeType.NUMBER),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # Frontend
        self.frontend_bucket = s3.Bucket(
            self, "RealEstateFrontendBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True, versioned=True,
            removal_policy=cdk.RemovalPolicy.DESTROY, auto_delete_objects=True,
        )
        oac = cloudfront.S3OriginAccessControl(self, "RealEstateOAC", signing=cloudfront.Signing.SIGV4_ALWAYS)
        self.distribution = cloudfront.Distribution(
            self, "RealEstateDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(self.frontend_bucket, origin_access_control=oac),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED, compress=True,
            ),
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(http_status=404, response_http_status=200, response_page_path="/index.html", ttl=cdk.Duration.seconds(0)),
                cloudfront.ErrorResponse(http_status=403, response_http_status=200, response_page_path="/index.html", ttl=cdk.Duration.seconds(0)),
            ],
        )

        self.log_group = logs.LogGroup(
            self, "RealEstateAgentLogs", log_group_name="/agenticai/real-estate-valuation",
            retention=logs.RetentionDays.THREE_MONTHS,
        )

        self.runtime_role = iam.Role(
            self, "RealEstateRuntimeRole", assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
        )
        self.runtime_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], resources=["*"],
        ))
        self.runtime_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:*Memory*", "bedrock-agentcore:*Session*"], resources=["*"],
        ))
        self.runtime_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan"],
            resources=[self.properties_table.table_arn, f"{self.properties_table.table_arn}/index/*"],
        ))

        cdk.CfnOutput(self, "UserPoolId", value=self.user_pool.user_pool_id)
        cdk.CfnOutput(self, "PropertiesTableName", value=self.properties_table.table_name)
        cdk.CfnOutput(self, "CloudFrontUrl", value=f"https://{self.distribution.distribution_domain_name}")
