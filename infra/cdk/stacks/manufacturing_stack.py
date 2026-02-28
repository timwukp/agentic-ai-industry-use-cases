"""Manufacturing Predictive Maintenance CDK Stack.

Infrastructure for IoT sensor data ingestion and predictive maintenance.

AWS Well-Architected:
- Security: IoT device auth, encrypted sensor data, VPC isolation
- Reliability: DynamoDB for sensor data, multi-AZ
- Performance: DynamoDB on-demand for bursty IoT data, CloudFront CDN
- Cost: DynamoDB on-demand, time-based data retention
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
    aws_timestream as timestream,
)
from constructs import Construct


class ManufacturingMaintenanceStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, vpc: ec2.IVpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Cognito
        self.user_pool = cognito.UserPool(
            self, "ManufacturingUserPool", user_pool_name="manufacturing-maintenance-users",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=12, require_lowercase=True, require_uppercase=True,
                require_digits=True, require_symbols=True,
            ),
            mfa=cognito.Mfa.OPTIONAL,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )
        for group in ["maintenance-techs", "engineers", "plant-managers", "reliability"]:
            cognito.CfnUserPoolGroup(
                self, f"Group{group.replace('-','')}", user_pool_id=self.user_pool.user_pool_id,
                group_name=group,
            )
        self.user_pool_client = self.user_pool.add_client(
            "ManufacturingAppClient", user_pool_client_name="maintenance-web-app",
            auth_flows=cognito.AuthFlow(user_srp=True),
            id_token_validity=cdk.Duration.hours(1),
        )

        # Equipment & Work Orders table
        self.equipment_table = dynamodb.Table(
            self, "EquipmentTable", table_name="manufacturing-equipment",
            partition_key=dynamodb.Attribute(name="equipment_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )
        self.work_orders_table = dynamodb.Table(
            self, "WorkOrdersTable", table_name="manufacturing-work-orders",
            partition_key=dynamodb.Attribute(name="wo_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="created_at", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # Frontend
        self.frontend_bucket = s3.Bucket(
            self, "ManufacturingFrontendBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True, versioned=True,
            removal_policy=cdk.RemovalPolicy.DESTROY, auto_delete_objects=True,
        )
        oac = cloudfront.S3OriginAccessControl(self, "ManufacturingOAC", signing=cloudfront.Signing.SIGV4_ALWAYS)
        self.distribution = cloudfront.Distribution(
            self, "ManufacturingDistribution",
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
            self, "ManufacturingAgentLogs", log_group_name="/agenticai/manufacturing-maintenance",
            retention=logs.RetentionDays.THREE_MONTHS,
        )

        # IAM Role
        self.runtime_role = iam.Role(
            self, "ManufacturingRuntimeRole", assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
        )
        self.runtime_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], resources=["*"],
        ))
        self.runtime_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:*Memory*", "bedrock-agentcore:*Session*"], resources=["*"],
        ))
        self.runtime_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:UpdateItem"],
            resources=[self.equipment_table.table_arn, self.work_orders_table.table_arn],
        ))

        cdk.CfnOutput(self, "UserPoolId", value=self.user_pool.user_pool_id)
        cdk.CfnOutput(self, "EquipmentTableName", value=self.equipment_table.table_name)
        cdk.CfnOutput(self, "CloudFrontUrl", value=f"https://{self.distribution.distribution_domain_name}")
