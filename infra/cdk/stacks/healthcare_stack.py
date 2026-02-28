"""Healthcare Medical Records CDK Stack.

HIPAA-compliant infrastructure for the Healthcare Medical Records application.

AWS Well-Architected:
- Security: HIPAA BAA, encryption at rest/transit, MFA required, audit logging, PHI protection
- Reliability: DynamoDB multi-AZ, CloudFront multi-edge
- Performance: DynamoDB on-demand, CloudFront CDN
- Cost: DynamoDB on-demand, S3 Intelligent Tiering
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
    aws_kms as kms,
)
from constructs import Construct


class HealthcareMedicalStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, vpc: ec2.IVpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # HIPAA-grade KMS key
        self.phi_key = kms.Key(
            self, "PHIKey", alias="agenticai/healthcare-phi",
            enable_key_rotation=True, description="HIPAA encryption key for PHI data",
        )

        # Cognito: HIPAA-compliant (MFA required, no self-signup, short token validity)
        self.user_pool = cognito.UserPool(
            self, "HealthcareUserPool", user_pool_name="healthcare-medical-users",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=14, require_lowercase=True, require_uppercase=True,
                require_digits=True, require_symbols=True, temp_password_validity=cdk.Duration.hours(24),
            ),
            mfa=cognito.Mfa.REQUIRED,
            mfa_second_factor=cognito.MfaSecondFactor(otp=True, sms=False),
            advanced_security_mode=cognito.AdvancedSecurityMode.ENFORCED,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        for group in ["physicians", "nurses", "admin-staff", "billing"]:
            cognito.CfnUserPoolGroup(
                self, f"Group{group.replace('-','')}", user_pool_id=self.user_pool.user_pool_id,
                group_name=group,
            )

        self.user_pool_client = self.user_pool.add_client(
            "HealthcareAppClient", user_pool_client_name="medical-web-app",
            auth_flows=cognito.AuthFlow(user_srp=True),
            id_token_validity=cdk.Duration.minutes(15),
            access_token_validity=cdk.Duration.minutes(15),
            refresh_token_validity=cdk.Duration.days(1),
        )

        # DynamoDB: Patient records (encrypted with customer-managed KMS)
        self.patients_table = dynamodb.Table(
            self, "PatientsTable", table_name="healthcare-patients",
            partition_key=dynamodb.Attribute(name="patient_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.phi_key,
            point_in_time_recovery=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # Frontend
        self.frontend_bucket = s3.Bucket(
            self, "HealthcareFrontendBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True, versioned=True,
            removal_policy=cdk.RemovalPolicy.DESTROY, auto_delete_objects=True,
        )
        oac = cloudfront.S3OriginAccessControl(self, "HealthcareOAC", signing=cloudfront.Signing.SIGV4_ALWAYS)
        self.distribution = cloudfront.Distribution(
            self, "HealthcareDistribution",
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

        # Logging: 6-year retention for HIPAA
        self.log_group = logs.LogGroup(
            self, "HealthcareAgentLogs", log_group_name="/agenticai/healthcare-medical",
            retention=logs.RetentionDays.SIX_YEARS, encryption_key=self.phi_key,
        )

        # IAM Role
        self.runtime_role = iam.Role(
            self, "HealthcareRuntimeRole",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
        )
        self.runtime_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], resources=["*"],
        ))
        self.runtime_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:*Memory*", "bedrock-agentcore:*Session*"], resources=["*"],
        ))
        self.runtime_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem"],
            resources=[self.patients_table.table_arn],
        ))
        self.phi_key.grant_encrypt_decrypt(self.runtime_role)

        # Outputs
        cdk.CfnOutput(self, "UserPoolId", value=self.user_pool.user_pool_id)
        cdk.CfnOutput(self, "PatientsTableName", value=self.patients_table.table_name)
        cdk.CfnOutput(self, "CloudFrontUrl", value=f"https://{self.distribution.distribution_domain_name}")
