"""HTTP API + Cognito JWT authorizer for dashboard REST endpoints,
plus the cross-industry chat-history service (S3 transcripts + index)."""

import json
import shutil
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_apigatewayv2_authorizers as authorizers
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_s3 as s3
from constructs import Construct

REPO_ROOT = Path(__file__).resolve().parents[3]
STAGING = REPO_ROOT / "infra" / "cdk" / ".lambda-staging"

ROUTES = [
    "/api/finance/portfolio",
    "/api/finance/orders",
    "/api/finance/market/overview",
    "/api/finance/market/live",
    "/api/finance/signals",
    "/api/finance/prism",
]


class ApiStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        user_pool: cognito.IUserPool,
        user_pool_client: cognito.IUserPoolClient,
        dashboard_lambda: lambda_.IFunction,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        authorizer = authorizers.HttpUserPoolAuthorizer(
            "CognitoAuthorizer", user_pool, user_pool_clients=[user_pool_client]
        )

        self.http_api = apigwv2.HttpApi(
            self,
            "DashboardApi",
            api_name="agentic-dashboard",
            default_authorizer=authorizer,
            cors_preflight=apigwv2.CorsPreflightOptions(
                # localhost for dev + the CloudFront origin once WebStack has
                # deployed (read back from deploy outputs on the next synth)
                allow_origins=["http://localhost:5173", *self._web_origins()],
                allow_methods=[
                    apigwv2.CorsHttpMethod.GET,
                    apigwv2.CorsHttpMethod.POST,
                    apigwv2.CorsHttpMethod.OPTIONS,
                ],
                allow_headers=["Authorization", "Content-Type"],
                max_age=cdk.Duration.hours(1),
            ),
        )

        integration = integrations.HttpLambdaIntegration(
            "DashboardIntegration", dashboard_lambda
        )
        for path in ROUTES:
            self.http_api.add_routes(
                path=path, methods=[apigwv2.HttpMethod.GET], integration=integration
            )

        # ---- Chat history: per-user durable transcripts in S3 ------------
        # Cross-industry (keyed by Cognito sub, not industry), so it lives
        # here rather than in any industry stack. Identity is enforced from
        # JWT claims in the handler; the bucket never leaves this account.
        chat_bucket = s3.Bucket(
            self,
            "ChatHistoryBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            lifecycle_rules=[
                s3.LifecycleRule(
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=cdk.Duration.days(90),
                        )
                    ]
                )
            ],
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        staging = STAGING / "chat_history"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        shutil.copy(
            REPO_ROOT / "tools" / "shared" / "chat_history" / "handler.py",
            staging / "handler.py",
        )
        chat_lambda = lambda_.Function(
            self,
            "ChatHistory",
            function_name="agentic-chat-history",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset(str(staging)),
            timeout=cdk.Duration.seconds(30),
            memory_size=256,
            environment={"CHAT_HISTORY_BUCKET": chat_bucket.bucket_name},
        )
        chat_bucket.grant_read_write(chat_lambda)
        chat_lambda.add_to_role_policy(
            iam.PolicyStatement(
                sid="SessionSummaryModel",
                actions=["bedrock:InvokeModel"],
                resources=[
                    "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku*",
                    f"arn:aws:bedrock:*:{self.account}:inference-profile/*.anthropic.claude-haiku*",
                ],
            )
        )
        chat_integration = integrations.HttpLambdaIntegration(
            "ChatHistoryIntegration", chat_lambda
        )
        self.http_api.add_routes(
            path="/api/chat/save",
            methods=[apigwv2.HttpMethod.POST],
            integration=chat_integration,
        )
        for path in ("/api/chat/sessions", "/api/chat/session"):
            self.http_api.add_routes(
                path=path,
                methods=[apigwv2.HttpMethod.GET],
                integration=chat_integration,
            )
        cdk.CfnOutput(self, "ChatHistoryBucketName", value=chat_bucket.bucket_name)

        cdk.CfnOutput(self, "ApiUrl", value=self.http_api.api_endpoint)

    def add_industry_routes(
        self,
        industry: str,
        paths: list[str],
        handler: lambda_.IFunction | None,
    ) -> None:
        """Attach GET /api/<industry>/<path> routes backed by that industry's lambda."""
        if handler is None:
            return
        integration = integrations.HttpLambdaIntegration(
            f"{industry.title()}DashboardIntegration", handler
        )
        for path in paths:
            self.http_api.add_routes(
                path=f"/api/{industry}/{path}",
                methods=[apigwv2.HttpMethod.GET],
                integration=integration,
            )

    @staticmethod
    def _web_origins() -> list[str]:
        outputs = (
            Path(__file__).resolve().parents[3]
            / "deploy"
            / "outputs"
            / "web-outputs.json"
        )
        if not outputs.exists():
            return []
        url = json.loads(outputs.read_text()).get("AgenticWeb", {}).get("CloudFrontUrl")
        return [url] if url else []
