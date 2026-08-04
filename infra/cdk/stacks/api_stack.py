"""HTTP API + Cognito JWT authorizer for dashboard REST endpoints."""

import json
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_apigatewayv2_authorizers as authorizers
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_lambda as lambda_
from constructs import Construct

ROUTES = [
    "/api/finance/portfolio",
    "/api/finance/orders",
    "/api/finance/market/overview",
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
