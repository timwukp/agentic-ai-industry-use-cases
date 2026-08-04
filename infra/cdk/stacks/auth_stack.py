"""Cognito user pool + SPA client. Single pool shared by all industry modules."""
import aws_cdk as cdk
from aws_cdk import aws_cognito as cognito
from constructs import Construct


class AuthStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.user_pool = cognito.UserPool(
            self,
            "UserPool",
            user_pool_name="agentic-usecases",
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
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            feature_plan=cognito.FeaturePlan.PLUS,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        self.domain = self.user_pool.add_domain(
            "HostedDomain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=f"agentic-usecases-{self.account}"
            ),
        )

        self.user_pool_client = self.user_pool.add_client(
            "SpaClient",
            # user_password enables headless smoke/E2E tests; the web app uses SRP
            auth_flows=cognito.AuthFlow(user_srp=True, user_password=True),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL,
                        cognito.OAuthScope.PROFILE],
                callback_urls=["http://localhost:5173/"],  # CloudFront URL added post-deploy
                logout_urls=["http://localhost:5173/"],
            ),
            prevent_user_existence_errors=True,
            access_token_validity=cdk.Duration.minutes(60),
            id_token_validity=cdk.Duration.minutes(60),
            refresh_token_validity=cdk.Duration.days(30),
        )

        discovery_url = (
            f"https://cognito-idp.{self.region}.amazonaws.com/"
            f"{self.user_pool.user_pool_id}/.well-known/openid-configuration"
        )

        cdk.CfnOutput(self, "UserPoolId", value=self.user_pool.user_pool_id)
        cdk.CfnOutput(self, "UserPoolClientId", value=self.user_pool_client.user_pool_client_id)
        cdk.CfnOutput(self, "DiscoveryUrl", value=discovery_url)
        cdk.CfnOutput(self, "HostedUiDomain", value=self.domain.base_url())
