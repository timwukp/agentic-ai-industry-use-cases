"""Unified PWA hosting: private S3 + CloudFront (WAF attached) + /agent/* proxy.

The /agent/* behavior reverse-proxies the AgentCore data plane so the browser
calls same-origin (no CORS). Authorization passes through because caching is
disabled and the origin request policy forwards all viewer headers except Host.
"""

import aws_cdk as cdk
from aws_cdk import (
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_s3 as s3,
)
from constructs import Construct


class WebStack(cdk.Stack):
    def __init__(
        self, scope: Construct, construct_id: str, *, web_acl_arn: str, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.site_bucket = s3.Bucket(
            self,
            "SiteBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        agent_origin = origins.HttpOrigin(
            f"bedrock-agentcore.{self.region}.amazonaws.com",
            protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
            read_timeout=cdk.Duration.seconds(60),
        )

        # strip the /agent prefix so /agent/harnesses/invoke → /harnesses/invoke
        strip_prefix_fn = cloudfront.Function(
            self,
            "StripAgentPrefix",
            code=cloudfront.FunctionCode.from_inline(
                "function handler(event) {"
                "  var req = event.request;"
                "  req.uri = req.uri.replace(/^\\/agent/, '');"
                "  return req;"
                "}"
            ),
            runtime=cloudfront.FunctionRuntime.JS_2_0,
        )

        self.distribution = cloudfront.Distribution(
            self,
            "Distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(
                    self.site_bucket
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                compress=True,
            ),
            additional_behaviors={
                "/agent/*": cloudfront.BehaviorOptions(
                    origin=agent_origin,
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                    function_associations=[
                        cloudfront.FunctionAssociation(
                            function=strip_prefix_fn,
                            event_type=cloudfront.FunctionEventType.VIEWER_REQUEST,
                        )
                    ],
                ),
            },
            default_root_object="index.html",
            web_acl_id=web_acl_arn,
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=code,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=cdk.Duration.seconds(0),
                )
                for code in (403, 404)
            ],
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
        )

        cdk.CfnOutput(self, "SiteBucketName", value=self.site_bucket.bucket_name)
        cdk.CfnOutput(
            self,
            "CloudFrontUrl",
            value=f"https://{self.distribution.distribution_domain_name}",
        )
        cdk.CfnOutput(self, "DistributionId", value=self.distribution.distribution_id)
