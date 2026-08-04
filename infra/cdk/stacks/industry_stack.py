"""Parameterized per-industry stack: tool Lambdas + KB + AgentCore roles.

Finance predates this class and keeps its bespoke stack (it also owns DynamoDB
tables and the dashboard API). Every other industry deploys through this one —
handlers are pure compute + KB search, so the stack needs no tables.
"""

import shutil
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import (
    aws_bedrock as bedrock,
    aws_iam as iam,
    aws_kms as kms,
    aws_lambda as lambda_,
    aws_s3 as s3,
    aws_s3_deployment as s3_deploy,
    aws_s3vectors as s3vectors,
)
from constructs import Construct

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOLS = REPO_ROOT / "tools"
STAGING = REPO_ROOT / "infra" / "cdk" / ".lambda-staging"

EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
EMBEDDING_DIM = 1024


def _stage(industry: str, name: str) -> str:
    dest = STAGING / industry / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    shutil.copy(TOOLS / industry / name / "handler.py", dest / "handler.py")
    shutil.copytree(TOOLS / "shared" / "toolkit", dest / "toolkit")
    return str(dest)


class IndustryStack(cdk.Stack):
    """One industry's deployable backend: N tool Lambdas, KB, gateway+harness roles."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        industry: str,  # tools/<industry> dir name, e.g. "healthcare"
        targets: list[str],  # handler dirs, e.g. ["records", ..., "kb_search"]
        kms_key: kms.IKey,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ---- Knowledge Base: docs bucket + S3 Vectors + Bedrock KB ----
        docs_bucket = s3.Bucket(
            self,
            "KbDocsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        s3_deploy.BucketDeployment(
            self,
            "KbSeedDocs",
            sources=[
                s3_deploy.Source.asset(str(REPO_ROOT / "kb" / industry / "seed-docs"))
            ],
            destination_bucket=docs_bucket,
            destination_key_prefix=f"{industry}/",
        )

        vector_bucket = s3vectors.CfnVectorBucket(self, "VectorBucket")
        vector_index = s3vectors.CfnIndex(
            self,
            "VectorIndex",
            vector_bucket_arn=vector_bucket.attr_vector_bucket_arn,
            index_name=f"{industry}-kb-index",
            data_type="float32",
            dimension=EMBEDDING_DIM,
            distance_metric="cosine",
            metadata_configuration=s3vectors.CfnIndex.MetadataConfigurationProperty(
                # both must be non-filterable: filterable metadata caps at 2048
                # bytes and Bedrock's chunk text/attribution exceed it
                non_filterable_metadata_keys=[
                    "AMAZON_BEDROCK_TEXT",
                    "AMAZON_BEDROCK_METADATA",
                ],
            ),
        )

        kb_role = iam.Role(
            self,
            "KbServiceRole",
            assumed_by=iam.ServicePrincipal(
                "bedrock.amazonaws.com",
                conditions={"StringEquals": {"aws:SourceAccount": self.account}},
            ),
        )
        docs_bucket.grant_read(kb_role)
        kb_role.add_to_policy(
            iam.PolicyStatement(
                actions=["bedrock:InvokeModel"],
                resources=[
                    f"arn:aws:bedrock:{self.region}::foundation-model/{EMBEDDING_MODEL}"
                ],
            )
        )
        kb_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "s3vectors:GetIndex",
                    "s3vectors:QueryVectors",
                    "s3vectors:PutVectors",
                    "s3vectors:GetVectors",
                    "s3vectors:DeleteVectors",
                    "s3vectors:ListVectors",
                ],
                resources=[vector_index.attr_index_arn],
            )
        )

        knowledge_base = bedrock.CfnKnowledgeBase(
            self,
            "Kb",
            name=f"{industry}-kb",
            role_arn=kb_role.role_arn,
            knowledge_base_configuration=bedrock.CfnKnowledgeBase.KnowledgeBaseConfigurationProperty(
                type="VECTOR",
                vector_knowledge_base_configuration=bedrock.CfnKnowledgeBase.VectorKnowledgeBaseConfigurationProperty(
                    embedding_model_arn=(
                        f"arn:aws:bedrock:{self.region}::foundation-model/{EMBEDDING_MODEL}"
                    ),
                ),
            ),
            storage_configuration=bedrock.CfnKnowledgeBase.StorageConfigurationProperty(
                type="S3_VECTORS",
                s3_vectors_configuration=bedrock.CfnKnowledgeBase.S3VectorsConfigurationProperty(
                    index_arn=vector_index.attr_index_arn,
                ),
            ),
        )
        knowledge_base.node.add_dependency(kb_role)

        data_source = bedrock.CfnDataSource(
            self,
            "KbDataSource",
            name=f"{industry}-seed-docs",
            knowledge_base_id=knowledge_base.attr_knowledge_base_id,
            data_source_configuration=bedrock.CfnDataSource.DataSourceConfigurationProperty(
                type="S3",
                s3_configuration=bedrock.CfnDataSource.S3DataSourceConfigurationProperty(
                    bucket_arn=docs_bucket.bucket_arn,
                    inclusion_prefixes=[f"{industry}/"],
                ),
            ),
        )

        # ---- Tool Lambdas ----
        self.tool_lambdas: dict[str, lambda_.Function] = {}
        for name in targets:
            fn = lambda_.Function(
                self,
                f"Tool{name.title().replace('_', '')}",
                function_name=f"{industry}-tool-{name.replace('_', '-')}",
                runtime=lambda_.Runtime.PYTHON_3_13,
                handler="handler.lambda_handler",
                timeout=cdk.Duration.seconds(30),
                memory_size=256,
                environment_encryption=kms_key,
                code=lambda_.Code.from_asset(_stage(industry, name)),
                environment=(
                    {"KNOWLEDGE_BASE_ID": knowledge_base.attr_knowledge_base_id}
                    if name == "kb_search"
                    else {}
                ),
            )
            self.tool_lambdas[name] = fn

        self.tool_lambdas["kb_search"].add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:Retrieve"],
                resources=[knowledge_base.attr_knowledge_base_arn],
            )
        )

        # ---- AgentCore roles ----
        self.gateway_role = iam.Role(
            self,
            "GatewayRole",
            role_name=f"{industry}-agentcore-gateway",
            assumed_by=iam.ServicePrincipal(
                "bedrock-agentcore.amazonaws.com",
                conditions={"StringEquals": {"aws:SourceAccount": self.account}},
            ),
        )
        for fn in self.tool_lambdas.values():
            fn.grant_invoke(self.gateway_role)

        self.harness_role = iam.Role(
            self,
            "HarnessRole",
            role_name=f"{industry}-agentcore-harness",
            assumed_by=iam.ServicePrincipal(
                "bedrock-agentcore.amazonaws.com",
                conditions={"StringEquals": {"aws:SourceAccount": self.account}},
            ),
        )
        self.harness_role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeModel",
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                ],
                resources=[
                    "arn:aws:bedrock:*::foundation-model/*",
                    f"arn:aws:bedrock:*:{self.account}:inference-profile/*",
                ],
            )
        )
        self.harness_role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeGatewayTools",
                actions=["bedrock-agentcore:*Gateway*"],
                resources=[
                    f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:gateway/*"
                ],
            )
        )
        self.harness_role.add_to_policy(
            iam.PolicyStatement(
                sid="ManagedMemoryEvents",
                actions=[
                    "bedrock-agentcore:CreateEvent",
                    "bedrock-agentcore:GetEvent",
                    "bedrock-agentcore:ListEvents",
                    "bedrock-agentcore:ListSessions",
                    "bedrock-agentcore:ListActors",
                    "bedrock-agentcore:ListMemoryRecords",
                    "bedrock-agentcore:RetrieveMemoryRecords",
                ],
                resources=[
                    f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:memory/*"
                ],
            )
        )
        self.harness_role.add_to_policy(
            iam.PolicyStatement(
                sid="ObservabilityLogs",
                actions=[
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                ],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/bedrock-agentcore/*"
                ],
            )
        )

        # ---- Outputs (same keys the deploy scripts read for finance) ----
        cdk.CfnOutput(
            self, "KnowledgeBaseId", value=knowledge_base.attr_knowledge_base_id
        )
        cdk.CfnOutput(self, "KbDataSourceId", value=data_source.attr_data_source_id)
        cdk.CfnOutput(self, "KbDocsBucketName", value=docs_bucket.bucket_name)
        cdk.CfnOutput(self, "GatewayRoleArn", value=self.gateway_role.role_arn)
        cdk.CfnOutput(self, "HarnessRoleArn", value=self.harness_role.role_arn)
        for name, fn in self.tool_lambdas.items():
            cdk.CfnOutput(
                self,
                f"ToolLambda{name.title().replace('_', '')}Arn",
                value=fn.function_arn,
            )
