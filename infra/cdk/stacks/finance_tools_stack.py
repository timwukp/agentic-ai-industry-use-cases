"""Finance tool Lambdas, AgentCore roles, and the Bedrock Knowledge Base.

Lambda assets are staged at synth time: each function bundle = its handler.py
plus the shared toolkit package (stdlib + boto3 only, no pip install needed).
"""

import shutil
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import (
    aws_bedrock as bedrock,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_kms as kms,
    aws_lambda as lambda_,
    aws_s3 as s3,
    aws_s3_deployment as s3_deploy,
    aws_s3vectors as s3vectors,
    aws_scheduler as scheduler,
)
from constructs import Construct

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOLS = REPO_ROOT / "tools"
STAGING = REPO_ROOT / "infra" / "cdk" / ".lambda-staging"

EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
EMBEDDING_DIM = 1024


def _stage(name: str, extra_modules: dict[str, Path] | None = None) -> str:
    """Build a Lambda asset dir: handler.py + toolkit/ (+ optional aliased modules)."""
    dest = STAGING / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    shutil.copy(TOOLS / "finance" / name / "handler.py", dest / "handler.py")
    shutil.copytree(TOOLS / "shared" / "toolkit", dest / "toolkit")
    for alias, src in (extra_modules or {}).items():
        shutil.copy(src, dest / f"{alias}.py")
    return str(dest)


class FinanceToolsStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        kms_key: kms.IKey,
        portfolio_table: dynamodb.ITable,
        orders_table: dynamodb.ITable,
        market_snapshots_table: dynamodb.ITable,
        market_lake_bucket: s3.IBucket,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ---------------- Knowledge Base: S3 docs + S3 Vectors + Bedrock KB ---------
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
                s3_deploy.Source.asset(str(REPO_ROOT / "kb" / "finance" / "seed-docs"))
            ],
            destination_bucket=docs_bucket,
            destination_key_prefix="finance/",
        )

        vector_bucket = s3vectors.CfnVectorBucket(self, "VectorBucket")
        vector_index = s3vectors.CfnIndex(
            self,
            "VectorIndex",
            vector_bucket_arn=vector_bucket.attr_vector_bucket_arn,
            index_name="finance-kb-index-v2",
            data_type="float32",
            dimension=EMBEDDING_DIM,
            distance_metric="cosine",
            metadata_configuration=s3vectors.CfnIndex.MetadataConfigurationProperty(
                # both must be non-filterable: filterable metadata caps at 2048 bytes
                # and Bedrock's chunk text/attribution routinely exceed it
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
            "FinanceKb",
            name="finance-trading-kb-v2",
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
            "FinanceKbDataSource",
            name="finance-seed-docs",
            knowledge_base_id=knowledge_base.attr_knowledge_base_id,
            data_source_configuration=bedrock.CfnDataSource.DataSourceConfigurationProperty(
                type="S3",
                s3_configuration=bedrock.CfnDataSource.S3DataSourceConfigurationProperty(
                    bucket_arn=docs_bucket.bucket_arn,
                    inclusion_prefixes=["finance/"],
                ),
            ),
        )

        # ---------------- Tool Lambdas (gateway targets) ----------------------------
        common_env = {
            "PORTFOLIO_TABLE": portfolio_table.table_name,
            "ORDERS_TABLE": orders_table.table_name,
            "MARKET_SNAPSHOTS_TABLE": market_snapshots_table.table_name,
        }
        runtime_kwargs = dict(
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="handler.lambda_handler",
            timeout=cdk.Duration.seconds(30),
            memory_size=256,
            environment_encryption=kms_key,
        )

        self.tool_lambdas: dict[str, lambda_.Function] = {}
        for name in (
            "market_data",
            "market_live",
            "portfolio",
            "risk",
            "trading",
            "kb_search",
        ):
            fn = lambda_.Function(
                self,
                f"Tool{name.title().replace('_', '')}",
                function_name=f"finance-tool-{name.replace('_', '-')}",
                code=lambda_.Code.from_asset(_stage(name)),
                environment={
                    **common_env,
                    **(
                        {"KNOWLEDGE_BASE_ID": knowledge_base.attr_knowledge_base_id}
                        if name == "kb_search"
                        else {}
                    ),
                },
                **runtime_kwargs,
            )
            self.tool_lambdas[name] = fn

        portfolio_table.grant_read_data(self.tool_lambdas["portfolio"])
        portfolio_table.grant_read_write_data(self.tool_lambdas["trading"])
        orders_table.grant_read_write_data(self.tool_lambdas["trading"])
        market_snapshots_table.grant_read_data(self.tool_lambdas["market_live"])
        self.tool_lambdas["kb_search"].add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:Retrieve"],
                resources=[knowledge_base.attr_knowledge_base_arn],
            )
        )

        # ---------------- Market data collector (scheduled, NOT a gateway tool) -----
        # Named outside the finance-tool- prefix: it is invoked by EventBridge
        # Scheduler, never by the Gateway, and gateway-tool count assertions
        # rely on the prefix staying meaningful. Tool Lambdas never call the
        # upstream providers — only this collector does, so provider quota use
        # is fixed by the schedules below regardless of dashboard/agent load.
        self.collector_lambda = lambda_.Function(
            self,
            "MarketCollector",
            function_name="finance-market-collector",
            code=lambda_.Code.from_asset(_stage("market_collector")),
            environment={
                **common_env,
                "MARKET_LAKE_BUCKET": market_lake_bucket.bucket_name,
                "SSM_KEY_PREFIX": "/agentic/finance",
            },
            **{**runtime_kwargs, "timeout": cdk.Duration.seconds(120)},
        )
        market_snapshots_table.grant_read_write_data(self.collector_lambda)
        market_lake_bucket.grant_put(self.collector_lambda)
        self.collector_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ssm:GetParameter"],
                resources=[
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/agentic/finance/*"
                ],
            )
        )
        kms_key.grant_decrypt(self.collector_lambda)

        scheduler_role = iam.Role(
            self,
            "CollectorScheduleRole",
            assumed_by=iam.ServicePrincipal(
                "scheduler.amazonaws.com",
                conditions={"StringEquals": {"aws:SourceAccount": self.account}},
            ),
        )
        self.collector_lambda.grant_invoke(scheduler_role)

        # EventBridge Scheduler (not classic rules): native America/New_York
        # timezone, so market-hours windows survive DST without cron hacks.
        collector_schedules = {
            # (cron in ET, job payload)
            "Quotes": ("cron(*/15 9-16 ? * MON-FRI *)", "quotes"),
            "Index": ("cron(*/15 9-16 ? * MON-FRI *)", "index"),
            "Daily": ("cron(30 18 ? * MON-FRI *)", "daily"),
            "Fundamentals": ("cron(0 7 * * ? *)", "fundamentals"),
        }
        for sched_id, (cron, job) in collector_schedules.items():
            scheduler.CfnSchedule(
                self,
                f"CollectorSchedule{sched_id}",
                name=f"finance-market-collector-{job}",
                schedule_expression=cron,
                schedule_expression_timezone="America/New_York",
                flexible_time_window=scheduler.CfnSchedule.FlexibleTimeWindowProperty(
                    mode="OFF"
                ),
                target=scheduler.CfnSchedule.TargetProperty(
                    arn=self.collector_lambda.function_arn,
                    role_arn=scheduler_role.role_arn,
                    input=f'{{"job": "{job}"}}',
                ),
            )

        # ---------------- Dashboard REST Lambda (API Gateway target) ----------------
        self.dashboard_lambda = lambda_.Function(
            self,
            "DashboardApi",
            function_name="finance-dashboard-api",
            code=lambda_.Code.from_asset(
                _stage(
                    "dashboard_api",
                    extra_modules={
                        "portfolio_tools": TOOLS
                        / "finance"
                        / "portfolio"
                        / "handler.py",
                        "trading_tools": TOOLS / "finance" / "trading" / "handler.py",
                        "market_live_tools": TOOLS
                        / "finance"
                        / "market_live"
                        / "handler.py",
                    },
                )
            ),
            environment=common_env,
            **runtime_kwargs,
        )
        portfolio_table.grant_read_data(self.dashboard_lambda)
        orders_table.grant_read_data(self.dashboard_lambda)
        market_snapshots_table.grant_read_data(self.dashboard_lambda)

        # ---------------- AgentCore Gateway execution role --------------------------
        self.gateway_role = iam.Role(
            self,
            "GatewayRole",
            role_name="finance-agentcore-gateway",
            assumed_by=iam.ServicePrincipal(
                "bedrock-agentcore.amazonaws.com",
                conditions={"StringEquals": {"aws:SourceAccount": self.account}},
            ),
        )
        for fn in self.tool_lambdas.values():
            fn.grant_invoke(self.gateway_role)

        # ---------------- Harness execution role ------------------------------------
        self.harness_role = iam.Role(
            self,
            "HarnessRole",
            role_name="finance-agentcore-harness",
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
        # Without this, the runtime's OTel exporter gets 403 Forbidden pushing
        # span batches, so nothing from this harness ever reaches the aws/spans
        # log group (X-Ray Transaction Search) — and the online evaluators, which
        # read spans from there, sit on six months of empty result log groups.
        # Diagnosed by diffing this role against the llmops harness role, whose
        # spans DO arrive: the only telemetry difference was its BaselineTelemetry
        # statement. xray:Put* does not support resource-level scoping, hence "*".
        self.harness_role.add_to_policy(
            iam.PolicyStatement(
                sid="ObservabilityTraces",
                actions=[
                    "xray:PutTraceSegments",
                    "xray:PutTelemetryRecords",
                    "cloudwatch:PutMetricData",
                ],
                resources=["*"],
            )
        )

        # ---------------- Outputs -----------------------------------------------------
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
