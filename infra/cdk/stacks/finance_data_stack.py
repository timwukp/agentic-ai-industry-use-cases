"""Finance demo trading data: portfolio positions + order book + live market data.

The live-market layer (snapshots table + lake bucket) is written by the
scheduled collector Lambda and read by the market-live tools; tool Lambdas
never call the upstream providers directly.
"""

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as dynamodb, aws_kms as kms, aws_s3 as s3
from constructs import Construct


class FinanceDataStack(cdk.Stack):
    def __init__(
        self, scope: Construct, construct_id: str, *, kms_key: kms.IKey, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.portfolio_table = dynamodb.Table(
            self,
            "PortfolioTable",
            table_name="finance-portfolio",
            partition_key=dynamodb.Attribute(
                name="portfolioId", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="sk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=kms_key,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        self.orders_table = dynamodb.Table(
            self,
            "OrdersTable",
            table_name="finance-orders",
            partition_key=dynamodb.Attribute(
                name="orderId", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=kms_key,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        self.orders_table.add_global_secondary_index(
            index_name="byPortfolio",
            partition_key=dynamodb.Attribute(
                name="portfolioId", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="createdAt", type=dynamodb.AttributeType.STRING
            ),
        )

        # Live-market snapshots: pk = QUOTE#<SYM> / INDEX#<ID> / TREASURY#CURVE /
        # RATES#POLICY / FUNDAMENTALS#<SYM> / META#TRACKED; sk = "latest" or
        # "d#YYYY-MM-DD". Dated items carry expiresAt so the 30-day rolling
        # window self-prunes; full history lives in the lake bucket instead.
        self.market_snapshots_table = dynamodb.Table(
            self,
            "MarketSnapshotsTable",
            table_name="finance-market-snapshots",
            partition_key=dynamodb.Attribute(
                name="pk", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="sk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=kms_key,
            time_to_live_attribute="expiresAt",
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # Append-only history for modeling/backtests, Athena-queryable:
        # market/<dataset>/dt=YYYY-MM-DD/part-<ts>.jsonl.gz
        self.market_lake_bucket = s3.Bucket(
            self,
            "MarketLakeBucket",
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
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        cdk.CfnOutput(self, "PortfolioTableName", value=self.portfolio_table.table_name)
        cdk.CfnOutput(self, "OrdersTableName", value=self.orders_table.table_name)
        cdk.CfnOutput(
            self,
            "MarketSnapshotsTableName",
            value=self.market_snapshots_table.table_name,
        )
        cdk.CfnOutput(
            self, "MarketLakeBucketName", value=self.market_lake_bucket.bucket_name
        )
