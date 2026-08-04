"""Finance demo trading data: portfolio positions + order book."""

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as dynamodb, aws_kms as kms
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

        cdk.CfnOutput(self, "PortfolioTableName", value=self.portfolio_table.table_name)
        cdk.CfnOutput(self, "OrdersTableName", value=self.orders_table.table_name)
