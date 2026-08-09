import os
import sys
from pathlib import Path

import boto3
import pytest

REPO = Path(__file__).resolve().parents[2]
# Lambda packaging flattens these; tests mirror that layout on sys.path
sys.path.insert(0, str(REPO / "tools" / "shared"))
for target in (
    "market_data",
    "market_live",
    "market_collector",
    "macro_signals",
    "quant_insights",
    "portfolio",
    "risk",
    "trading",
    "kb_search",
):
    sys.path.insert(0, str(REPO / "tools" / "finance" / target))

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ["PORTFOLIO_TABLE"] = "finance-portfolio-test"
os.environ["ORDERS_TABLE"] = "finance-orders-test"
os.environ["MARKET_SNAPSHOTS_TABLE"] = "finance-market-snapshots-test"
os.environ["MARKET_LAKE_BUCKET"] = "finance-market-lake-test"


class FakeContext:
    """Mimics the Lambda context the Gateway sends (tool name in client context)."""

    def __init__(self, tool_name: str, target: str = "t"):
        custom = {"bedrockAgentCoreToolName": f"{target}___{tool_name}"}
        self.client_context = type("CC", (), {"custom": custom})()


@pytest.fixture
def gateway_context():
    return FakeContext


@pytest.fixture
def ddb_tables():
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName=os.environ["PORTFOLIO_TABLE"],
            KeySchema=[
                {"AttributeName": "portfolioId", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "portfolioId", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.create_table(
            TableName=os.environ["ORDERS_TABLE"],
            KeySchema=[{"AttributeName": "orderId", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "orderId", "AttributeType": "S"},
                {"AttributeName": "portfolioId", "AttributeType": "S"},
                {"AttributeName": "createdAt", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "byPortfolio",
                    "KeySchema": [
                        {"AttributeName": "portfolioId", "KeyType": "HASH"},
                        {"AttributeName": "createdAt", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        # reset cached boto3 resources inside the toolkit between tests
        import toolkit.dynamo as tdyn

        tdyn._resource = None
        seed = ddb.Table(os.environ["PORTFOLIO_TABLE"])
        for sym, qty, cost in [
            ("AAPL", 100, 185.50),
            ("MSFT", 50, 380.20),
            ("NVDA", 30, 490.00),
            ("JPM", 80, 195.00),
        ]:
            seed.put_item(
                Item={
                    "portfolioId": "default",
                    "sk": f"POSITION#{sym}",
                    "symbol": sym,
                    "quantity": qty,
                    "avgCost": __import__("decimal").Decimal(str(cost)),
                }
            )
        yield ddb
        tdyn._resource = None


@pytest.fixture
def market_snapshots():
    """Moto DynamoDB snapshots table + S3 lake bucket for market-live tests."""
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName=os.environ["MARKET_SNAPSHOTS_TABLE"],
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket=os.environ["MARKET_LAKE_BUCKET"]
        )
        import toolkit.dynamo as tdyn

        tdyn._resource = None
        yield ddb.Table(os.environ["MARKET_SNAPSHOTS_TABLE"])
        tdyn._resource = None
