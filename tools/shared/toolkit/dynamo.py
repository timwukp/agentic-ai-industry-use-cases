"""DynamoDB helpers for the demo trading system."""
import os
from decimal import Decimal

import boto3

_resource = None


def table(name_env: str):
    global _resource
    if _resource is None:
        _resource = boto3.resource("dynamodb")
    return _resource.Table(os.environ[name_env])


def to_decimal(obj):
    """Convert floats to Decimal for DynamoDB writes."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_decimal(v) for v in obj]
    return obj


def from_decimal(obj):
    """Convert Decimals back to int/float for JSON responses."""
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    if isinstance(obj, dict):
        return {k: from_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [from_decimal(v) for v in obj]
    return obj
