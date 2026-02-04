"""
Next-Generation eKYC System

A multi-agent electronic Know Your Customer (eKYC) system built with
AWS Strands for orchestration, AWS Bedrock AgentCore for deployment,
and AWS Nova ACT for testing.
"""

__version__ = "0.1.0"
__title__ = "Next-Generation eKYC System"
__author__ = "eKYC Team"
__license__ = "MIT"

from . import agents
from . import orchestration
from . import api
from . import services
from . import models
from . import utils

__all__ = [
    "__version__",
    "__title__",
    "agents",
    "orchestration",
    "api",
    "services",
    "models",
    "utils",
]
