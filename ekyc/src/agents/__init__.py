"""
eKYC Agents Module

This module contains specialized verification agents for the eKYC system:
- Document Verification Agent
- Biometric Verification Agent
- Compliance Screening Agent
- Fraud Detection Agent
- Manual Review Agent
"""

from .base_ekyc_agent import (
    AgentConfig,
    AgentResult,
    AWSClientManager,
    BaseEKYCAgent,
    TimingContext,
    VerificationStatus,
)
from .exceptions import (
    AWSServiceError,
    BiometricError,
    ComplianceError,
    ConfigurationError,
    ConsentError,
    DocumentError,
    EKYCException,
    EncryptionError,
    FraudDetectionError,
    RateLimitError,
    SessionError,
    TimeoutError,
    ValidationError,
)

__all__ = [
    # Base classes
    "AgentConfig",
    "AgentResult",
    "AWSClientManager",
    "BaseEKYCAgent",
    "TimingContext",
    "VerificationStatus",
    # Exceptions
    "AWSServiceError",
    "BiometricError",
    "ComplianceError",
    "ConfigurationError",
    "ConsentError",
    "DocumentError",
    "EKYCException",
    "EncryptionError",
    "FraudDetectionError",
    "RateLimitError",
    "SessionError",
    "TimeoutError",
    "ValidationError",
]
