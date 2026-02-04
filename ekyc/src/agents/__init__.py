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
from .biometric_verification_agent import BiometricVerificationAgent
from .compliance_screening_agent import ComplianceScreeningAgent
from .document_verification_agent import DocumentVerificationAgent
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
from .fraud_detection_agent import FraudDetectionAgent
from .manual_review_agent import ManualReviewAgent, ReviewDecision

__all__ = [
    # Base classes
    "AgentConfig",
    "AgentResult",
    "AWSClientManager",
    "BaseEKYCAgent",
    "TimingContext",
    "VerificationStatus",
    # Verification Agents
    "DocumentVerificationAgent",
    "BiometricVerificationAgent",
    "ComplianceScreeningAgent",
    "FraudDetectionAgent",
    "ManualReviewAgent",
    "ReviewDecision",
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
