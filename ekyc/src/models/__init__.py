"""
eKYC Data Models Module

This module contains Pydantic data models for:
- Verification sessions
- Document data
- Biometric data
- Compliance screening results
"""

from .biometric import (
    Biometric,
    BiometricVerificationResult,
    ChallengeType,
    FaceMatch,
    LivenessChallenge,
    LivenessDetection,
    LivenessMethod,
    LivenessResult,
    SelfieUpload,
)
from .document import (
    Document,
    DocumentSide,
    DocumentType,
    DocumentUpload,
    DocumentVerificationResult,
    ExtractedData,
    QualityMetrics,
    SecurityFeatures,
)
from .screening import (
    AuditLogEntry,
    MatchConfidence,
    ScreeningRequest,
    ScreeningResult,
    WatchlistEntry,
    WatchlistMatch,
    WatchlistType,
)
from .session import (
    RiskLevel,
    Session,
    SessionCreate,
    SessionResult,
    SessionStatus,
    SessionUpdate,
)

__all__ = [
    # Session models
    "Session",
    "SessionCreate",
    "SessionUpdate",
    "SessionResult",
    "SessionStatus",
    "RiskLevel",
    # Document models
    "Document",
    "DocumentUpload",
    "DocumentVerificationResult",
    "DocumentType",
    "DocumentSide",
    "ExtractedData",
    "QualityMetrics",
    "SecurityFeatures",
    # Biometric models
    "Biometric",
    "BiometricVerificationResult",
    "SelfieUpload",
    "LivenessChallenge",
    "LivenessDetection",
    "FaceMatch",
    "LivenessMethod",
    "LivenessResult",
    "ChallengeType",
    # Screening models
    "ScreeningRequest",
    "ScreeningResult",
    "WatchlistEntry",
    "WatchlistMatch",
    "WatchlistType",
    "MatchConfidence",
    "AuditLogEntry",
]
