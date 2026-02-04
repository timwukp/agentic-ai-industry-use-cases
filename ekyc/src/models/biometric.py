"""
Biometric data models for facial verification and liveness detection.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class LivenessMethod(str, Enum):
    """Liveness detection method."""
    ACTIVE = "active"
    PASSIVE = "passive"


class LivenessResult(str, Enum):
    """Liveness detection result."""
    LIVE = "live"
    SPOOF = "spoof"
    UNCERTAIN = "uncertain"


class ChallengeType(str, Enum):
    """Active liveness challenge types."""
    TURN_HEAD_LEFT = "turn_head_left"
    TURN_HEAD_RIGHT = "turn_head_right"
    LOOK_UP = "look_up"
    LOOK_DOWN = "look_down"
    SMILE = "smile"
    BLINK = "blink"


class SelfieUpload(BaseModel):
    """Request model for selfie upload."""
    image_base64: Optional[str] = Field(None, description="Base64 encoded image")
    image_s3_key: Optional[str] = None
    device_info: Optional[Dict[str, Any]] = None


class LivenessChallenge(BaseModel):
    """Active liveness challenge request."""
    challenge_type: ChallengeType
    video_base64: Optional[str] = None
    video_s3_key: Optional[str] = None
    duration_ms: Optional[int] = None


class LivenessDetection(BaseModel):
    """Liveness detection result."""
    result: LivenessResult
    method: LivenessMethod
    confidence: float = Field(..., ge=0, le=1.0)
    challenges_completed: List[ChallengeType] = Field(default_factory=list)
    spoof_indicators: List[str] = Field(default_factory=list)
    processing_time_ms: int = 0


class FaceMatch(BaseModel):
    """Face matching result."""
    match_score: float = Field(..., ge=0, le=1.0)
    confidence: float = Field(..., ge=0, le=1.0)
    is_match: bool
    threshold_used: float = Field(default=0.95)
    reference_image_uri: Optional[str] = None


class Biometric(BaseModel):
    """Biometric verification data model."""
    biometric_id: str
    session_id: str
    biometric_type: str = "facial"
    
    # Image reference
    selfie_image_s3_uri: Optional[str] = None
    
    # Liveness detection
    liveness_detection: Optional[LivenessDetection] = None
    liveness_attempts: int = 0
    max_liveness_attempts: int = 2
    
    # Face matching
    face_match: Optional[FaceMatch] = None
    face_match_attempts: int = 0
    max_face_match_attempts: int = 3
    
    # Encryption
    encryption_key_id: Optional[str] = None
    
    # Retention policy
    retention_days: int = Field(default=30)
    scheduled_deletion_date: Optional[datetime] = None
    
    # Processing metadata
    processing_time_ms: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class BiometricVerificationResult(BaseModel):
    """Result of biometric verification."""
    biometric_id: str
    session_id: str
    is_verified: bool
    overall_confidence: float = Field(..., ge=0, le=1.0)
    liveness_passed: bool
    face_match_passed: bool
    liveness_result: Optional[LivenessDetection] = None
    face_match_result: Optional[FaceMatch] = None
    failure_reason: Optional[str] = None
    attempts_remaining: int = 0
