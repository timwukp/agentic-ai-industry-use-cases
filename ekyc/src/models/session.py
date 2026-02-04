"""
Session data models for eKYC verification sessions.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SessionStatus(str, Enum):
    """Session status states."""
    CREATED = "created"
    DOCUMENT_CAPTURE = "document_capture"
    DOCUMENT_PROCESSING = "document_processing"
    BIOMETRIC_CAPTURE = "biometric_capture"
    BIOMETRIC_PROCESSING = "biometric_processing"
    COMPLIANCE_SCREENING = "compliance_screening"
    FRAUD_ANALYSIS = "fraud_analysis"
    MANUAL_REVIEW = "manual_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    FAILED = "failed"
    EXPIRED = "expired"


class RiskLevel(str, Enum):
    """Risk assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SessionCreate(BaseModel):
    """Request model for creating a new session."""
    organization_id: str = Field(..., min_length=1, max_length=64)
    customer_id: Optional[str] = Field(None, max_length=64)
    callback_url: Optional[str] = Field(None, max_length=512)
    metadata: Optional[Dict[str, Any]] = None


class Session(BaseModel):
    """Verification session model."""
    session_id: str = Field(..., description="Unique session identifier")
    organization_id: str
    customer_id: Optional[str] = None
    status: SessionStatus = SessionStatus.CREATED
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    
    # Verification results
    verification_score: Optional[float] = Field(None, ge=0, le=100)
    risk_level: Optional[RiskLevel] = None
    risk_factors: List[str] = Field(default_factory=list)
    
    # Processing flags
    requires_manual_review: bool = False
    review_reason: Optional[str] = None
    
    # Device/context info
    device_fingerprint: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    geolocation: Optional[Dict[str, Any]] = None
    
    # Callback
    callback_url: Optional[str] = None
    callback_sent: bool = False
    
    # Metadata
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class SessionUpdate(BaseModel):
    """Model for session updates."""
    status: Optional[SessionStatus] = None
    verification_score: Optional[float] = Field(None, ge=0, le=100)
    risk_level: Optional[RiskLevel] = None
    risk_factors: Optional[List[str]] = None
    requires_manual_review: Optional[bool] = None
    review_reason: Optional[str] = None


class SessionResult(BaseModel):
    """Final verification result for a session."""
    session_id: str
    status: SessionStatus
    verification_score: float = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    decision: str = Field(..., description="approved, rejected, or manual_review")
    risk_factors: List[str] = Field(default_factory=list)
    completed_at: datetime = Field(default_factory=datetime.utcnow)
    review_notes: Optional[str] = None
