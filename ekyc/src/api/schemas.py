"""
API schemas for request/response validation.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# Request Schemas
class SessionCreateRequest(BaseModel):
    """Request to create a verification session."""
    organization_id: str = Field(..., min_length=1, max_length=64)
    customer_id: Optional[str] = Field(None, max_length=64)
    callback_url: Optional[str] = Field(None, max_length=512)
    metadata: Optional[Dict[str, Any]] = None


class DocumentUploadRequest(BaseModel):
    """Request to upload a document."""
    document_type: str = Field(..., description="passport, drivers_license, national_id")
    country_code: str = Field(..., min_length=2, max_length=3)
    side: str = Field(default="front", description="front or back")
    image_base64: Optional[str] = None


class SelfieUploadRequest(BaseModel):
    """Request to upload a selfie."""
    image_base64: str = Field(..., description="Base64 encoded selfie image")


class WebhookRegisterRequest(BaseModel):
    """Request to register a webhook."""
    url: str = Field(..., min_length=10, max_length=512)
    events: List[str] = Field(..., description="Events to subscribe to")
    secret: Optional[str] = None


class ReviewDecisionRequest(BaseModel):
    """Request to record a review decision."""
    decision: str = Field(..., description="approve, reject, request_info")
    officer_id: str = Field(..., min_length=1)
    notes: Optional[str] = None


# Response Schemas
class SessionResponse(BaseModel):
    """Session response."""
    session_id: str
    status: str
    created_at: datetime
    expires_at: Optional[datetime] = None


class SessionStatusResponse(BaseModel):
    """Session status response."""
    session_id: str
    status: str
    current_step: Optional[str] = None
    verification_score: Optional[float] = None
    created_at: datetime
    updated_at: datetime


class VerificationResultResponse(BaseModel):
    """Verification result response."""
    session_id: str
    status: str
    verification_score: float
    risk_level: str
    decision: str
    risk_factors: List[str] = Field(default_factory=list)
    completed_at: datetime


class DocumentResponse(BaseModel):
    """Document upload response."""
    document_id: str
    session_id: str
    document_type: str
    is_authentic: Optional[bool] = None
    quality_issues: List[str] = Field(default_factory=list)


class SelfieResponse(BaseModel):
    """Selfie upload response."""
    biometric_id: str
    session_id: str
    liveness_passed: bool
    face_match_passed: bool


class WebhookResponse(BaseModel):
    """Webhook registration response."""
    webhook_id: str
    url: str
    events: List[str]
    created_at: datetime


class AnalyticsResponse(BaseModel):
    """Analytics response."""
    organization_id: str
    period_start: datetime
    period_end: datetime
    total_sessions: int
    success_rate: float
    avg_completion_time_seconds: float
    status_breakdown: Dict[str, int]


class ErrorResponse(BaseModel):
    """Error response."""
    error: Dict[str, Any] = Field(
        ...,
        example={
            "code": "VALIDATION_ERROR",
            "message": "Invalid input",
            "details": {},
        },
    )
    request_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
