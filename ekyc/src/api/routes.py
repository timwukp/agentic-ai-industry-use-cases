"""
FastAPI routes for eKYC API.
"""

import base64
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, status
from fastapi.security import HTTPBearer, OAuth2PasswordBearer

from .schemas import (
    AnalyticsResponse,
    DocumentResponse,
    DocumentUploadRequest,
    ErrorResponse,
    HealthResponse,
    ReviewDecisionRequest,
    SelfieResponse,
    SelfieUploadRequest,
    SessionCreateRequest,
    SessionResponse,
    SessionStatusResponse,
    VerificationResultResponse,
    WebhookRegisterRequest,
    WebhookResponse,
)
from ..agents import AgentConfig
from ..orchestration import StrandsOrchestrator

# Routers
router = APIRouter(prefix="/v1", tags=["eKYC"])
security = HTTPBearer(auto_error=False)

# In-memory storage (use DynamoDB in production)
_sessions: Dict[str, Dict[str, Any]] = {}
_webhooks: Dict[str, Dict[str, Any]] = {}

# Orchestrator instance
_orchestrator: Optional[StrandsOrchestrator] = None


def get_orchestrator() -> StrandsOrchestrator:
    """Get or create orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = StrandsOrchestrator()
    return _orchestrator


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """Verify API key (simplified for demo)."""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )
    # In production, validate against stored API keys
    return x_api_key


# Health Check
@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
    )


# Session Endpoints
@router.post(
    "/sessions",
    response_model=SessionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_session(
    request: SessionCreateRequest,
    api_key: str = Depends(verify_api_key),
):
    """Create a new verification session."""
    session_id = str(uuid.uuid4())
    now = datetime.utcnow()
    
    session = {
        "session_id": session_id,
        "organization_id": request.organization_id,
        "customer_id": request.customer_id,
        "status": "created",
        "created_at": now,
        "updated_at": now,
        "expires_at": now + timedelta(hours=1),
        "callback_url": request.callback_url,
        "metadata": request.metadata,
        "document_data": None,
        "biometric_data": None,
    }
    _sessions[session_id] = session
    
    return SessionResponse(
        session_id=session_id,
        status="created",
        created_at=now,
        expires_at=session["expires_at"],
    )


@router.get("/sessions/{session_id}", response_model=SessionStatusResponse)
async def get_session(
    session_id: str,
    api_key: str = Depends(verify_api_key),
):
    """Get session status."""
    if session_id not in _sessions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )
    
    session = _sessions[session_id]
    return SessionStatusResponse(
        session_id=session_id,
        status=session["status"],
        current_step=session.get("current_step"),
        verification_score=session.get("verification_score"),
        created_at=session["created_at"],
        updated_at=session["updated_at"],
    )


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(
    session_id: str,
    api_key: str = Depends(verify_api_key),
):
    """Delete session and all associated data (GDPR compliance)."""
    if session_id not in _sessions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )
    
    del _sessions[session_id]
    return None


# Document Endpoints
@router.post("/sessions/{session_id}/document", response_model=DocumentResponse)
async def upload_document(
    session_id: str,
    request: DocumentUploadRequest,
    api_key: str = Depends(verify_api_key),
):
    """Upload identity document for verification."""
    if session_id not in _sessions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )
    
    session = _sessions[session_id]
    
    # Decode image
    image_bytes = None
    if request.image_base64:
        try:
            image_bytes = base64.b64decode(request.image_base64)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 image data",
            )
    
    # Process document
    orchestrator = get_orchestrator()
    doc_result = await orchestrator.document_agent.process(
        session_id,
        {
            "image_bytes": image_bytes,
            "document_type": request.document_type,
            "country_code": request.country_code,
        },
    )
    
    # Update session
    session["status"] = "document_processed"
    session["document_data"] = doc_result.data
    session["updated_at"] = datetime.utcnow()
    
    return DocumentResponse(
        document_id=doc_result.data.get("document_id", str(uuid.uuid4())),
        session_id=session_id,
        document_type=request.document_type,
        is_authentic=doc_result.data.get("is_authentic"),
        quality_issues=doc_result.warnings or [],
    )


# Selfie/Biometric Endpoints
@router.post("/sessions/{session_id}/selfie", response_model=SelfieResponse)
async def upload_selfie(
    session_id: str,
    request: SelfieUploadRequest,
    api_key: str = Depends(verify_api_key),
):
    """Upload selfie for biometric verification."""
    if session_id not in _sessions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )
    
    session = _sessions[session_id]
    
    # Decode image
    try:
        selfie_bytes = base64.b64decode(request.image_base64)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 image data",
        )
    
    # Process biometric
    orchestrator = get_orchestrator()
    bio_result = await orchestrator.biometric_agent.process(
        session_id,
        {
            "selfie_bytes": selfie_bytes,
            "document_photo_bytes": session.get("document_data", {}).get("photo_bytes"),
        },
    )
    
    # Update session
    session["status"] = "biometric_processed"
    session["biometric_data"] = bio_result.data
    session["updated_at"] = datetime.utcnow()
    
    return SelfieResponse(
        biometric_id=bio_result.data.get("biometric_id", str(uuid.uuid4())),
        session_id=session_id,
        liveness_passed=bio_result.data.get("liveness_passed", False),
        face_match_passed=bio_result.data.get("face_match_passed", False),
    )


# Result Endpoints
@router.get("/sessions/{session_id}/result", response_model=VerificationResultResponse)
async def get_result(
    session_id: str,
    api_key: str = Depends(verify_api_key),
):
    """Get final verification result."""
    if session_id not in _sessions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )
    
    session = _sessions[session_id]
    
    if session["status"] not in ["approved", "rejected", "manual_review"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification not yet complete",
        )
    
    return VerificationResultResponse(
        session_id=session_id,
        status=session["status"],
        verification_score=session.get("verification_score", 0),
        risk_level=session.get("risk_level", "unknown"),
        decision=session["status"],
        risk_factors=session.get("risk_factors", []),
        completed_at=session["updated_at"],
    )


# Webhook Endpoints
@router.post("/webhooks", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def register_webhook(
    request: WebhookRegisterRequest,
    api_key: str = Depends(verify_api_key),
):
    """Register a webhook for event notifications."""
    webhook_id = str(uuid.uuid4())
    now = datetime.utcnow()
    
    webhook = {
        "webhook_id": webhook_id,
        "url": request.url,
        "events": request.events,
        "secret": request.secret,
        "created_at": now,
    }
    _webhooks[webhook_id] = webhook
    
    return WebhookResponse(
        webhook_id=webhook_id,
        url=request.url,
        events=request.events,
        created_at=now,
    )


# Analytics Endpoints
@router.get("/organizations/{org_id}/analytics", response_model=AnalyticsResponse)
async def get_analytics(
    org_id: str,
    api_key: str = Depends(verify_api_key),
):
    """Get verification analytics for an organization."""
    # Filter sessions by org
    org_sessions = [s for s in _sessions.values() if s.get("organization_id") == org_id]
    
    # Calculate metrics
    total = len(org_sessions)
    approved = sum(1 for s in org_sessions if s.get("status") == "approved")
    
    now = datetime.utcnow()
    return AnalyticsResponse(
        organization_id=org_id,
        period_start=now - timedelta(days=30),
        period_end=now,
        total_sessions=total,
        success_rate=approved / total if total > 0 else 0.0,
        avg_completion_time_seconds=45.0,  # Placeholder
        status_breakdown={
            "approved": approved,
            "rejected": sum(1 for s in org_sessions if s.get("status") == "rejected"),
            "pending": sum(1 for s in org_sessions if s.get("status") not in ["approved", "rejected"]),
        },
    )


# Error handler helper
def create_error_response(code: str, message: str, details: Dict = None) -> ErrorResponse:
    """Create standardized error response."""
    return ErrorResponse(
        error={
            "code": code,
            "message": message,
            "details": details or {},
        },
        request_id=str(uuid.uuid4()),
    )
