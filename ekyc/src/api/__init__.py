"""
eKYC API Module

This module contains the FastAPI-based REST API with OpenAPI 3.0
specification, OAuth 2.0 authentication, and webhook support.
"""

from .app import app, create_app
from .routes import router
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

__all__ = [
    # App
    "app",
    "create_app",
    "router",
    # Request schemas
    "SessionCreateRequest",
    "DocumentUploadRequest",
    "SelfieUploadRequest",
    "WebhookRegisterRequest",
    "ReviewDecisionRequest",
    # Response schemas
    "SessionResponse",
    "SessionStatusResponse",
    "VerificationResultResponse",
    "DocumentResponse",
    "SelfieResponse",
    "WebhookResponse",
    "AnalyticsResponse",
    "ErrorResponse",
    "HealthResponse",
]
