"""
Security-Hardened Insurance Claims Processing System
Main application with comprehensive security middleware stack
"""

import os
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession
import uvicorn

from config import get_settings, SecuritySettings
from security_utils import SecurityUtils
from auth_service import AuthService
from database import get_db_session
from models import ClaimRequest, ClaimResponse, UserCreate, UserLogin
from audit_logger import AuditLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize settings
settings = get_settings()
security_settings = SecuritySettings()

# Initialize security utilities
security_utils = SecurityUtils()
auth_service = AuthService()
audit_logger = AuditLogger()

# Initialize rate limiter with Redis backend
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.redis_url,
    default_limits=["100/minute", "1000/hour"]
)

# Security middleware for headers
class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = dict(message.get("headers", []))
                    
                    # Security headers
                    security_headers = {
                        b"x-content-type-options": b"nosniff",
                        b"x-frame-options": b"DENY",
                        b"x-xss-protection": b"1; mode=block",
                        b"strict-transport-security": b"max-age=31536000; includeSubDomains",
                        b"content-security-policy": b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
                        b"referrer-policy": b"strict-origin-when-cross-origin",
                        b"permissions-policy": b"geolocation=(), microphone=(), camera=()"
                    }
                    
                    headers.update(security_headers)
                    message["headers"] = list(headers.items())
                
                await send(message)
            
            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)

# Request validation middleware
class RequestValidationMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            request = Request(scope, receive)
            
            # Validate request size
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > security_settings.max_request_size:
                response = JSONResponse(
                    status_code=413,
                    content={"error": "Request too large"}
                )
                await response(scope, receive, send)
                return
            
            # Validate content type for POST/PUT requests
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if not content_type.startswith(("application/json", "multipart/form-data")):
                    response = JSONResponse(
                        status_code=415,
                        content={"error": "Unsupported media type"}
                    )
                    await response(scope, receive, send)
                    return
        
        await self.app(scope, receive, send)

# Application lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Insurance Claims Processing System")
    
    # Initialize Redis connection
    try:
        redis_client = redis.from_url(settings.redis_url)
        await redis_client.ping()
        app.state.redis = redis_client
        logger.info("Redis connection established")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise
    
    # Initialize database
    try:
        # Test database connection
        async with get_db_session() as session:
            await session.execute("SELECT 1")
        logger.info("Database connection established")
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Insurance Claims Processing System")
    if hasattr(app.state, 'redis'):
        await app.state.redis.close()

# Initialize FastAPI application
app = FastAPI(
    title="Insurance Claims Processing System",
    description="Secure AI-powered insurance claims processing with AWS Bedrock integration",
    version="2.0.0",
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url="/redoc" if settings.environment == "development" else None,
    lifespan=lifespan
)

# Add security middleware stack
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(SlowAPIMiddleware)

# CORS middleware with strict configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    max_age=3600
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts
)

# Rate limit exceeded handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security dependencies
security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None
) -> Dict[str, Any]:
    """Validate JWT token and return current user"""
    try:
        token = credentials.credentials
        user_data = await auth_service.validate_token(token)
        
        # Log successful authentication
        await audit_logger.log_event(
            event_type="authentication_success",
            user_id=user_data.get("user_id"),
            ip_address=get_remote_address(request),
            details={"endpoint": request.url.path}
        )
        
        return user_data
    except Exception as e:
        # Log failed authentication
        await audit_logger.log_event(
            event_type="authentication_failure",
            ip_address=get_remote_address(request),
            details={"error": str(e), "endpoint": request.url.path}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

# Health check endpoint
@app.get("/health")
@limiter.limit("10/minute")
async def health_check(request: Request):
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }

# Authentication endpoints
@app.post("/auth/register")
@limiter.limit("5/minute")
async def register_user(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db_session)
):
    """Register new user with comprehensive validation"""
    try:
        # Validate input data
        validated_data = security_utils.validate_user_input(user_data.dict())
        
        # Check password strength
        if not security_utils.validate_password_strength(validated_data["password"]):
            raise HTTPException(
                status_code=400,
                detail="Password does not meet security requirements"
            )
        
        # Register user
        user = await auth_service.register_user(validated_data, db)
        
        # Log successful registration
        await audit_logger.log_event(
            event_type="user_registration",
            user_id=user["user_id"],
            ip_address=get_remote_address(request),
            details={"email": validated_data["email"]}
        )
        
        return {"message": "User registered successfully", "user_id": user["user_id"]}
        
    except Exception as e:
        # Log failed registration
        await audit_logger.log_event(
            event_type="registration_failure",
            ip_address=get_remote_address(request),
            details={"error": str(e), "email": user_data.email}
        )
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/auth/login")
@limiter.limit("5/minute")
async def login_user(
    login_data: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db_session)
):
    """User login with brute force protection"""
    try:
        # Validate input
        validated_data = security_utils.validate_user_input(login_data.dict())
        
        # Check for account lockout
        ip_address = get_remote_address(request)
        if await auth_service.is_account_locked(validated_data["email"], ip_address):
            raise HTTPException(
                status_code=429,
                detail="Account temporarily locked due to multiple failed attempts"
            )
        
        # Authenticate user
        auth_result = await auth_service.authenticate_user(validated_data, db)
        
        # Log successful login
        await audit_logger.log_event(
            event_type="user_login",
            user_id=auth_result["user_id"],
            ip_address=ip_address,
            details={"email": validated_data["email"]}
        )
        
        return auth_result
        
    except HTTPException:
        raise
    except Exception as e:
        # Log failed login and increment failed attempts
        await auth_service.record_failed_login(login_data.email, get_remote_address(request))
        await audit_logger.log_event(
            event_type="login_failure",
            ip_address=get_remote_address(request),
            details={"error": str(e), "email": login_data.email}
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

# Claims processing endpoints
@app.post("/claims/submit", response_model=ClaimResponse)
@limiter.limit("10/minute")
async def submit_claim(
    claim_data: ClaimRequest,
    request: Request,
    current_user: Dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Submit insurance claim with comprehensive validation"""
    try:
        # Validate and sanitize claim data
        validated_claim = security_utils.validate_claim_data(claim_data.dict())
        
        # Add user context
        validated_claim["user_id"] = current_user["user_id"]
        validated_claim["submitted_at"] = datetime.utcnow()
        
        # Process claim using Bedrock AgentCore
        # This would integrate with your Strands SDK and Bedrock AgentCore
        claim_result = await process_claim_with_ai(validated_claim)
        
        # Log claim submission
        await audit_logger.log_event(
            event_type="claim_submission",
            user_id=current_user["user_id"],
            ip_address=get_remote_address(request),
            details={
                "claim_id": claim_result["claim_id"],
                "claim_type": validated_claim.get("claim_type"),
                "amount": validated_claim.get("amount")
            }
        )
        
        return ClaimResponse(**claim_result)
        
    except Exception as e:
        # Log failed claim submission
        await audit_logger.log_event(
            event_type="claim_submission_failure",
            user_id=current_user["user_id"],
            ip_address=get_remote_address(request),
            details={"error": str(e)}
        )
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/claims/{claim_id}")
@limiter.limit("20/minute")
async def get_claim(
    claim_id: str,
    current_user: Dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Retrieve claim details with authorization check"""
    try:
        # Validate claim ID format
        if not security_utils.validate_uuid(claim_id):
            raise HTTPException(status_code=400, detail="Invalid claim ID format")
        
        # Retrieve claim with authorization check
        claim = await get_claim_by_id(claim_id, current_user["user_id"], db)
        
        if not claim:
            raise HTTPException(status_code=404, detail="Claim not found")
        
        # Log claim access
        await audit_logger.log_event(
            event_type="claim_access",
            user_id=current_user["user_id"],
            details={"claim_id": claim_id}
        )
        
        return claim
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving claim {claim_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# File upload endpoint with security validation
@app.post("/claims/{claim_id}/documents")
@limiter.limit("5/minute")
async def upload_claim_document(
    claim_id: str,
    request: Request,
    current_user: Dict = Depends(get_current_user)
):
    """Upload claim documents with comprehensive security validation"""
    try:
        # Validate claim ID
        if not security_utils.validate_uuid(claim_id):
            raise HTTPException(status_code=400, detail="Invalid claim ID format")
        
        # Process file upload with security validation
        form = await request.form()
        file = form.get("file")
        
        if not file:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Validate file
        validation_result = await security_utils.validate_file_upload(file)
        if not validation_result["valid"]:
            raise HTTPException(status_code=400, detail=validation_result["error"])
        
        # Process and store file securely
        file_result = await process_secure_file_upload(file, claim_id, current_user["user_id"])
        
        # Log file upload
        await audit_logger.log_event(
            event_type="document_upload",
            user_id=current_user["user_id"],
            ip_address=get_remote_address(request),
            details={
                "claim_id": claim_id,
                "filename": file.filename,
                "file_size": file.size
            }
        )
        
        return file_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading document for claim {claim_id}: {e}")
        raise HTTPException(status_code=500, detail="File upload failed")

# Admin endpoints with role-based access
@app.get("/admin/claims")
@limiter.limit("30/minute")
async def get_all_claims(
    current_user: Dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Admin endpoint to retrieve all claims"""
    # Check admin role
    if not auth_service.has_role(current_user, "admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        claims = await get_all_claims_admin(db)
        
        # Log admin access
        await audit_logger.log_event(
            event_type="admin_claims_access",
            user_id=current_user["user_id"],
            details={"claims_count": len(claims)}
        )
        
        return {"claims": claims}
        
    except Exception as e:
        logger.error(f"Error retrieving admin claims: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Audit log endpoint
@app.get("/admin/audit-logs")
@limiter.limit("10/minute")
async def get_audit_logs(
    current_user: Dict = Depends(get_current_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    event_type: Optional[str] = None
):
    """Retrieve audit logs (admin only)"""
    # Check admin role
    if not auth_service.has_role(current_user, "admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        logs = await audit_logger.get_audit_logs(
            start_date=start_date,
            end_date=end_date,
            event_type=event_type
        )
        
        return {"audit_logs": logs}
        
    except Exception as e:
        logger.error(f"Error retrieving audit logs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Placeholder functions for business logic
async def process_claim_with_ai(claim_data: Dict) -> Dict:
    """Process claim using AI/ML services"""
    # This would integrate with Strands SDK and Bedrock AgentCore
    # Placeholder implementation
    return {
        "claim_id": security_utils.generate_uuid(),
        "status": "submitted",
        "estimated_processing_time": "2-3 business days",
        "reference_number": f"CLM-{int(time.time())}"
    }

async def get_claim_by_id(claim_id: str, user_id: str, db: AsyncSession) -> Optional[Dict]:
    """Retrieve claim by ID with user authorization"""
    # Placeholder implementation
    return {
        "claim_id": claim_id,
        "user_id": user_id,
        "status": "processing",
        "submitted_at": datetime.utcnow().isoformat()
    }

async def get_all_claims_admin(db: AsyncSession) -> List[Dict]:
    """Retrieve all claims for admin users"""
    # Placeholder implementation
    return []

async def process_secure_file_upload(file, claim_id: str, user_id: str) -> Dict:
    """Process file upload with security measures"""
    # Placeholder implementation
    return {
        "file_id": security_utils.generate_uuid(),
        "filename": file.filename,
        "status": "uploaded",
        "scan_result": "clean"
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat(),
            "path": request.url.path
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "timestamp": datetime.utcnow().isoformat(),
            "path": request.url.path
        }
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.environment == "development",
        ssl_keyfile=settings.ssl_keyfile if settings.ssl_enabled else None,
        ssl_certfile=settings.ssl_certfile if settings.ssl_enabled else None,
        access_log=True,
        log_level="info"
    )