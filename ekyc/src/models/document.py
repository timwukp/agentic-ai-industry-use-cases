"""
Document data models for identity document verification.
"""

from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DocumentType(str, Enum):
    """Supported identity document types."""
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    NATIONAL_ID = "national_id"
    RESIDENCE_PERMIT = "residence_permit"


class DocumentSide(str, Enum):
    """Document side identifier."""
    FRONT = "front"
    BACK = "back"


class QualityMetrics(BaseModel):
    """Document image quality metrics."""
    sharpness: float = Field(..., ge=0, le=1.0)
    brightness: float = Field(..., ge=0, le=1.0)
    glare: float = Field(..., ge=0, le=1.0, description="0=no glare, 1=severe glare")
    completeness: float = Field(..., ge=0, le=1.0)
    overall_quality: float = Field(..., ge=0, le=1.0)


class SecurityFeatures(BaseModel):
    """Detected document security features."""
    hologram_detected: bool = False
    watermark_detected: bool = False
    microprinting_detected: bool = False
    uv_features_detected: bool = False
    features_list: List[str] = Field(default_factory=list)


class ExtractedData(BaseModel):
    """Data extracted from document via OCR."""
    document_number: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    full_name: Optional[str] = None
    date_of_birth: Optional[date] = None
    expiry_date: Optional[date] = None
    issue_date: Optional[date] = None
    issuing_authority: Optional[str] = None
    issuing_country: Optional[str] = None
    nationality: Optional[str] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    mrz: Optional[str] = Field(None, description="Machine Readable Zone data")
    raw_fields: Optional[Dict[str, str]] = None


class DocumentUpload(BaseModel):
    """Request model for document upload."""
    document_type: DocumentType
    country_code: str = Field(..., min_length=2, max_length=3)
    side: DocumentSide = DocumentSide.FRONT
    image_base64: Optional[str] = Field(None, description="Base64 encoded image")
    image_s3_key: Optional[str] = None


class Document(BaseModel):
    """Verified identity document model."""
    document_id: str
    session_id: str
    document_type: DocumentType
    country_code: str
    
    # Image references
    front_image_s3_uri: Optional[str] = None
    back_image_s3_uri: Optional[str] = None
    
    # Extracted data
    extracted_data: Optional[ExtractedData] = None
    
    # Verification results
    authenticity_score: float = Field(0.0, ge=0, le=1.0)
    is_authentic: Optional[bool] = None
    quality_metrics: Optional[QualityMetrics] = None
    security_features: Optional[SecurityFeatures] = None
    
    # Fraud indicators
    is_photocopy: bool = False
    is_screenshot: bool = False
    is_manipulated: bool = False
    fraud_indicators: List[str] = Field(default_factory=list)
    
    # Processing metadata
    ocr_confidence: float = Field(0.0, ge=0, le=1.0)
    processing_time_ms: int = 0
    encryption_key_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            date: lambda v: v.isoformat(),
        }


class DocumentVerificationResult(BaseModel):
    """Result of document verification."""
    document_id: str
    session_id: str
    is_valid: bool
    authenticity_score: float = Field(..., ge=0, le=1.0)
    extracted_data: Optional[ExtractedData] = None
    quality_issues: List[str] = Field(default_factory=list)
    fraud_indicators: List[str] = Field(default_factory=list)
    requires_recapture: bool = False
    recapture_reason: Optional[str] = None
