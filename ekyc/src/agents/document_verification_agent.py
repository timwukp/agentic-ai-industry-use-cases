"""
Document Verification Agent for identity document analysis.
"""

import logging
import uuid
from typing import Any, Dict, Optional

from .base_ekyc_agent import AgentConfig, AgentResult, BaseEKYCAgent, VerificationStatus
from .exceptions import DocumentError, ValidationError
from ..models.document import (
    Document,
    DocumentType,
    DocumentVerificationResult,
    ExtractedData,
    QualityMetrics,
    SecurityFeatures,
)
from ..services.textract_service import TextractService

logger = logging.getLogger(__name__)


class DocumentVerificationAgent(BaseEKYCAgent):
    """
    Agent for verifying identity documents.
    
    Responsibilities:
    - Document capture guidance
    - OCR text extraction via AWS Textract
    - Document authenticity verification
    - Quality validation
    """

    AGENT_ID = "document-verification-agent"
    
    # Quality thresholds
    MIN_SHARPNESS = 0.6
    MIN_BRIGHTNESS = 0.3
    MAX_GLARE = 0.4
    MIN_COMPLETENESS = 0.8
    
    # Authenticity threshold
    MIN_AUTHENTICITY_SCORE = 0.85

    def __init__(self, config: Optional[AgentConfig] = None):
        super().__init__(self.AGENT_ID, config)
        self.textract = TextractService(
            region=self.config.region,
            max_retries=self.config.max_retries,
        )

    async def process(
        self, session_id: str, data: Dict[str, Any]
    ) -> AgentResult:
        """
        Process document verification request.
        
        Args:
            session_id: Verification session ID
            data: Document data including image_bytes or s3_key
            
        Returns:
            AgentResult with verification outcome
        """
        with self.measure_time() as timer:
            try:
                await self.validate_input(data)
                
                # Extract document data
                document = await self._process_document(session_id, data)
                
                # Verify authenticity
                is_authentic = document.authenticity_score >= self.MIN_AUTHENTICITY_SCORE
                
                # Check quality
                quality_issues = self._check_quality(document.quality_metrics)
                
                # Determine result
                success = is_authentic and not quality_issues and not document.fraud_indicators
                status = VerificationStatus.COMPLETED if success else VerificationStatus.FAILED
                
                result_data = {
                    "document_id": document.document_id,
                    "document_type": document.document_type.value,
                    "is_authentic": is_authentic,
                    "authenticity_score": document.authenticity_score,
                    "extracted_data": document.extracted_data.dict() if document.extracted_data else {},
                    "quality_issues": quality_issues,
                    "fraud_indicators": document.fraud_indicators,
                }
                
                audit_id = self.log_audit_event(
                    "document_verification",
                    {"session_id": session_id, "success": success},
                    session_id,
                )

            except Exception as e:
                logger.error(f"Document verification failed: {e}")
                return AgentResult(
                    success=False,
                    agent_id=self.agent_id,
                    session_id=session_id,
                    errors=[str(e)],
                    status=VerificationStatus.FAILED,
                    processing_time_ms=timer.elapsed_ms,
                )

        return AgentResult(
            success=success,
            agent_id=self.agent_id,
            session_id=session_id,
            data=result_data,
            confidence_score=document.authenticity_score * 100,
            processing_time_ms=timer.elapsed_ms,
            warnings=quality_issues,
            audit_id=audit_id,
            status=status,
        )

    async def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate document input data."""
        await super().validate_input(data)
        
        if not data.get("image_bytes") and not data.get("s3_key"):
            raise ValidationError("Document image required (image_bytes or s3_key)")
        
        if data.get("document_type"):
            try:
                DocumentType(data["document_type"])
            except ValueError:
                raise ValidationError(f"Invalid document type: {data['document_type']}")
        
        return True

    async def _process_document(
        self, session_id: str, data: Dict[str, Any]
    ) -> Document:
        """Process and analyze document."""
        document_id = str(uuid.uuid4())
        
        # Extract text using Textract
        if data.get("image_bytes"):
            ocr_result = await self.textract.analyze_id_document(
                image_bytes=data["image_bytes"]
            )
        else:
            ocr_result = await self.textract.analyze_id_document(
                s3_bucket=self.config.s3_bucket,
                s3_key=data["s3_key"],
            )
        
        # Parse extracted fields
        extracted = self._parse_extracted_fields(ocr_result.get("fields", {}))
        
        # Assess quality (simulated - in production use image analysis)
        quality = self._assess_quality(data)
        
        # Check security features (simulated)
        security = self._check_security_features(data)
        
        # Calculate authenticity score
        authenticity = self._calculate_authenticity(quality, security, ocr_result)
        
        # Detect fraud indicators
        fraud_indicators = self._detect_fraud(data, ocr_result)
        
        return Document(
            document_id=document_id,
            session_id=session_id,
            document_type=DocumentType(data.get("document_type", "passport")),
            country_code=data.get("country_code", "US"),
            extracted_data=extracted,
            authenticity_score=authenticity,
            is_authentic=authenticity >= self.MIN_AUTHENTICITY_SCORE,
            quality_metrics=quality,
            security_features=security,
            fraud_indicators=fraud_indicators,
            ocr_confidence=ocr_result.get("confidence_avg", 0) / 100,
        )

    def _parse_extracted_fields(self, fields: Dict) -> ExtractedData:
        """Parse OCR fields into ExtractedData model."""
        return ExtractedData(
            document_number=fields.get("DOCUMENT_NUMBER", {}).get("value"),
            first_name=fields.get("FIRST_NAME", {}).get("value"),
            last_name=fields.get("LAST_NAME", {}).get("value"),
            date_of_birth=None,  # Would parse date string
            expiry_date=None,
            issuing_country=fields.get("ISSUING_COUNTRY", {}).get("value"),
            mrz=fields.get("MRZ", {}).get("value"),
            raw_fields={k: v.get("value", "") for k, v in fields.items()},
        )

    def _assess_quality(self, data: Dict) -> QualityMetrics:
        """Assess document image quality."""
        # Simulated - in production use image processing
        return QualityMetrics(
            sharpness=0.85,
            brightness=0.75,
            glare=0.1,
            completeness=0.95,
            overall_quality=0.88,
        )

    def _check_security_features(self, data: Dict) -> SecurityFeatures:
        """Check for document security features."""
        # Simulated - in production use ML models
        return SecurityFeatures(
            hologram_detected=True,
            watermark_detected=True,
            microprinting_detected=False,
            features_list=["hologram", "watermark"],
        )

    def _calculate_authenticity(
        self, quality: QualityMetrics, security: SecurityFeatures, ocr: Dict
    ) -> float:
        """Calculate overall authenticity score."""
        quality_score = quality.overall_quality
        security_score = sum([
            security.hologram_detected * 0.3,
            security.watermark_detected * 0.3,
            security.microprinting_detected * 0.2,
        ]) / 0.8 if security.hologram_detected or security.watermark_detected else 0.5
        ocr_score = ocr.get("confidence_avg", 80) / 100
        
        return (quality_score * 0.3 + security_score * 0.4 + ocr_score * 0.3)

    def _detect_fraud(self, data: Dict, ocr: Dict) -> list:
        """Detect potential fraud indicators."""
        indicators = []
        # Simulated checks - in production use ML models
        return indicators

    def _check_quality(self, quality: Optional[QualityMetrics]) -> list:
        """Check quality metrics against thresholds."""
        issues = []
        if not quality:
            return ["Quality metrics unavailable"]
        
        if quality.sharpness < self.MIN_SHARPNESS:
            issues.append("Image too blurry")
        if quality.brightness < self.MIN_BRIGHTNESS:
            issues.append("Image too dark")
        if quality.glare > self.MAX_GLARE:
            issues.append("Too much glare")
        if quality.completeness < self.MIN_COMPLETENESS:
            issues.append("Document not fully visible")
        
        return issues
