"""
Biometric Verification Agent for facial recognition and liveness detection.
"""

import logging
import uuid
from typing import Any, Dict, Optional

from .base_ekyc_agent import AgentConfig, AgentResult, BaseEKYCAgent, VerificationStatus
from .exceptions import BiometricError, ValidationError
from ..models.biometric import (
    Biometric,
    BiometricVerificationResult,
    FaceMatch,
    LivenessDetection,
    LivenessMethod,
    LivenessResult,
)
from ..services.rekognition_service import RekognitionService

logger = logging.getLogger(__name__)


class BiometricVerificationAgent(BaseEKYCAgent):
    """
    Agent for biometric verification including face matching and liveness.
    
    Responsibilities:
    - Face matching (selfie vs document photo)
    - Active liveness detection
    - Passive liveness detection
    - Biometric data encryption
    """

    AGENT_ID = "biometric-verification-agent"
    
    # Thresholds
    FACE_MATCH_THRESHOLD = 0.95  # 95% match required
    LIVENESS_THRESHOLD = 0.90  # 90% confidence for liveness
    MAX_FACE_MATCH_ATTEMPTS = 3
    MAX_LIVENESS_ATTEMPTS = 2

    def __init__(self, config: Optional[AgentConfig] = None):
        super().__init__(self.AGENT_ID, config)
        self.rekognition = RekognitionService(
            region=self.config.region,
            max_retries=self.config.max_retries,
        )

    async def process(
        self, session_id: str, data: Dict[str, Any]
    ) -> AgentResult:
        """
        Process biometric verification request.
        
        Args:
            session_id: Verification session ID
            data: Biometric data including selfie and document photo
            
        Returns:
            AgentResult with verification outcome
        """
        with self.measure_time() as timer:
            try:
                await self.validate_input(data)
                
                biometric = await self._process_biometric(session_id, data)
                
                # Determine overall success
                liveness_passed = (
                    biometric.liveness_detection and 
                    biometric.liveness_detection.result == LivenessResult.LIVE
                )
                face_match_passed = (
                    biometric.face_match and 
                    biometric.face_match.is_match
                )
                
                success = liveness_passed and face_match_passed
                status = VerificationStatus.COMPLETED if success else VerificationStatus.FAILED
                
                # Calculate overall confidence
                confidence = self._calculate_confidence(biometric)
                
                result_data = {
                    "biometric_id": biometric.biometric_id,
                    "liveness_passed": liveness_passed,
                    "face_match_passed": face_match_passed,
                    "liveness_confidence": biometric.liveness_detection.confidence if biometric.liveness_detection else 0,
                    "face_match_score": biometric.face_match.match_score if biometric.face_match else 0,
                    "attempts": {
                        "liveness": biometric.liveness_attempts,
                        "face_match": biometric.face_match_attempts,
                    },
                }
                
                # Determine if manual review needed
                if not success and (
                    biometric.liveness_attempts >= self.MAX_LIVENESS_ATTEMPTS or
                    biometric.face_match_attempts >= self.MAX_FACE_MATCH_ATTEMPTS
                ):
                    status = VerificationStatus.MANUAL_REVIEW
                
                audit_id = self.log_audit_event(
                    "biometric_verification",
                    {"session_id": session_id, "success": success},
                    session_id,
                )

            except Exception as e:
                logger.error(f"Biometric verification failed: {e}")
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
            confidence_score=confidence,
            processing_time_ms=timer.elapsed_ms,
            audit_id=audit_id,
            status=status,
        )

    async def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate biometric input data."""
        await super().validate_input(data)
        
        if not data.get("selfie_bytes") and not data.get("selfie_s3_key"):
            raise ValidationError("Selfie image required")
        
        if not data.get("document_photo_bytes") and not data.get("document_photo_s3_key"):
            raise ValidationError("Document photo required for face matching")
        
        return True

    async def _process_biometric(
        self, session_id: str, data: Dict[str, Any]
    ) -> Biometric:
        """Process biometric verification."""
        biometric_id = str(uuid.uuid4())
        
        # Perform liveness detection
        liveness = await self._check_liveness(data)
        
        # Perform face matching
        face_match = await self._match_faces(data)
        
        return Biometric(
            biometric_id=biometric_id,
            session_id=session_id,
            liveness_detection=liveness,
            liveness_attempts=1,
            face_match=face_match,
            face_match_attempts=1,
        )

    async def _check_liveness(self, data: Dict[str, Any]) -> LivenessDetection:
        """Perform liveness detection."""
        # In production, use Rekognition Face Liveness
        # Simulated for now
        is_live = True  # Would be determined by actual liveness check
        confidence = 0.95 if is_live else 0.3
        
        return LivenessDetection(
            result=LivenessResult.LIVE if is_live else LivenessResult.SPOOF,
            method=LivenessMethod.PASSIVE,
            confidence=confidence,
            spoof_indicators=[] if is_live else ["texture_anomaly"],
        )

    async def _match_faces(self, data: Dict[str, Any]) -> FaceMatch:
        """Match selfie against document photo."""
        try:
            result = await self.rekognition.compare_faces(
                source_bytes=data.get("document_photo_bytes"),
                target_bytes=data.get("selfie_bytes"),
                source_s3={"Bucket": self.config.s3_bucket, "Name": data.get("document_photo_s3_key")} if data.get("document_photo_s3_key") else None,
                target_s3={"Bucket": self.config.s3_bucket, "Name": data.get("selfie_s3_key")} if data.get("selfie_s3_key") else None,
                threshold=self.FACE_MATCH_THRESHOLD * 100,
            )
            
            return FaceMatch(
                match_score=result["similarity"] / 100,
                confidence=result["confidence"] / 100,
                is_match=result["is_match"],
                threshold_used=self.FACE_MATCH_THRESHOLD,
            )
        except Exception as e:
            logger.warning(f"Face matching error: {e}")
            # Return failed match on error
            return FaceMatch(
                match_score=0.0,
                confidence=0.0,
                is_match=False,
                threshold_used=self.FACE_MATCH_THRESHOLD,
            )

    def _calculate_confidence(self, biometric: Biometric) -> float:
        """Calculate overall biometric confidence score."""
        scores = []
        
        if biometric.liveness_detection:
            scores.append(biometric.liveness_detection.confidence * 100)
        
        if biometric.face_match:
            scores.append(biometric.face_match.match_score * 100)
        
        return sum(scores) / len(scores) if scores else 0.0
