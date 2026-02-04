"""
AWS Rekognition service for biometric verification.
"""

import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config

from ..agents.exceptions import AWSServiceError, BiometricError, ValidationError

logger = logging.getLogger(__name__)


class RekognitionService:
    """Service for facial recognition and liveness detection using AWS Rekognition."""

    # Default thresholds
    FACE_MATCH_THRESHOLD = 95.0  # 95% confidence required
    LIVENESS_CONFIDENCE_THRESHOLD = 90.0

    def __init__(self, region: str = "us-east-1", max_retries: int = 3):
        self.region = region
        self._client = boto3.client(
            "rekognition",
            config=Config(
                region_name=region,
                retries={"max_attempts": max_retries, "mode": "adaptive"},
            ),
        )

    async def compare_faces(
        self,
        source_bytes: Optional[bytes] = None,
        target_bytes: Optional[bytes] = None,
        source_s3: Optional[Dict[str, str]] = None,
        target_s3: Optional[Dict[str, str]] = None,
        threshold: float = FACE_MATCH_THRESHOLD,
    ) -> Dict[str, Any]:
        """
        Compare faces between source (document) and target (selfie).
        
        Args:
            source_bytes: Source image bytes (document photo)
            target_bytes: Target image bytes (selfie)
            source_s3: S3 location {"Bucket": "", "Name": ""}
            target_s3: S3 location for target
            threshold: Similarity threshold (default 95%)
            
        Returns:
            Face comparison results
        """
        source = self._build_image_param(source_bytes, source_s3)
        target = self._build_image_param(target_bytes, target_s3)

        try:
            response = self._client.compare_faces(
                SourceImage=source,
                TargetImage=target,
                SimilarityThreshold=threshold,
            )
            return self._parse_compare_response(response, threshold)
        except self._client.exceptions.InvalidParameterException as e:
            raise BiometricError(
                f"Invalid image for face comparison: {e}",
                operation="compare_faces",
            )
        except Exception as e:
            raise AWSServiceError(
                f"Face comparison failed: {e}",
                service_name="rekognition",
                operation="compare_faces",
            )

    async def detect_faces(
        self,
        image_bytes: Optional[bytes] = None,
        s3_bucket: Optional[str] = None,
        s3_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Detect faces in an image."""
        image = self._build_image_param(
            image_bytes, {"Bucket": s3_bucket, "Name": s3_key} if s3_bucket else None
        )

        try:
            response = self._client.detect_faces(
                Image=image,
                Attributes=["ALL"],
            )
            return self._parse_detect_response(response)
        except Exception as e:
            raise AWSServiceError(
                f"Face detection failed: {e}",
                service_name="rekognition",
                operation="detect_faces",
            )

    async def create_liveness_session(self) -> Dict[str, str]:
        """Create a Face Liveness session."""
        try:
            response = self._client.create_face_liveness_session(
                Settings={"AuditImagesLimit": 4}
            )
            return {
                "session_id": response["SessionId"],
            }
        except Exception as e:
            raise AWSServiceError(
                f"Failed to create liveness session: {e}",
                service_name="rekognition",
                operation="create_face_liveness_session",
            )

    async def get_liveness_session_results(
        self, session_id: str
    ) -> Dict[str, Any]:
        """Get Face Liveness session results."""
        try:
            response = self._client.get_face_liveness_session_results(
                SessionId=session_id
            )
            return {
                "status": response.get("Status"),
                "confidence": response.get("Confidence", 0),
                "is_live": response.get("Confidence", 0) >= self.LIVENESS_CONFIDENCE_THRESHOLD,
                "reference_image": response.get("ReferenceImage"),
                "audit_images": response.get("AuditImages", []),
            }
        except Exception as e:
            raise AWSServiceError(
                f"Failed to get liveness results: {e}",
                service_name="rekognition",
                operation="get_face_liveness_session_results",
            )

    def _build_image_param(
        self, image_bytes: Optional[bytes], s3_location: Optional[Dict]
    ) -> Dict[str, Any]:
        """Build Rekognition image parameter."""
        if image_bytes:
            return {"Bytes": image_bytes}
        if s3_location and s3_location.get("Bucket") and s3_location.get("Name"):
            return {"S3Object": s3_location}
        raise ValidationError("Either image bytes or S3 location required")

    def _parse_compare_response(
        self, response: Dict, threshold: float
    ) -> Dict[str, Any]:
        """Parse face comparison response."""
        matches = response.get("FaceMatches", [])
        if not matches:
            return {
                "is_match": False,
                "similarity": 0.0,
                "confidence": 0.0,
                "threshold": threshold,
                "face_details": None,
            }

        best_match = matches[0]
        similarity = best_match.get("Similarity", 0)
        return {
            "is_match": similarity >= threshold,
            "similarity": similarity,
            "confidence": best_match.get("Face", {}).get("Confidence", 0),
            "threshold": threshold,
            "face_details": best_match.get("Face"),
        }

    def _parse_detect_response(self, response: Dict) -> Dict[str, Any]:
        """Parse face detection response."""
        faces = response.get("FaceDetails", [])
        return {
            "face_count": len(faces),
            "faces": [
                {
                    "confidence": f.get("Confidence", 0),
                    "bounding_box": f.get("BoundingBox"),
                    "quality": {
                        "brightness": f.get("Quality", {}).get("Brightness", 0),
                        "sharpness": f.get("Quality", {}).get("Sharpness", 0),
                    },
                    "pose": f.get("Pose"),
                    "emotions": f.get("Emotions", []),
                }
                for f in faces
            ],
        }
