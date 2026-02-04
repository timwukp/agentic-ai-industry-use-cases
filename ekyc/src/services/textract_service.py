"""
AWS Textract service for document OCR and text extraction.
"""

import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config

from ..agents.exceptions import AWSServiceError, ValidationError

logger = logging.getLogger(__name__)


class TextractService:
    """Service for document text extraction using AWS Textract."""

    def __init__(self, region: str = "us-east-1", max_retries: int = 3):
        self.region = region
        self._client = boto3.client(
            "textract",
            config=Config(
                region_name=region,
                retries={"max_attempts": max_retries, "mode": "adaptive"},
            ),
        )

    async def analyze_document(
        self,
        image_bytes: Optional[bytes] = None,
        s3_bucket: Optional[str] = None,
        s3_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze document using Textract.
        
        Args:
            image_bytes: Raw image bytes (max 5MB)
            s3_bucket: S3 bucket name (for images > 5MB)
            s3_key: S3 object key
            
        Returns:
            Dictionary containing extracted text and blocks
        """
        if not image_bytes and not (s3_bucket and s3_key):
            raise ValidationError("Either image_bytes or S3 location required")

        try:
            if image_bytes:
                response = self._client.analyze_document(
                    Document={"Bytes": image_bytes},
                    FeatureTypes=["FORMS", "TABLES"],
                )
            else:
                response = self._client.analyze_document(
                    Document={"S3Object": {"Bucket": s3_bucket, "Name": s3_key}},
                    FeatureTypes=["FORMS", "TABLES"],
                )
            return self._parse_response(response)
        except Exception as e:
            raise AWSServiceError(
                f"Textract analysis failed: {e}",
                service_name="textract",
                operation="analyze_document",
            )

    async def detect_document_text(
        self,
        image_bytes: Optional[bytes] = None,
        s3_bucket: Optional[str] = None,
        s3_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Detect text in document (simpler than analyze)."""
        if not image_bytes and not (s3_bucket and s3_key):
            raise ValidationError("Either image_bytes or S3 location required")

        try:
            if image_bytes:
                response = self._client.detect_document_text(
                    Document={"Bytes": image_bytes}
                )
            else:
                response = self._client.detect_document_text(
                    Document={"S3Object": {"Bucket": s3_bucket, "Name": s3_key}}
                )
            return self._parse_text_response(response)
        except Exception as e:
            raise AWSServiceError(
                f"Textract text detection failed: {e}",
                service_name="textract",
                operation="detect_document_text",
            )

    async def analyze_id_document(
        self,
        image_bytes: Optional[bytes] = None,
        s3_bucket: Optional[str] = None,
        s3_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze identity document using Textract AnalyzeID."""
        if not image_bytes and not (s3_bucket and s3_key):
            raise ValidationError("Either image_bytes or S3 location required")

        try:
            if image_bytes:
                response = self._client.analyze_id(
                    DocumentPages=[{"Bytes": image_bytes}]
                )
            else:
                response = self._client.analyze_id(
                    DocumentPages=[{"S3Object": {"Bucket": s3_bucket, "Name": s3_key}}]
                )
            return self._parse_id_response(response)
        except Exception as e:
            raise AWSServiceError(
                f"Textract ID analysis failed: {e}",
                service_name="textract",
                operation="analyze_id",
            )

    def _parse_response(self, response: Dict) -> Dict[str, Any]:
        """Parse Textract analyze response."""
        blocks = response.get("Blocks", [])
        result = {
            "raw_text": "",
            "lines": [],
            "words": [],
            "key_values": {},
            "tables": [],
            "confidence_avg": 0.0,
        }
        
        confidences = []
        for block in blocks:
            block_type = block.get("BlockType")
            if block_type == "LINE":
                result["lines"].append(block.get("Text", ""))
                result["raw_text"] += block.get("Text", "") + "\n"
            elif block_type == "WORD":
                result["words"].append({
                    "text": block.get("Text", ""),
                    "confidence": block.get("Confidence", 0),
                })
                confidences.append(block.get("Confidence", 0))

        if confidences:
            result["confidence_avg"] = sum(confidences) / len(confidences)
        return result

    def _parse_text_response(self, response: Dict) -> Dict[str, Any]:
        """Parse Textract detect text response."""
        blocks = response.get("Blocks", [])
        lines = [b.get("Text", "") for b in blocks if b.get("BlockType") == "LINE"]
        return {
            "raw_text": "\n".join(lines),
            "lines": lines,
            "block_count": len(blocks),
        }

    def _parse_id_response(self, response: Dict) -> Dict[str, Any]:
        """Parse Textract AnalyzeID response."""
        documents = response.get("IdentityDocuments", [])
        if not documents:
            return {"fields": {}, "document_type": None}

        doc = documents[0]
        fields = {}
        for field in doc.get("IdentityDocumentFields", []):
            field_type = field.get("Type", {}).get("Text", "")
            field_value = field.get("ValueDetection", {}).get("Text", "")
            confidence = field.get("ValueDetection", {}).get("Confidence", 0)
            if field_type and field_value:
                fields[field_type] = {
                    "value": field_value,
                    "confidence": confidence,
                }

        return {
            "fields": fields,
            "document_type": fields.get("DOCUMENT_TYPE", {}).get("value"),
        }
