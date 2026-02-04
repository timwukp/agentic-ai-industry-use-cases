"""
AWS KMS service for encryption and key management.
"""

import base64
import logging
from typing import Any, Dict, Optional

import boto3
from botocore.config import Config

from ..agents.exceptions import AWSServiceError, EncryptionError

logger = logging.getLogger(__name__)


class EncryptionService:
    """Service for data encryption using AWS KMS."""

    def __init__(
        self,
        kms_key_id: Optional[str] = None,
        region: str = "us-east-1",
        max_retries: int = 3,
    ):
        self.kms_key_id = kms_key_id
        self.region = region
        self._client = boto3.client(
            "kms",
            config=Config(
                region_name=region,
                retries={"max_attempts": max_retries, "mode": "adaptive"},
            ),
        )

    async def encrypt(
        self, plaintext: str, key_id: Optional[str] = None
    ) -> str:
        """
        Encrypt plaintext using KMS.
        
        Args:
            plaintext: String to encrypt
            key_id: KMS key ID (uses default if not provided)
            
        Returns:
            Base64-encoded ciphertext
        """
        key = key_id or self.kms_key_id
        if not key:
            raise EncryptionError("KMS key ID not configured", operation="encrypt")

        try:
            response = self._client.encrypt(
                KeyId=key,
                Plaintext=plaintext.encode("utf-8"),
            )
            ciphertext = response["CiphertextBlob"]
            return base64.b64encode(ciphertext).decode("utf-8")
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}", operation="encrypt")

    async def decrypt(self, ciphertext_b64: str) -> str:
        """
        Decrypt ciphertext using KMS.
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            
        Returns:
            Decrypted plaintext string
        """
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            response = self._client.decrypt(CiphertextBlob=ciphertext)
            return response["Plaintext"].decode("utf-8")
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}", operation="decrypt")

    async def generate_data_key(
        self, key_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate a data key for envelope encryption."""
        key = key_id or self.kms_key_id
        if not key:
            raise EncryptionError("KMS key ID not configured", operation="generate_data_key")

        try:
            response = self._client.generate_data_key(
                KeyId=key,
                KeySpec="AES_256",
            )
            return {
                "plaintext_key": response["Plaintext"],
                "encrypted_key": base64.b64encode(response["CiphertextBlob"]).decode(),
                "key_id": response["KeyId"],
            }
        except Exception as e:
            raise EncryptionError(
                f"Data key generation failed: {e}", operation="generate_data_key"
            )

    async def encrypt_dict(
        self, data: Dict[str, Any], fields: list, key_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Encrypt specified fields in a dictionary."""
        result = data.copy()
        for field in fields:
            if field in result and result[field] is not None:
                value = str(result[field])
                result[field] = await self.encrypt(value, key_id)
        return result

    async def decrypt_dict(
        self, data: Dict[str, Any], fields: list
    ) -> Dict[str, Any]:
        """Decrypt specified fields in a dictionary."""
        result = data.copy()
        for field in fields:
            if field in result and result[field] is not None:
                result[field] = await self.decrypt(result[field])
        return result

    async def describe_key(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """Get KMS key metadata."""
        key = key_id or self.kms_key_id
        if not key:
            raise EncryptionError("KMS key ID not configured", operation="describe_key")

        try:
            response = self._client.describe_key(KeyId=key)
            metadata = response.get("KeyMetadata", {})
            return {
                "key_id": metadata.get("KeyId"),
                "arn": metadata.get("Arn"),
                "enabled": metadata.get("Enabled"),
                "key_state": metadata.get("KeyState"),
                "creation_date": str(metadata.get("CreationDate")),
            }
        except Exception as e:
            raise AWSServiceError(
                f"Failed to describe key: {e}",
                service_name="kms",
                operation="describe_key",
            )
