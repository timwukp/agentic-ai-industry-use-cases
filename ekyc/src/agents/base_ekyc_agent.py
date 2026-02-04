"""
Base eKYC Agent class providing common functionality for all verification agents.
"""

import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config

from .exceptions import (
    AWSServiceError,
    ConfigurationError,
    EncryptionError,
    SessionError,
    ValidationError,
)

logger = logging.getLogger(__name__)


class VerificationStatus(str, Enum):
    """Verification session status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    MANUAL_REVIEW = "manual_review"


@dataclass
class AgentConfig:
    """Configuration for eKYC agents."""
    region: str = "us-east-1"
    kms_key_id: Optional[str] = None
    dynamodb_table: str = "ekyc-sessions"
    s3_bucket: str = "ekyc-documents"
    max_retries: int = 3
    timeout_seconds: int = 30
    enable_tracing: bool = True


@dataclass
class AgentResult:
    """Result from agent processing."""
    success: bool
    agent_id: str
    session_id: str
    data: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0
    processing_time_ms: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    audit_id: Optional[str] = None
    status: VerificationStatus = VerificationStatus.PENDING

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "success": self.success,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "data": self.data,
            "confidence_score": self.confidence_score,
            "processing_time_ms": self.processing_time_ms,
            "errors": self.errors,
            "warnings": self.warnings,
            "audit_id": self.audit_id,
            "status": self.status.value,
        }


class AWSClientManager:
    """Manages AWS service clients with connection pooling."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self._clients: Dict[str, Any] = {}
        self._boto_config = Config(
            region_name=config.region,
            retries={"max_attempts": config.max_retries, "mode": "adaptive"},
        )

    def _get_client(self, service_name: str) -> Any:
        """Get or create a boto3 client."""
        if service_name not in self._clients:
            try:
                self._clients[service_name] = boto3.client(
                    service_name, config=self._boto_config
                )
            except Exception as e:
                raise AWSServiceError(
                    f"Failed to create {service_name} client: {e}",
                    service_name=service_name,
                    operation="create_client",
                )
        return self._clients[service_name]

    def get_textract_client(self) -> Any:
        return self._get_client("textract")

    def get_rekognition_client(self) -> Any:
        return self._get_client("rekognition")

    def get_kms_client(self) -> Any:
        return self._get_client("kms")

    def get_dynamodb_client(self) -> Any:
        return self._get_client("dynamodb")

    def get_s3_client(self) -> Any:
        return self._get_client("s3")


class BaseEKYCAgent(ABC):
    """
    Base class for all eKYC verification agents.
    
    Provides common functionality for encryption, audit logging,
    performance monitoring, and AWS service integration.
    """

    def __init__(self, agent_id: str, config: Optional[AgentConfig] = None):
        """Initialize agent with ID and configuration."""
        self.agent_id = agent_id
        self.config = config or AgentConfig()
        self.aws_clients = AWSClientManager(self.config)
        self._setup_logging()
        logger.info(f"Initialized agent: {self.agent_id}")

    def _setup_logging(self) -> None:
        """Configure structured JSON logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='{"time":"%(asctime)s","agent":"%(name)s","level":"%(levelname)s","message":"%(message)s"}',
        )

    @abstractmethod
    async def process(self, session_id: str, data: Dict[str, Any]) -> AgentResult:
        """Main processing method - to be overridden by subclasses."""
        pass

    async def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data before processing."""
        if not data:
            raise ValidationError("Input data cannot be empty")
        if not isinstance(data, dict):
            raise ValidationError("Input data must be a dictionary")
        return True

    async def encrypt_sensitive_data(
        self, data: Dict[str, Any], fields: List[str]
    ) -> Dict[str, Any]:
        """Encrypt specified sensitive fields using KMS."""
        if not self.config.kms_key_id:
            raise ConfigurationError("KMS key ID not configured", config_key="kms_key_id")
        
        result = data.copy()
        kms = self.aws_clients.get_kms_client()
        
        for field_name in fields:
            if field_name in result and result[field_name]:
                try:
                    response = kms.encrypt(
                        KeyId=self.config.kms_key_id,
                        Plaintext=str(result[field_name]).encode(),
                    )
                    result[field_name] = response["CiphertextBlob"]
                except Exception as e:
                    raise EncryptionError(f"Failed to encrypt {field_name}: {e}", operation="encrypt")
        return result

    async def decrypt_sensitive_data(
        self, data: Dict[str, Any], fields: List[str]
    ) -> Dict[str, Any]:
        """Decrypt specified sensitive fields using KMS."""
        result = data.copy()
        kms = self.aws_clients.get_kms_client()
        
        for field_name in fields:
            if field_name in result and result[field_name]:
                try:
                    response = kms.decrypt(CiphertextBlob=result[field_name])
                    result[field_name] = response["Plaintext"].decode()
                except Exception as e:
                    raise EncryptionError(f"Failed to decrypt {field_name}: {e}", operation="decrypt")
        return result

    def log_audit_event(
        self, event_type: str, details: Dict[str, Any], session_id: Optional[str] = None
    ) -> str:
        """Log audit event with session context. Returns audit_id."""
        audit_id = str(uuid.uuid4())
        audit_record = {
            "audit_id": audit_id,
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": self.agent_id,
            "event_type": event_type,
            "session_id": session_id,
            "details": details,
        }
        logger.info(f"AUDIT: {audit_record}")
        return audit_id

    def measure_time(self) -> "TimingContext":
        """Context manager for measuring operation timing."""
        return TimingContext()

    async def health_check(self) -> bool:
        """Check agent health and dependencies."""
        try:
            # Test DynamoDB connection
            self.aws_clients.get_dynamodb_client().describe_limits()
            return True
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False


class TimingContext:
    """Context manager for timing operations."""

    def __init__(self):
        self.start_time: float = 0
        self.elapsed_ms: int = 0

    def __enter__(self) -> "TimingContext":
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args) -> None:
        self.elapsed_ms = int((time.perf_counter() - self.start_time) * 1000)
