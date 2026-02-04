"""
eKYC Custom Exception Classes

This module defines custom exceptions for the eKYC system providing:
- Structured error handling
- Error categorization for appropriate responses
- Contextual information for debugging and audit logging
"""

from typing import Optional, Dict, Any


class EKYCException(Exception):
    """
    Base exception for all eKYC system errors.
    
    Attributes:
        message: Human-readable error message
        error_code: Unique error code for categorization
        details: Additional context about the error
        session_id: Associated verification session ID
        agent_id: ID of the agent that raised the error
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = "EKYC_ERROR",
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.session_id = session_id
        self.agent_id = agent_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/API responses."""
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "session_id": self.session_id,
            "agent_id": self.agent_id
        }
    
    def __str__(self) -> str:
        return f"[{self.error_code}] {self.message}"


class ValidationError(EKYCException):
    """
    Input validation failed.
    
    Raised when input data doesn't meet the required format,
    contains invalid values, or fails security checks.
    """
    
    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        invalid_value: Optional[Any] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        if field_name:
            details["field_name"] = field_name
        if invalid_value is not None:
            # Mask potentially sensitive values
            details["invalid_value"] = "[MASKED]" if self._is_sensitive(field_name) else str(invalid_value)[:100]
        
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.field_name = field_name
        self.invalid_value = invalid_value
    
    @staticmethod
    def _is_sensitive(field_name: Optional[str]) -> bool:
        """Check if field contains sensitive data."""
        if not field_name:
            return False
        sensitive_keywords = ["password", "secret", "key", "token", "ssn", "biometric", "face"]
        return any(keyword in field_name.lower() for keyword in sensitive_keywords)


class EncryptionError(EKYCException):
    """
    Encryption or decryption operation failed.
    
    Raised when KMS operations fail, key rotation issues occur,
    or data integrity checks fail during crypto operations.
    """
    
    def __init__(
        self,
        message: str,
        operation: str = "unknown",
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        details["operation"] = operation
        
        super().__init__(
            message=message,
            error_code="ENCRYPTION_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.operation = operation


class AWSServiceError(EKYCException):
    """
    AWS service call failed.
    
    Raised when calls to AWS services (Textract, Rekognition, KMS,
    DynamoDB, S3) fail due to service errors or misconfigurations.
    """
    
    def __init__(
        self,
        message: str,
        service_name: str,
        operation: Optional[str] = None,
        aws_error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        details["service_name"] = service_name
        if operation:
            details["operation"] = operation
        if aws_error_code:
            details["aws_error_code"] = aws_error_code
        
        super().__init__(
            message=message,
            error_code="AWS_SERVICE_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.service_name = service_name
        self.operation = operation
        self.aws_error_code = aws_error_code


class SessionError(EKYCException):
    """
    Session management error.
    
    Raised when session creation, lookup, update, or expiration
    handling fails.
    """
    
    def __init__(
        self,
        message: str,
        session_id: Optional[str] = None,
        session_state: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        if session_state:
            details["session_state"] = session_state
        
        super().__init__(
            message=message,
            error_code="SESSION_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.session_state = session_state


class TimeoutError(EKYCException):
    """
    Operation timed out.
    
    Raised when an operation exceeds the configured timeout threshold.
    Default workflow timeout is 60 seconds.
    """
    
    def __init__(
        self,
        message: str,
        operation: str,
        timeout_seconds: float,
        elapsed_seconds: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        details["operation"] = operation
        details["timeout_seconds"] = timeout_seconds
        if elapsed_seconds is not None:
            details["elapsed_seconds"] = elapsed_seconds
        
        super().__init__(
            message=message,
            error_code="TIMEOUT_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        self.elapsed_seconds = elapsed_seconds


class RateLimitError(EKYCException):
    """
    Rate limit exceeded.
    
    Raised when request rate exceeds configured thresholds
    (default: 1000 requests/minute per organization).
    """
    
    def __init__(
        self,
        message: str,
        limit: int,
        window_seconds: int,
        current_count: Optional[int] = None,
        retry_after_seconds: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        details["limit"] = limit
        details["window_seconds"] = window_seconds
        if current_count is not None:
            details["current_count"] = current_count
        if retry_after_seconds is not None:
            details["retry_after_seconds"] = retry_after_seconds
        
        super().__init__(
            message=message,
            error_code="RATE_LIMIT_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.limit = limit
        self.window_seconds = window_seconds
        self.current_count = current_count
        self.retry_after_seconds = retry_after_seconds


class BiometricError(EKYCException):
    """
    Biometric verification error.
    
    Raised when face matching, liveness detection, or other
    biometric operations fail.
    """
    
    def __init__(
        self,
        message: str,
        operation: str,
        confidence_score: Optional[float] = None,
        threshold: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        details["operation"] = operation
        if confidence_score is not None:
            details["confidence_score"] = confidence_score
        if threshold is not None:
            details["threshold"] = threshold
        
        super().__init__(
            message=message,
            error_code="BIOMETRIC_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.operation = operation
        self.confidence_score = confidence_score
        self.threshold = threshold


class DocumentError(EKYCException):
    """
    Document verification error.
    
    Raised when document capture, OCR extraction, or authenticity
    verification fails.
    """
    
    def __init__(
        self,
        message: str,
        document_type: Optional[str] = None,
        country_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        if document_type:
            details["document_type"] = document_type
        if country_code:
            details["country_code"] = country_code
        
        super().__init__(
            message=message,
            error_code="DOCUMENT_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.document_type = document_type
        self.country_code = country_code


class ComplianceError(EKYCException):
    """
    Compliance screening error.
    
    Raised when watchlist screening, PEP checks, or adverse media
    screening operations fail.
    """
    
    def __init__(
        self,
        message: str,
        screening_type: str,
        watchlist: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        details["screening_type"] = screening_type
        if watchlist:
            details["watchlist"] = watchlist
        
        super().__init__(
            message=message,
            error_code="COMPLIANCE_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.screening_type = screening_type
        self.watchlist = watchlist


class FraudDetectionError(EKYCException):
    """
    Fraud detection error.
    
    Raised when device fingerprinting, velocity checks, or fraud
    scoring operations fail.
    """
    
    def __init__(
        self,
        message: str,
        detection_type: str,
        risk_score: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        details["detection_type"] = detection_type
        if risk_score is not None:
            details["risk_score"] = risk_score
        
        super().__init__(
            message=message,
            error_code="FRAUD_DETECTION_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.detection_type = detection_type
        self.risk_score = risk_score


class ConsentError(EKYCException):
    """
    Consent management error.
    
    Raised when user consent is missing, invalid, or expired
    for required data processing operations.
    """
    
    def __init__(
        self,
        message: str,
        consent_type: str,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        details["consent_type"] = consent_type
        
        super().__init__(
            message=message,
            error_code="CONSENT_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.consent_type = consent_type


class ConfigurationError(EKYCException):
    """
    Configuration error.
    
    Raised when agent or system configuration is invalid or missing.
    """
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ):
        details = details or {}
        if config_key:
            details["config_key"] = config_key
        
        super().__init__(
            message=message,
            error_code="CONFIGURATION_ERROR",
            details=details,
            session_id=session_id,
            agent_id=agent_id
        )
        self.config_key = config_key


# Exception type mapping for error handling
EXCEPTION_MAP = {
    "EKYC_ERROR": EKYCException,
    "VALIDATION_ERROR": ValidationError,
    "ENCRYPTION_ERROR": EncryptionError,
    "AWS_SERVICE_ERROR": AWSServiceError,
    "SESSION_ERROR": SessionError,
    "TIMEOUT_ERROR": TimeoutError,
    "RATE_LIMIT_ERROR": RateLimitError,
    "BIOMETRIC_ERROR": BiometricError,
    "DOCUMENT_ERROR": DocumentError,
    "COMPLIANCE_ERROR": ComplianceError,
    "FRAUD_DETECTION_ERROR": FraudDetectionError,
    "CONSENT_ERROR": ConsentError,
    "CONFIGURATION_ERROR": ConfigurationError,
}


def get_exception_class(error_code: str) -> type:
    """Get exception class by error code."""
    return EXCEPTION_MAP.get(error_code, EKYCException)
