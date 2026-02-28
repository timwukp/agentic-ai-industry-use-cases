"""Security utilities for input validation, sanitization, and encryption.

Reuses patterns from the existing common/secure_base_agent.py with enhancements
for AgentCore deployment.
"""
import re
import logging
import hashlib
import hmac
import secrets
from typing import Optional

logger = logging.getLogger(__name__)

# Patterns that indicate potential injection attacks
INJECTION_PATTERNS = [
    r"(?i)(\b(eval|exec|compile|__import__|subprocess|os\.system)\s*\()",
    r"(?i)(<script[^>]*>)",
    r"(?i)(;\s*(drop|delete|truncate|alter)\s+)",
    r"(?i)(\b(union\s+select|or\s+1\s*=\s*1))",
    r"(?:\.\.\/|\.\.\\)",  # Path traversal
]

# Sensitive data patterns for log redaction
SENSITIVE_PATTERNS = [
    (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "[REDACTED_CARD]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    (r"(?i)(password|secret|token|api[_-]?key)\s*[=:]\s*\S+", "[REDACTED_CREDENTIAL]"),
]


def validate_input(text: str, max_length: int = 10000) -> tuple[bool, str]:
    """Validate user input for security threats.

    Args:
        text: Input text to validate.
        max_length: Maximum allowed length.

    Returns:
        Tuple of (is_valid, error_message). error_message is empty if valid.
    """
    if not text or not text.strip():
        return False, "Input cannot be empty"

    if len(text) > max_length:
        return False, f"Input exceeds maximum length of {max_length} characters"

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text):
            logger.warning(f"Potential injection attempt detected in input")
            return False, "Input contains potentially unsafe content"

    return True, ""


def sanitize_input(text: str) -> str:
    """Sanitize user input by removing potentially dangerous content."""
    # Remove null bytes
    text = text.replace("\x00", "")
    # Remove control characters except newlines and tabs
    text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text.strip()


def redact_sensitive_data(text: str) -> str:
    """Redact sensitive data from text for safe logging."""
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text


def generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(32)


def hash_value(value: str, salt: Optional[str] = None) -> str:
    """Create a SHA-256 hash of a value with optional salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 100000)
    return f"{salt}:{hashed.hex()}"
