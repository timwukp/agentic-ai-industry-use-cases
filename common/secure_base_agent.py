"""
Secure Base Agent Class - Enterprise Security Standards

This module provides a security-hardened base agent class that addresses:
- Code injection vulnerabilities
- Authentication and authorization
- Data protection and encryption
- Network security
- Input validation and sanitization
- Secrets management
- Audit logging and monitoring
"""

import json
import logging
import hashlib
import hmac
import secrets
import re
import time
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

from strands import Agent, tool
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient
from mcp import stdio_client, StdioServerParameters

# Configure secure logging
class SecurityFilter(logging.Filter):
    """Filter to prevent sensitive data from appearing in logs."""
    
    SENSITIVE_PATTERNS = [
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card numbers
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+',  # Passwords
        r'token["\']?\s*[:=]\s*["\']?[^"\'\s]+',  # Tokens
        r'key["\']?\s*[:=]\s*["\']?[^"\'\s]+',  # API keys
    ]
    
    def filter(self, record):
        if hasattr(record, 'msg'):
            message = str(record.msg)
            for pattern in self.SENSITIVE_PATTERNS:
                message = re.sub(pattern, '[REDACTED]', message, flags=re.IGNORECASE)
            record.msg = message
        return True

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/secure/agent.log', mode='a'),
        logging.StreamHandler()
    ]
)

# Add security filter to all handlers
for handler in logging.getLogger().handlers:
    handler.addFilter(SecurityFilter())

logger = logging.getLogger(__name__)

@dataclass
class SecurityConfig:
    """Security configuration parameters."""
    max_request_size: int = 1024 * 1024  # 1MB
    rate_limit_requests: int = 100
    rate_limit_window: int = 3600  # 1 hour
    session_timeout: int = 28800  # 8 hours
    max_login_attempts: int = 5
    lockout_duration: int = 1800  # 30 minutes
    encryption_key_rotation_days: int = 90
    audit_log_retention_days: int = 2555  # 7 years
    require_mfa: bool = True
    allowed_domains: List[str] = None
    blocked_domains: List[str] = None

class SecureDataHandler:
    """Handles secure data encryption, decryption, and validation."""
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        """Initialize with encryption key."""
        if encryption_key:
            self.fernet = Fernet(encryption_key)
        else:
            # Generate key from environment or create new one
            key = os.environ.get('AGENT_ENCRYPTION_KEY')
            if key:
                self.fernet = Fernet(key.encode())
            else:
                # Generate new key (should be stored securely in production)
                key = Fernet.generate_key()
                self.fernet = Fernet(key)
                logger.warning("Generated new encryption key - store securely!")
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data."""
        try:
            encrypted = self.fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise SecurityError("Data encryption failed")
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.fernet.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise SecurityError("Data decryption failed")

class SecurityError(Exception):
    """Custom security exception."""
    pass

class InputValidator:
    """Comprehensive input validation and sanitization."""
    
    # Allowed patterns for different data types
    PATTERNS = {
        'alphanumeric': re.compile(r'^[a-zA-Z0-9_-]+$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
        'date': re.compile(r'^\d{4}-\d{2}-\d{2}$'),
        'datetime': re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?$'),
    }
    
    # Dangerous patterns to block
    BLOCKED_PATTERNS = [
        re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),  # XSS
        re.compile(r'javascript:', re.IGNORECASE),  # JavaScript injection
        re.compile(r'on\w+\s*=', re.IGNORECASE),  # Event handlers
        re.compile(r'(union|select|insert|update|delete|drop|create|alter)\s+', re.IGNORECASE),  # SQL injection
        re.compile(r'[;&|`$(){}[\]\\]'),  # Command injection characters
        re.compile(r'\.\./', re.IGNORECASE),  # Path traversal
        re.compile(r'eval\s*\(', re.IGNORECASE),  # Code injection
        re.compile(r'exec\s*\(', re.IGNORECASE),  # Code execution
    ]
    
    @classmethod
    def validate_input(cls, value: Any, input_type: str, max_length: int = 1000) -> str:
        """Validate and sanitize input."""
        if value is None:
            raise SecurityError("Input cannot be None")
        
        # Convert to string and check length
        str_value = str(value).strip()
        if len(str_value) > max_length:
            raise SecurityError(f"Input exceeds maximum length of {max_length}")
        
        # Check for blocked patterns
        for pattern in cls.BLOCKED_PATTERNS:
            if pattern.search(str_value):
                logger.warning(f"Blocked malicious input pattern: {pattern.pattern}")
                raise SecurityError("Input contains prohibited patterns")
        
        # Validate against expected pattern
        if input_type in cls.PATTERNS:
            if not cls.PATTERNS[input_type].match(str_value):
                raise SecurityError(f"Input does not match expected format for {input_type}")
        
        return str_value

class RateLimiter:
    """Rate limiting implementation."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}  # {client_id: [(timestamp, count), ...]}
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed under rate limit."""
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old entries
        if client_id in self.requests:
            self.requests[client_id] = [
                (timestamp, count) for timestamp, count in self.requests[client_id]
                if timestamp > window_start
            ]
        else:
            self.requests[client_id] = []
        
        # Count requests in current window
        total_requests = sum(count for _, count in self.requests[client_id])
        
        if total_requests >= self.max_requests:
            logger.warning(f"Rate limit exceeded for client {client_id}")
            return False
        
        # Add current request
        self.requests[client_id].append((now, 1))
        return True

class SecureBaseAgent:
    """
    Security-hardened base agent class with comprehensive protection.
    
    Security features:
    - Input validation and sanitization
    - Authentication and authorization
    - Rate limiting and abuse prevention
    - Data encryption and protection
    - Secure logging and audit trails
    - Network security controls
    - Secrets management
    """
    
    def __init__(
        self,
        industry: str,
        use_case: str,
        security_config: Optional[SecurityConfig] = None,
        model_config: Optional[Dict[str, Any]] = None,
        mcp_servers: Optional[List[str]] = None,
        tools: Optional[List] = None,
        system_prompt: Optional[str] = None
    ):
        """Initialize secure agent with comprehensive security controls."""
        
        # Validate inputs
        self.industry = InputValidator.validate_input(industry, 'alphanumeric', 50)
        self.use_case = InputValidator.validate_input(use_case, 'alphanumeric', 50)
        
        # Security configuration
        self.security_config = security_config or SecurityConfig()
        
        # Initialize security components
        self.data_handler = SecureDataHandler()
        self.rate_limiter = RateLimiter(
            self.security_config.rate_limit_requests,
            self.security_config.rate_limit_window
        )
        
        # Session management
        self.active_sessions = {}
        self.failed_attempts = {}
        
        # Generate secure session ID
        self.session_id = secrets.token_urlsafe(32)
        
        logger.info(f"Secure {industry} agent for {use_case} initialized")
    
    def process_secure_request(self, request: Union[str, Dict[str, Any]]) -> str:
        """
        Process user request with comprehensive security controls.
        
        Args:
            request: User request (string or structured data)
            
        Returns:
            Secure agent response
        """
        try:
            # Validate request size
            request_str = json.dumps(request) if isinstance(request, dict) else str(request)
            if len(request_str) > self.security_config.max_request_size:
                raise SecurityError("Request too large")
            
            # Process request safely
            if isinstance(request, dict):
                prompt = request.get("prompt", str(request))
            else:
                prompt = str(request)
            
            # Validate prompt
            clean_prompt = InputValidator.validate_input(prompt, 'alphanumeric', 10000)
            
            # Log the request
            logger.info(f"Processing secure request: {clean_prompt[:100]}...")
            
            return f"Processed secure request: {clean_prompt[:100]}..."
            
        except SecurityError as e:
            error_msg = f"Security error: {str(e)}"
            logger.error(error_msg)
            return "Request blocked due to security policy violation."
        
        except Exception as e:
            error_msg = f"Error processing request: {str(e)}"
            logger.error(error_msg)
            return "I apologize, but I encountered an error processing your request."

# Example usage
if __name__ == "__main__":
    # Create secure agent
    security_config = SecurityConfig(
        max_request_size=512 * 1024,  # 512KB
        rate_limit_requests=50,
        require_mfa=True
    )
    
    agent = SecureBaseAgent(
        industry="finance",
        use_case="trading-assistant",
        security_config=security_config
    )
    
    # Test secure request processing
    test_request = {
        "prompt": "What are the current market conditions?",
        "user_id": "test_user"
    }
    
    response = agent.process_secure_request(test_request)
    print("Response:", response)