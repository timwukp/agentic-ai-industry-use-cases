"""
Security Utilities Module for Insurance Claims Processing System
Comprehensive security functions for validation, encryption, and sanitization
"""

import re
import uuid
import hashlib
import secrets
import base64
import mimetypes
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bleach
from email_validator import validate_email, EmailNotValidError
import magic
from PIL import Image
import io

from config import get_settings


class SecurityUtils:
    """Comprehensive security utilities for the insurance claims system"""
    
    def __init__(self):
        self.settings = get_settings()
        self._fernet = None
        self._init_encryption()
    
    def _init_encryption(self):
        """Initialize encryption with key derivation"""
        try:
            # Derive key from the encryption key in settings
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'insurance_claims_salt',  # In production, use random salt per encryption
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.settings.security.encryption_key.encode()))
            self._fernet = Fernet(key)
        except Exception as e:
            raise ValueError(f"Failed to initialize encryption: {e}")
    
    # Input Validation Methods
    
    def validate_user_input(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive user input validation and sanitization"""
        validated_data = {}
        
        for key, value in data.items():
            if value is None:
                validated_data[key] = None
                continue
            
            # String sanitization
            if isinstance(value, str):
                validated_data[key] = self.sanitize_string(value)
            elif isinstance(value, (int, float, bool)):
                validated_data[key] = value
            elif isinstance(value, dict):
                validated_data[key] = self.validate_user_input(value)
            elif isinstance(value, list):
                validated_data[key] = [self.sanitize_string(item) if isinstance(item, str) else item for item in value]
            else:
                validated_data[key] = str(value)
        
        return validated_data
    
    def sanitize_string(self, input_string: str, max_length: int = 1000) -> str:
        """Sanitize string input to prevent XSS and injection attacks"""
        if not input_string:
            return ""
        
        # Truncate if too long
        if len(input_string) > max_length:
            input_string = input_string[:max_length]
        
        # Remove null bytes and control characters
        input_string = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_string)
        
        # HTML sanitization
        allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
        allowed_attributes = {}
        
        sanitized = bleach.clean(
            input_string,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
        
        return sanitized.strip()
    
    def validate_email(self, email: str) -> bool:
        """Validate email address format and domain"""
        try:
            # Basic format validation
            validated_email = validate_email(email)
            
            # Additional security checks
            email_str = validated_email.email.lower()
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'[<>"\']',  # HTML/script injection attempts
                r'javascript:',  # JavaScript injection
                r'data:',  # Data URI injection
                r'\.\.',  # Directory traversal
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, email_str, re.IGNORECASE):
                    return False
            
            return True
            
        except EmailNotValidError:
            return False
    
    def validate_phone_number(self, phone: str) -> bool:
        """Validate phone number format"""
        # Remove all non-digit characters
        digits_only = re.sub(r'\D', '', phone)
        
        # Check length (10-15 digits for international numbers)
        if len(digits_only) < 10 or len(digits_only) > 15:
            return False
        
        # Basic format validation
        phone_pattern = r'^[\+]?[1-9][\d]{9,14}$'
        return bool(re.match(phone_pattern, digits_only))
    
    def validate_uuid(self, uuid_string: str) -> bool:
        """Validate UUID format"""
        try:
            uuid.UUID(uuid_string)
            return True
        except (ValueError, TypeError):
            return False
    
    def validate_claim_data(self, claim_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize insurance claim data"""
        validated_claim = {}
        
        # Required fields validation
        required_fields = ['claim_type', 'description', 'amount', 'incident_date']
        for field in required_fields:
            if field not in claim_data or not claim_data[field]:
                raise ValueError(f"Required field '{field}' is missing or empty")
        
        # Claim type validation
        allowed_claim_types = ['auto', 'home', 'health', 'life', 'travel', 'business']
        claim_type = claim_data['claim_type'].lower().strip()
        if claim_type not in allowed_claim_types:
            raise ValueError(f"Invalid claim type. Allowed types: {allowed_claim_types}")
        validated_claim['claim_type'] = claim_type
        
        # Description validation
        description = self.sanitize_string(claim_data['description'], max_length=5000)
        if len(description) < 10:
            raise ValueError("Claim description must be at least 10 characters long")
        validated_claim['description'] = description
        
        # Amount validation
        try:
            amount = float(claim_data['amount'])
            if amount <= 0 or amount > 1000000:  # Max claim amount
                raise ValueError("Claim amount must be between $0.01 and $1,000,000")
            validated_claim['amount'] = round(amount, 2)
        except (ValueError, TypeError):
            raise ValueError("Invalid claim amount format")
        
        # Date validation
        try:
            incident_date = datetime.fromisoformat(claim_data['incident_date'].replace('Z', '+00:00'))
            if incident_date > datetime.now():
                raise ValueError("Incident date cannot be in the future")
            if incident_date < datetime.now() - timedelta(days=365 * 5):  # 5 years ago
                raise ValueError("Incident date cannot be more than 5 years ago")
            validated_claim['incident_date'] = incident_date
        except (ValueError, TypeError):
            raise ValueError("Invalid incident date format")
        
        # Optional fields validation
        optional_fields = ['policy_number', 'location', 'witnesses', 'police_report_number']
        for field in optional_fields:
            if field in claim_data and claim_data[field]:
                validated_claim[field] = self.sanitize_string(str(claim_data[field]))
        
        return validated_claim
    
    # Password Security Methods
    
    def validate_password_strength(self, password: str) -> bool:
        """Validate password strength according to security policy"""
        if len(password) < self.settings.security.password_min_length:
            return False
        
        checks = []
        
        if self.settings.security.password_require_uppercase:
            checks.append(bool(re.search(r'[A-Z]', password)))
        
        if self.settings.security.password_require_lowercase:
            checks.append(bool(re.search(r'[a-z]', password)))
        
        if self.settings.security.password_require_numbers:
            checks.append(bool(re.search(r'\d', password)))
        
        if self.settings.security.password_require_special:
            checks.append(bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)))
        
        return all(checks)
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt with configurable rounds"""
        salt = bcrypt.gensalt(rounds=self.settings.security.password_hash_rounds)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception:
            return False
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    # File Security Methods
    
    async def validate_file_upload(self, file) -> Dict[str, Any]:
        """Comprehensive file upload validation"""
        try:
            # Check file size
            if hasattr(file, 'size') and file.size > self.settings.security.max_file_size:
                return {
                    "valid": False,
                    "error": f"File size exceeds maximum allowed size of {self.settings.security.max_file_size} bytes"
                }
            
            # Read file content for validation
            content = await file.read()
            await file.seek(0)  # Reset file pointer
            
            # Check actual file size
            if len(content) > self.settings.security.max_file_size:
                return {
                    "valid": False,
                    "error": "File size exceeds maximum allowed size"
                }
            
            # MIME type validation
            mime_type = magic.from_buffer(content, mime=True)
            file_extension = file.filename.split('.')[-1].lower() if '.' in file.filename else ''
            
            if file_extension not in self.settings.security.allowed_file_types:
                return {
                    "valid": False,
                    "error": f"File type '{file_extension}' not allowed"
                }
            
            # Validate MIME type matches extension
            expected_mime_types = {
                'pdf': 'application/pdf',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'png': 'image/png',
                'doc': 'application/msword',
                'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            }
            
            expected_mime = expected_mime_types.get(file_extension)
            if expected_mime and mime_type != expected_mime:
                return {
                    "valid": False,
                    "error": "File content does not match file extension"
                }
            
            # Image-specific validation
            if file_extension in ['jpg', 'jpeg', 'png']:
                try:
                    image = Image.open(io.BytesIO(content))
                    image.verify()  # Verify image integrity
                    
                    # Check image dimensions (prevent zip bombs)
                    if image.size[0] > 10000 or image.size[1] > 10000:
                        return {
                            "valid": False,
                            "error": "Image dimensions too large"
                        }
                        
                except Exception:
                    return {
                        "valid": False,
                        "error": "Invalid or corrupted image file"
                    }
            
            # Scan for malicious content patterns
            malicious_patterns = [
                b'<script',
                b'javascript:',
                b'vbscript:',
                b'onload=',
                b'onerror=',
                b'<?php',
                b'<%',
                b'exec(',
                b'system(',
                b'shell_exec('
            ]
            
            content_lower = content.lower()
            for pattern in malicious_patterns:
                if pattern in content_lower:
                    return {
                        "valid": False,
                        "error": "File contains potentially malicious content"
                    }
            
            return {
                "valid": True,
                "mime_type": mime_type,
                "file_size": len(content),
                "file_extension": file_extension
            }
            
        except Exception as e:
            return {
                "valid": False,
                "error": f"File validation error: {str(e)}"
            }
    
    # Encryption Methods
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        try:
            encrypted = self._fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self._fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def hash_sensitive_data(self, data: str) -> str:
        """Create irreversible hash of sensitive data for indexing"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    # Utility Methods
    
    def generate_uuid(self) -> str:
        """Generate UUID for unique identifiers"""
        return str(uuid.uuid4())
    
    def generate_claim_reference(self) -> str:
        """Generate unique claim reference number"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = secrets.token_hex(4).upper()
        return f"CLM-{timestamp}-{random_suffix}"
    
    def validate_ip_address(self, ip_address: str) -> bool:
        """Validate IP address format"""
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def is_safe_redirect_url(self, url: str, allowed_hosts: List[str]) -> bool:
        """Validate redirect URL to prevent open redirect attacks"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            # Allow relative URLs
            if not parsed.netloc:
                return True
            
            # Check if host is in allowed list
            return parsed.netloc.lower() in [host.lower() for host in allowed_hosts]
            
        except Exception:
            return False
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent directory traversal"""
        # Remove path separators and dangerous characters
        filename = re.sub(r'[<>:"/\\|?*]', '', filename)
        filename = re.sub(r'\.\.', '', filename)  # Remove directory traversal
        filename = filename.strip('. ')  # Remove leading/trailing dots and spaces
        
        # Ensure filename is not empty and not too long
        if not filename:
            filename = f"file_{secrets.token_hex(8)}"
        elif len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = f"{name[:250]}.{ext}" if ext else filename[:255]
        
        return filename
    
    def rate_limit_key(self, identifier: str, endpoint: str) -> str:
        """Generate rate limiting key"""
        return f"rate_limit:{identifier}:{endpoint}"
    
    def audit_log_entry(self, event_type: str, user_id: Optional[str], details: Dict[str, Any]) -> Dict[str, Any]:
        """Create standardized audit log entry"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "details": details,
            "session_id": details.get("session_id"),
            "ip_address": details.get("ip_address"),
            "user_agent": details.get("user_agent")
        }
    
    # SQL Injection Prevention
    
    def validate_sql_input(self, input_value: str) -> bool:
        """Check for potential SQL injection patterns"""
        sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(OR|AND)\b.*=.*)",
            r"(';|\")",
            r"(\bxp_cmdshell\b)",
            r"(\bsp_executesql\b)"
        ]
        
        for pattern in sql_injection_patterns:
            if re.search(pattern, input_value, re.IGNORECASE):
                return False
        
        return True
    
    # XSS Prevention
    
    def validate_html_input(self, html_content: str) -> str:
        """Sanitize HTML content to prevent XSS"""
        allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li']
        allowed_attributes = {}
        
        return bleach.clean(
            html_content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
    
    # CSRF Protection
    
    def generate_csrf_token(self) -> str:
        """Generate CSRF token"""
        return secrets.token_urlsafe(32)
    
    def validate_csrf_token(self, token: str, expected_token: str) -> bool:
        """Validate CSRF token"""
        return secrets.compare_digest(token, expected_token)