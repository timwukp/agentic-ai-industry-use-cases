"""
Authentication Service for Insurance Claims Processing System
Comprehensive authentication with JWT tokens, session management, and security controls
"""

import jwt
import redis.asyncio as redis
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_
import json
import secrets
from enum import Enum

from config import get_settings
from security_utils import SecurityUtils
from models import User, UserSession, LoginAttempt
from audit_logger import AuditLogger


class UserRole(Enum):
    """User roles for role-based access control"""
    USER = "user"
    AGENT = "agent"
    SUPERVISOR = "supervisor"
    ADMIN = "admin"


class AuthService:
    """Comprehensive authentication service"""
    
    def __init__(self):
        self.settings = get_settings()
        self.security_utils = SecurityUtils()
        self.audit_logger = AuditLogger()
        self._redis_client = None
    
    async def _get_redis_client(self) -> redis.Redis:
        """Get Redis client for session management"""
        if not self._redis_client:
            self._redis_client = redis.from_url(self.settings.redis_url)
        return self._redis_client
    
    # User Registration
    
    async def register_user(self, user_data: Dict[str, Any], db: AsyncSession) -> Dict[str, Any]:
        """Register new user with comprehensive validation"""
        try:
            # Validate email format
            if not self.security_utils.validate_email(user_data["email"]):
                raise ValueError("Invalid email format")
            
            # Check if user already exists
            existing_user = await self._get_user_by_email(user_data["email"], db)
            if existing_user:
                raise ValueError("User with this email already exists")
            
            # Validate password strength
            if not self.security_utils.validate_password_strength(user_data["password"]):
                raise ValueError("Password does not meet security requirements")
            
            # Hash password
            hashed_password = self.security_utils.hash_password(user_data["password"])
            
            # Create user record
            user = User(
                email=user_data["email"].lower().strip(),
                password_hash=hashed_password,
                first_name=self.security_utils.sanitize_string(user_data.get("first_name", "")),
                last_name=self.security_utils.sanitize_string(user_data.get("last_name", "")),
                phone=user_data.get("phone", ""),
                role=UserRole.USER.value,
                is_active=True,
                email_verified=False,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            db.add(user)
            await db.commit()
            await db.refresh(user)
            
            return {
                "user_id": str(user.id),
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at.isoformat()
            }
            
        except Exception as e:
            await db.rollback()
            raise ValueError(f"User registration failed: {str(e)}")
    
    # User Authentication
    
    async def authenticate_user(self, login_data: Dict[str, Any], db: AsyncSession) -> Dict[str, Any]:
        """Authenticate user and create session"""
        try:
            email = login_data["email"].lower().strip()
            password = login_data["password"]
            
            # Get user from database
            user = await self._get_user_by_email(email, db)
            if not user:
                raise ValueError("Invalid credentials")
            
            # Check if user is active
            if not user.is_active:
                raise ValueError("Account is deactivated")
            
            # Verify password
            if not self.security_utils.verify_password(password, user.password_hash):
                raise ValueError("Invalid credentials")
            
            # Generate tokens
            access_token = await self._generate_access_token(user)
            refresh_token = await self._generate_refresh_token(user)
            
            # Create session
            session_id = await self._create_user_session(user, access_token, refresh_token)
            
            # Update last login
            user.last_login = datetime.utcnow()
            await db.commit()
            
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": self.settings.security.jwt_expiration_hours * 3600,
                "user_id": str(user.id),
                "email": user.email,
                "role": user.role,
                "session_id": session_id
            }
            
        except Exception as e:
            raise ValueError(f"Authentication failed: {str(e)}")
    
    # Token Management
    
    async def _generate_access_token(self, user: User) -> str:
        """Generate JWT access token"""
        payload = {
            "user_id": str(user.id),
            "email": user.email,
            "role": user.role,
            "token_type": "access",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=self.settings.security.jwt_expiration_hours),
            "jti": secrets.token_urlsafe(16)  # JWT ID for token revocation
        }
        
        return jwt.encode(
            payload,
            self.settings.security.jwt_secret_key,
            algorithm=self.settings.security.jwt_algorithm
        )
    
    async def _generate_refresh_token(self, user: User) -> str:
        """Generate JWT refresh token"""
        payload = {
            "user_id": str(user.id),
            "token_type": "refresh",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=self.settings.security.jwt_refresh_expiration_days),
            "jti": secrets.token_urlsafe(16)
        }
        
        return jwt.encode(
            payload,
            self.settings.security.jwt_secret_key,
            algorithm=self.settings.security.jwt_algorithm
        )
    
    async def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate JWT token and return user data"""
        try:
            # Decode token
            payload = jwt.decode(
                token,
                self.settings.security.jwt_secret_key,
                algorithms=[self.settings.security.jwt_algorithm]
            )
            
            # Check token type
            if payload.get("token_type") != "access":
                raise ValueError("Invalid token type")
            
            # Check if token is blacklisted
            redis_client = await self._get_redis_client()
            jti = payload.get("jti")
            if jti and await redis_client.get(f"blacklist:{jti}"):
                raise ValueError("Token has been revoked")
            
            # Check session validity
            session_valid = await self._validate_user_session(payload["user_id"], token)
            if not session_valid:
                raise ValueError("Session is invalid or expired")
            
            return {
                "user_id": payload["user_id"],
                "email": payload["email"],
                "role": payload["role"],
                "token_id": jti
            }
            
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
        except Exception as e:
            raise ValueError(f"Token validation failed: {str(e)}")
    
    async def refresh_access_token(self, refresh_token: str, db: AsyncSession) -> Dict[str, Any]:
        """Refresh access token using refresh token"""
        try:
            # Validate refresh token
            payload = jwt.decode(
                refresh_token,
                self.settings.security.jwt_secret_key,
                algorithms=[self.settings.security.jwt_algorithm]
            )
            
            if payload.get("token_type") != "refresh":
                raise ValueError("Invalid token type")
            
            # Get user
            user = await self._get_user_by_id(payload["user_id"], db)
            if not user or not user.is_active:
                raise ValueError("User not found or inactive")
            
            # Generate new access token
            new_access_token = await self._generate_access_token(user)
            
            # Update session with new token
            await self._update_user_session(user.id, new_access_token)
            
            return {
                "access_token": new_access_token,
                "token_type": "bearer",
                "expires_in": self.settings.security.jwt_expiration_hours * 3600
            }
            
        except jwt.ExpiredSignatureError:
            raise ValueError("Refresh token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid refresh token")
        except Exception as e:
            raise ValueError(f"Token refresh failed: {str(e)}")
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke token by adding to blacklist"""
        try:
            payload = jwt.decode(
                token,
                self.settings.security.jwt_secret_key,
                algorithms=[self.settings.security.jwt_algorithm],
                options={"verify_exp": False}  # Allow expired tokens for revocation
            )
            
            jti = payload.get("jti")
            if jti:
                redis_client = await self._get_redis_client()
                # Add to blacklist with expiration matching token expiration
                exp_timestamp = payload.get("exp", 0)
                current_timestamp = datetime.utcnow().timestamp()
                ttl = max(0, int(exp_timestamp - current_timestamp))
                
                await redis_client.setex(f"blacklist:{jti}", ttl, "revoked")
                return True
            
            return False
            
        except Exception:
            return False
    
    # Session Management
    
    async def _create_user_session(self, user: User, access_token: str, refresh_token: str) -> str:
        """Create user session in Redis"""
        try:
            session_id = secrets.token_urlsafe(32)
            redis_client = await self._get_redis_client()
            
            session_data = {
                "user_id": str(user.id),
                "email": user.email,
                "role": user.role,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "created_at": datetime.utcnow().isoformat(),
                "last_activity": datetime.utcnow().isoformat(),
                "ip_address": None,  # Will be set by middleware
                "user_agent": None   # Will be set by middleware
            }\n            \n            # Store session with timeout\n            timeout_seconds = self.settings.security.session_timeout_minutes * 60\n            await redis_client.setex(\n                f\"session:{session_id}\",\n                timeout_seconds,\n                json.dumps(session_data)\n            )\n            \n            # Store user's active sessions (for multi-session management)\n            await redis_client.sadd(f\"user_sessions:{user.id}\", session_id)\n            await redis_client.expire(f\"user_sessions:{user.id}\", timeout_seconds)\n            \n            return session_id\n            \n        except Exception as e:\n            raise ValueError(f\"Session creation failed: {str(e)}\")\n    \n    async def _validate_user_session(self, user_id: str, access_token: str) -> bool:\n        \"\"\"Validate user session\"\"\"\n        try:\n            redis_client = await self._get_redis_client()\n            \n            # Get all user sessions\n            session_ids = await redis_client.smembers(f\"user_sessions:{user_id}\")\n            \n            for session_id in session_ids:\n                session_data_str = await redis_client.get(f\"session:{session_id.decode()}\")\n                if session_data_str:\n                    session_data = json.loads(session_data_str)\n                    if session_data.get(\"access_token\") == access_token:\n                        # Update last activity\n                        session_data[\"last_activity\"] = datetime.utcnow().isoformat()\n                        timeout_seconds = self.settings.security.session_timeout_minutes * 60\n                        await redis_client.setex(\n                            f\"session:{session_id.decode()}\",\n                            timeout_seconds,\n                            json.dumps(session_data)\n                        )\n                        return True\n            \n            return False\n            \n        except Exception:\n            return False\n    \n    async def _update_user_session(self, user_id: str, new_access_token: str) -> bool:\n        \"\"\"Update user session with new access token\"\"\"\n        try:\n            redis_client = await self._get_redis_client()\n            \n            # Get all user sessions\n            session_ids = await redis_client.smembers(f\"user_sessions:{user_id}\")\n            \n            for session_id in session_ids:\n                session_data_str = await redis_client.get(f\"session:{session_id.decode()}\")\n                if session_data_str:\n                    session_data = json.loads(session_data_str)\n                    session_data[\"access_token\"] = new_access_token\n                    session_data[\"last_activity\"] = datetime.utcnow().isoformat()\n                    \n                    timeout_seconds = self.settings.security.session_timeout_minutes * 60\n                    await redis_client.setex(\n                        f\"session:{session_id.decode()}\",\n                        timeout_seconds,\n                        json.dumps(session_data)\n                    )\n                    return True\n            \n            return False\n            \n        except Exception:\n            return False\n    \n    async def logout_user(self, user_id: str, session_id: Optional[str] = None) -> bool:\n        \"\"\"Logout user and invalidate session(s)\"\"\"\n        try:\n            redis_client = await self._get_redis_client()\n            \n            if session_id:\n                # Logout specific session\n                await redis_client.delete(f\"session:{session_id}\")\n                await redis_client.srem(f\"user_sessions:{user_id}\", session_id)\n            else:\n                # Logout all sessions\n                session_ids = await redis_client.smembers(f\"user_sessions:{user_id}\")\n                for sid in session_ids:\n                    await redis_client.delete(f\"session:{sid.decode()}\")\n                await redis_client.delete(f\"user_sessions:{user_id}\")\n            \n            return True\n            \n        except Exception:\n            return False\n    \n    # Account Security\n    \n    async def is_account_locked(self, email: str, ip_address: str) -> bool:\n        \"\"\"Check if account is locked due to failed login attempts\"\"\"\n        try:\n            redis_client = await self._get_redis_client()\n            \n            # Check email-based lockout\n            email_attempts = await redis_client.get(f\"login_attempts:email:{email}\")\n            if email_attempts and int(email_attempts) >= self.settings.security.max_login_attempts:\n                return True\n            \n            # Check IP-based lockout\n            ip_attempts = await redis_client.get(f\"login_attempts:ip:{ip_address}\")\n            if ip_attempts and int(ip_attempts) >= self.settings.security.max_login_attempts * 2:\n                return True\n            \n            return False\n            \n        except Exception:\n            return False\n    \n    async def record_failed_login(self, email: str, ip_address: str) -> None:\n        \"\"\"Record failed login attempt\"\"\"\n        try:\n            redis_client = await self._get_redis_client()\n            lockout_duration = self.settings.security.account_lockout_duration_minutes * 60\n            \n            # Increment email-based counter\n            email_key = f\"login_attempts:email:{email}\"\n            await redis_client.incr(email_key)\n            await redis_client.expire(email_key, lockout_duration)\n            \n            # Increment IP-based counter\n            ip_key = f\"login_attempts:ip:{ip_address}\"\n            await redis_client.incr(ip_key)\n            await redis_client.expire(ip_key, lockout_duration)\n            \n        except Exception:\n            pass  # Don't fail authentication due to logging issues\n    \n    async def clear_failed_login_attempts(self, email: str, ip_address: str) -> None:\n        \"\"\"Clear failed login attempts after successful login\"\"\"\n        try:\n            redis_client = await self._get_redis_client()\n            \n            await redis_client.delete(f\"login_attempts:email:{email}\")\n            await redis_client.delete(f\"login_attempts:ip:{ip_address}\")\n            \n        except Exception:\n            pass\n    \n    # Role-Based Access Control\n    \n    def has_role(self, user_data: Dict[str, Any], required_role: str) -> bool:\n        \"\"\"Check if user has required role\"\"\"\n        user_role = user_data.get(\"role\", \"\")\n        \n        # Define role hierarchy\n        role_hierarchy = {\n            UserRole.USER.value: 1,\n            UserRole.AGENT.value: 2,\n            UserRole.SUPERVISOR.value: 3,\n            UserRole.ADMIN.value: 4\n        }\n        \n        user_level = role_hierarchy.get(user_role, 0)\n        required_level = role_hierarchy.get(required_role, 0)\n        \n        return user_level >= required_level\n    \n    def has_permission(self, user_data: Dict[str, Any], permission: str) -> bool:\n        \"\"\"Check if user has specific permission\"\"\"\n        role = user_data.get(\"role\", \"\")\n        \n        # Define role permissions\n        role_permissions = {\n            UserRole.USER.value: [\n                \"view_own_claims\",\n                \"submit_claim\",\n                \"upload_documents\"\n            ],\n            UserRole.AGENT.value: [\n                \"view_own_claims\",\n                \"submit_claim\",\n                \"upload_documents\",\n                \"view_assigned_claims\",\n                \"update_claim_status\",\n                \"add_claim_notes\"\n            ],\n            UserRole.SUPERVISOR.value: [\n                \"view_own_claims\",\n                \"submit_claim\",\n                \"upload_documents\",\n                \"view_assigned_claims\",\n                \"update_claim_status\",\n                \"add_claim_notes\",\n                \"view_team_claims\",\n                \"assign_claims\",\n                \"approve_claims\"\n            ],\n            UserRole.ADMIN.value: [\n                \"*\"  # All permissions\n            ]\n        }\n        \n        permissions = role_permissions.get(role, [])\n        return \"*\" in permissions or permission in permissions\n    \n    # Database Helper Methods\n    \n    async def _get_user_by_email(self, email: str, db: AsyncSession) -> Optional[User]:\n        \"\"\"Get user by email\"\"\"\n        result = await db.execute(\n            select(User).where(User.email == email.lower())\n        )\n        return result.scalar_one_or_none()\n    \n    async def _get_user_by_id(self, user_id: str, db: AsyncSession) -> Optional[User]:\n        \"\"\"Get user by ID\"\"\"\n        result = await db.execute(\n            select(User).where(User.id == user_id)\n        )\n        return result.scalar_one_or_none()\n    \n    # Password Reset\n    \n    async def initiate_password_reset(self, email: str, db: AsyncSession) -> Dict[str, Any]:\n        \"\"\"Initiate password reset process\"\"\"\n        try:\n            user = await self._get_user_by_email(email, db)\n            if not user:\n                # Don't reveal if email exists\n                return {\"message\": \"If the email exists, a reset link has been sent\"}\n            \n            # Generate reset token\n            reset_token = secrets.token_urlsafe(32)\n            \n            # Store reset token in Redis with expiration\n            redis_client = await self._get_redis_client()\n            await redis_client.setex(\n                f\"password_reset:{reset_token}\",\n                3600,  # 1 hour expiration\n                str(user.id)\n            )\n            \n            # In a real implementation, send email with reset link\n            # For now, return the token (remove in production)\n            return {\n                \"message\": \"If the email exists, a reset link has been sent\",\n                \"reset_token\": reset_token  # Remove in production\n            }\n            \n        except Exception as e:\n            raise ValueError(f\"Password reset initiation failed: {str(e)}\")\n    \n    async def reset_password(self, reset_token: str, new_password: str, db: AsyncSession) -> Dict[str, Any]:\n        \"\"\"Reset user password using reset token\"\"\"\n        try:\n            # Validate new password\n            if not self.security_utils.validate_password_strength(new_password):\n                raise ValueError(\"Password does not meet security requirements\")\n            \n            # Get user ID from reset token\n            redis_client = await self._get_redis_client()\n            user_id = await redis_client.get(f\"password_reset:{reset_token}\")\n            \n            if not user_id:\n                raise ValueError(\"Invalid or expired reset token\")\n            \n            # Get user\n            user = await self._get_user_by_id(user_id.decode(), db)\n            if not user:\n                raise ValueError(\"User not found\")\n            \n            # Update password\n            user.password_hash = self.security_utils.hash_password(new_password)\n            user.updated_at = datetime.utcnow()\n            \n            await db.commit()\n            \n            # Delete reset token\n            await redis_client.delete(f\"password_reset:{reset_token}\")\n            \n            # Logout all user sessions\n            await self.logout_user(str(user.id))\n            \n            return {\"message\": \"Password reset successfully\"}\n            \n        except Exception as e:\n            await db.rollback()\n            raise ValueError(f\"Password reset failed: {str(e)}\")