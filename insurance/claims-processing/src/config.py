"""
Secure Configuration Management for Insurance Claims Processing System
Environment-based configuration with comprehensive validation
"""

import os
from typing import List, Optional, Union
from functools import lru_cache
from pydantic import BaseSettings, validator, Field
from pydantic.networks import AnyHttpUrl, PostgresDsn, RedisDsn


class SecuritySettings(BaseSettings):
    """Security-specific configuration settings"""
    
    # JWT Configuration
    jwt_secret_key: str = Field(..., env="JWT_SECRET_KEY", min_length=32)
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_expiration_hours: int = Field(default=24, env="JWT_EXPIRATION_HOURS", ge=1, le=168)
    jwt_refresh_expiration_days: int = Field(default=7, env="JWT_REFRESH_EXPIRATION_DAYS", ge=1, le=30)
    
    # Password Security
    password_min_length: int = Field(default=12, env="PASSWORD_MIN_LENGTH", ge=8)
    password_require_uppercase: bool = Field(default=True, env="PASSWORD_REQUIRE_UPPERCASE")
    password_require_lowercase: bool = Field(default=True, env="PASSWORD_REQUIRE_LOWERCASE")
    password_require_numbers: bool = Field(default=True, env="PASSWORD_REQUIRE_NUMBERS")
    password_require_special: bool = Field(default=True, env="PASSWORD_REQUIRE_SPECIAL")
    password_hash_rounds: int = Field(default=12, env="PASSWORD_HASH_ROUNDS", ge=10, le=15)
    
    # Session Security
    session_timeout_minutes: int = Field(default=30, env="SESSION_TIMEOUT_MINUTES", ge=5, le=480)
    max_login_attempts: int = Field(default=5, env="MAX_LOGIN_ATTEMPTS", ge=3, le=10)
    account_lockout_duration_minutes: int = Field(default=15, env="ACCOUNT_LOCKOUT_DURATION_MINUTES", ge=5, le=60)
    
    # Request Security
    max_request_size: int = Field(default=10485760, env="MAX_REQUEST_SIZE")  # 10MB
    max_file_size: int = Field(default=52428800, env="MAX_FILE_SIZE")  # 50MB
    allowed_file_types: List[str] = Field(
        default=["pdf", "jpg", "jpeg", "png", "doc", "docx"],
        env="ALLOWED_FILE_TYPES"
    )
    
    # Rate Limiting
    rate_limit_per_minute: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE", ge=10, le=1000)
    rate_limit_per_hour: int = Field(default=1000, env="RATE_LIMIT_PER_HOUR", ge=100, le=10000)
    
    # Encryption
    encryption_key: str = Field(..., env="ENCRYPTION_KEY", min_length=32)
    
    @validator('allowed_file_types', pre=True)
    def parse_file_types(cls, v):
        if isinstance(v, str):
            return [ext.strip().lower() for ext in v.split(',')]
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = False


class DatabaseSettings(BaseSettings):
    """Database configuration settings"""
    
    # PostgreSQL Configuration
    postgres_server: str = Field(..., env="POSTGRES_SERVER")
    postgres_user: str = Field(..., env="POSTGRES_USER")
    postgres_password: str = Field(..., env="POSTGRES_PASSWORD")
    postgres_db: str = Field(..., env="POSTGRES_DB")
    postgres_port: int = Field(default=5432, env="POSTGRES_PORT", ge=1, le=65535)
    postgres_ssl_mode: str = Field(default="require", env="POSTGRES_SSL_MODE")
    
    # Connection Pool Settings
    db_pool_size: int = Field(default=10, env="DB_POOL_SIZE", ge=5, le=50)
    db_max_overflow: int = Field(default=20, env="DB_MAX_OVERFLOW", ge=10, le=100)
    db_pool_timeout: int = Field(default=30, env="DB_POOL_TIMEOUT", ge=10, le=300)
    db_pool_recycle: int = Field(default=3600, env="DB_POOL_RECYCLE", ge=300, le=7200)
    
    @property
    def database_url(self) -> str:
        """Construct database URL with SSL configuration"""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_server}:{self.postgres_port}/{self.postgres_db}"
            f"?sslmode={self.postgres_ssl_mode}"
        )
    
    class Config:
        env_file = ".env"
        case_sensitive = False


class RedisSettings(BaseSettings):
    """Redis configuration settings"""
    
    redis_host: str = Field(default="localhost", env="REDIS_HOST")
    redis_port: int = Field(default=6379, env="REDIS_PORT", ge=1, le=65535)
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_db: int = Field(default=0, env="REDIS_DB", ge=0, le=15)
    redis_ssl: bool = Field(default=False, env="REDIS_SSL")
    redis_ssl_cert_reqs: str = Field(default="required", env="REDIS_SSL_CERT_REQS")
    
    # Connection Settings
    redis_max_connections: int = Field(default=20, env="REDIS_MAX_CONNECTIONS", ge=5, le=100)
    redis_retry_on_timeout: bool = Field(default=True, env="REDIS_RETRY_ON_TIMEOUT")
    redis_socket_timeout: int = Field(default=5, env="REDIS_SOCKET_TIMEOUT", ge=1, le=30)
    redis_socket_connect_timeout: int = Field(default=5, env="REDIS_SOCKET_CONNECT_TIMEOUT", ge=1, le=30)
    
    @property
    def redis_url(self) -> str:
        """Construct Redis URL with SSL and authentication"""
        scheme = "rediss" if self.redis_ssl else "redis"
        auth = f":{self.redis_password}@" if self.redis_password else ""
        ssl_params = "?ssl_cert_reqs=required" if self.redis_ssl else ""
        
        return f"{scheme}://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}{ssl_params}"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


class AWSSettings(BaseSettings):
    """AWS service configuration"""
    
    aws_region: str = Field(default="us-east-1", env="AWS_REGION")
    aws_access_key_id: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    aws_session_token: Optional[str] = Field(default=None, env="AWS_SESSION_TOKEN")
    
    # Bedrock Configuration
    bedrock_model_id: str = Field(default="anthropic.claude-3-sonnet-20240229-v1:0", env="BEDROCK_MODEL_ID")
    bedrock_agent_id: Optional[str] = Field(default=None, env="BEDROCK_AGENT_ID")
    bedrock_agent_alias_id: Optional[str] = Field(default=None, env="BEDROCK_AGENT_ALIAS_ID")
    
    # S3 Configuration
    s3_bucket_name: Optional[str] = Field(default=None, env="S3_BUCKET_NAME")
    s3_region: Optional[str] = Field(default=None, env="S3_REGION")
    
    # KMS Configuration
    kms_key_id: Optional[str] = Field(default=None, env="KMS_KEY_ID")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


class ApplicationSettings(BaseSettings):
    """Main application configuration"""
    
    # Application Info
    app_name: str = Field(default="Insurance Claims Processing System", env="APP_NAME")
    app_version: str = Field(default="2.0.0", env="APP_VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    
    # Server Configuration
    host: str = Field(default="127.0.0.1", env="HOST")
    port: int = Field(default=8000, env="PORT", ge=1, le=65535)
    workers: int = Field(default=1, env="WORKERS", ge=1, le=10)
    
    # SSL Configuration
    ssl_enabled: bool = Field(default=False, env="SSL_ENABLED")
    ssl_keyfile: Optional[str] = Field(default=None, env="SSL_KEYFILE")
    ssl_certfile: Optional[str] = Field(default=None, env="SSL_CERTFILE")
    
    # CORS Configuration
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "https://localhost:3000"],
        env="ALLOWED_ORIGINS"
    )
    allowed_hosts: List[str] = Field(
        default=["localhost", "127.0.0.1"],
        env="ALLOWED_HOSTS"
    )
    
    # Logging Configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: str = Field(default="app.log", env="LOG_FILE")
    log_max_size: int = Field(default=10485760, env="LOG_MAX_SIZE")  # 10MB
    log_backup_count: int = Field(default=5, env="LOG_BACKUP_COUNT")
    
    # Monitoring
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_port: int = Field(default=9090, env="METRICS_PORT", ge=1, le=65535)
    
    @validator('allowed_origins', 'allowed_hosts', pre=True)
    def parse_list_from_string(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(',')]
        return v
    
    @validator('environment')
    def validate_environment(cls, v):
        allowed_envs = ['development', 'staging', 'production']
        if v.lower() not in allowed_envs:
            raise ValueError(f'Environment must be one of: {allowed_envs}')
        return v.lower()
    
    @validator('log_level')
    def validate_log_level(cls, v):
        allowed_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in allowed_levels:
            raise ValueError(f'Log level must be one of: {allowed_levels}')
        return v.upper()
    
    class Config:
        env_file = ".env"
        case_sensitive = False


class Settings(BaseSettings):
    """Combined application settings"""
    
    # Include all setting groups
    app: ApplicationSettings = ApplicationSettings()
    security: SecuritySettings = SecuritySettings()
    database: DatabaseSettings = DatabaseSettings()
    redis: RedisSettings = RedisSettings()
    aws: AWSSettings = AWSSettings()
    
    # Convenience properties
    @property
    def database_url(self) -> str:
        return self.database.database_url
    
    @property
    def redis_url(self) -> str:
        return self.redis.redis_url
    
    @property
    def is_production(self) -> bool:
        return self.app.environment == "production"
    
    @property
    def is_development(self) -> bool:
        return self.app.environment == "development"
    
    @property
    def allowed_origins(self) -> List[str]:
        return self.app.allowed_origins
    
    @property
    def allowed_hosts(self) -> List[str]:
        return self.app.allowed_hosts
    
    @property
    def host(self) -> str:
        return self.app.host
    
    @property
    def port(self) -> int:
        return self.app.port
    
    @property
    def environment(self) -> str:
        return self.app.environment
    
    @property
    def ssl_enabled(self) -> bool:
        return self.app.ssl_enabled
    
    @property
    def ssl_keyfile(self) -> Optional[str]:
        return self.app.ssl_keyfile
    
    @property
    def ssl_certfile(self) -> Optional[str]:
        return self.app.ssl_certfile
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings"""
    return Settings()


def validate_required_env_vars():
    """Validate that all required environment variables are set"""
    required_vars = [
        "JWT_SECRET_KEY",
        "ENCRYPTION_KEY",
        "POSTGRES_SERVER",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "POSTGRES_DB"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")


def get_environment_specific_settings():
    """Get environment-specific configuration overrides"""
    settings = get_settings()
    
    if settings.is_production:
        # Production-specific overrides
        return {
            "debug": False,
            "log_level": "WARNING",
            "ssl_enabled": True,
            "allowed_origins": ["https://yourdomain.com"],
            "allowed_hosts": ["yourdomain.com", "www.yourdomain.com"]
        }
    elif settings.app.environment == "staging":
        # Staging-specific overrides
        return {
            "debug": False,
            "log_level": "INFO",
            "allowed_origins": ["https://staging.yourdomain.com"],
            "allowed_hosts": ["staging.yourdomain.com"]
        }
    else:
        # Development-specific overrides
        return {
            "debug": True,
            "log_level": "DEBUG",
            "ssl_enabled": False
        }


# Configuration validation on import
if __name__ != "__main__":
    try:
        validate_required_env_vars()
        settings = get_settings()
        print(f"Configuration loaded successfully for environment: {settings.environment}")
    except Exception as e:
        print(f"Configuration validation failed: {e}")
        raise