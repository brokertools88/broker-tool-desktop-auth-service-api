"""
InsureCove Authentication Service - Configuration Management

Comprehensive configuration management using Pydantic Settings with:
- Environment-based configuration
- Type validation and defaults
- Security settings
- Database and external service configs
- AWS integration settings
- CORS and rate limiting configuration
"""

import os
from typing import List, Optional, Union, Any, Dict
from functools import lru_cache
from pathlib import Path

try:
    from pydantic_settings import BaseSettings
    from pydantic import Field, field_validator, model_validator
except ImportError:
    # Fallback for older pydantic versions
    from pydantic import BaseSettings, Field, validator as field_validator, root_validator as model_validator


class DatabaseSettings(BaseSettings):
    """Database configuration settings"""
    
    # Supabase Configuration
    supabase_url: Optional[str] = Field(default=None, env="SUPABASE_URL")
    supabase_anon_key: Optional[str] = Field(default=None, env="SUPABASE_ANON_KEY")
    supabase_service_key: Optional[str] = Field(default=None, env="SUPABASE_SERVICE_KEY")
    database_password: Optional[str] = Field(default=None, env="DATABASE_PASSWORD")
    
    # Connection settings
    max_connections: int = Field(default=10, env="DB_MAX_CONNECTIONS")
    connection_timeout: int = Field(default=30, env="DB_CONNECTION_TIMEOUT")
    
    model_config = {
        "env_prefix": "DB_",
        "case_sensitive": False
    }


class AWSSettings(BaseSettings):
    """AWS configuration settings"""
    
    # AWS Credentials
    aws_access_key_id: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    aws_region: str = Field(default="ap-east-1", env="AWS_DEFAULT_REGION")
    
    # Proxy settings for corporate networks
    http_proxy: Optional[str] = Field(default=None, env="HTTP_PROXY")
    https_proxy: Optional[str] = Field(default=None, env="HTTPS_PROXY")
    
    # Secrets Manager settings
    secret_prefix: str = Field(default="insurecove", env="SECRET_PREFIX")
    secret_cache_ttl: int = Field(default=300, env="SECRET_CACHE_TTL")  # 5 minutes
    
    # S3 settings
    s3_bucket_name: Optional[str] = Field(default=None, env="S3_BUCKET_NAME")
    max_file_size_mb: int = Field(default=10, env="MAX_FILE_SIZE_MB")
    
    model_config = {
        "env_prefix": "AWS_",
        "case_sensitive": False
    }


class JWTSettings(BaseSettings):
    """JWT configuration settings"""
    
    # JWT Configuration (will be overridden by AWS Secrets Manager in production)
    jwt_secret_key: Optional[str] = Field(default=None, env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_issuer: str = Field(default="insurecove-auth", env="JWT_ISSUER")
    jwt_audience: str = Field(default="insurecove-api", env="JWT_AUDIENCE")
    
    # Token expiration settings
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    service_token_expire_hours: int = Field(default=24, env="SERVICE_TOKEN_EXPIRE_HOURS")
    
    # Token validation settings
    allow_refresh_token_reuse: bool = Field(default=False, env="ALLOW_REFRESH_TOKEN_REUSE")
    require_aud_claim: bool = Field(default=True, env="REQUIRE_AUD_CLAIM")
    
    model_config = {
        "env_prefix": "JWT_",
        "case_sensitive": False
    }


class SecuritySettings(BaseSettings):
    """Security configuration settings"""
    
    # Password settings
    min_password_length: int = Field(default=8, env="MIN_PASSWORD_LENGTH")
    require_uppercase: bool = Field(default=True, env="REQUIRE_UPPERCASE")
    require_lowercase: bool = Field(default=True, env="REQUIRE_LOWERCASE")
    require_numbers: bool = Field(default=True, env="REQUIRE_NUMBERS")
    require_special_chars: bool = Field(default=True, env="REQUIRE_SPECIAL_CHARS")
    
    # Rate limiting
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_window: int = Field(default=60, env="RATE_LIMIT_WINDOW")  # seconds
    
    # Session settings
    session_timeout_minutes: int = Field(default=60, env="SESSION_TIMEOUT_MINUTES")
    max_failed_attempts: int = Field(default=5, env="MAX_FAILED_ATTEMPTS")
    lockout_duration_minutes: int = Field(default=15, env="LOCKOUT_DURATION_MINUTES")
    
    # CORS settings
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"],
        env="ALLOWED_ORIGINS"
    )
    allowed_methods: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        env="ALLOWED_METHODS"
    )
    allowed_headers: List[str] = Field(
        default=["*"],
        env="ALLOWED_HEADERS"
    )
    
    # Encryption settings
    encryption_key: Optional[str] = Field(default=None, env="ENCRYPTION_KEY")
    encryption_salt: Optional[str] = Field(default=None, env="ENCRYPTION_SALT")
    
    @field_validator('allowed_origins', mode='before')
    @classmethod
    def parse_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(',')]
        return v
    
    @field_validator('allowed_methods', mode='before')
    @classmethod
    def parse_methods(cls, v):
        if isinstance(v, str):
            return [method.strip().upper() for method in v.split(',')]
        return v
    
    @field_validator('allowed_headers', mode='before')
    @classmethod
    def parse_headers(cls, v):
        if isinstance(v, str):
            return [header.strip() for header in v.split(',')]
        return v
    
    model_config = {
        "env_prefix": "SECURITY_",
        "case_sensitive": False
    }


class LoggingSettings(BaseSettings):
    """Logging configuration settings"""
    
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        env="LOG_FORMAT"
    )
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    log_max_bytes: int = Field(default=10_000_000, env="LOG_MAX_BYTES")  # 10MB
    log_backup_count: int = Field(default=5, env="LOG_BACKUP_COUNT")
    
    # Structured logging
    use_json_logging: bool = Field(default=False, env="USE_JSON_LOGGING")
    log_requests: bool = Field(default=True, env="LOG_REQUESTS")
    log_responses: bool = Field(default=False, env="LOG_RESPONSES")  # May contain sensitive data
    
    # Performance monitoring
    log_slow_queries: bool = Field(default=True, env="LOG_SLOW_QUERIES")
    slow_query_threshold: float = Field(default=1.0, env="SLOW_QUERY_THRESHOLD")  # seconds
    
    model_config = {
        "env_prefix": "LOG_",
        "case_sensitive": False
    }


class CacheSettings(BaseSettings):
    """Cache configuration settings"""
    
    # Redis settings
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_ssl: bool = Field(default=False, env="REDIS_SSL")
    
    # Cache TTL settings (in seconds)
    default_cache_ttl: int = Field(default=300, env="DEFAULT_CACHE_TTL")  # 5 minutes
    user_cache_ttl: int = Field(default=600, env="USER_CACHE_TTL")  # 10 minutes
    session_cache_ttl: int = Field(default=1800, env="SESSION_CACHE_TTL")  # 30 minutes
    
    # Cache behavior
    cache_enabled: bool = Field(default=True, env="CACHE_ENABLED")
    cache_key_prefix: str = Field(default="insurecove:", env="CACHE_KEY_PREFIX")
    
    model_config = {
        "env_prefix": "CACHE_",
        "case_sensitive": False
    }


class MonitoringSettings(BaseSettings):
    """Monitoring and metrics configuration"""
    
    # Health check settings
    health_check_interval: int = Field(default=30, env="HEALTH_CHECK_INTERVAL")  # seconds
    health_check_timeout: int = Field(default=5, env="HEALTH_CHECK_TIMEOUT")  # seconds
    
    # Metrics settings
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")
    metrics_port: int = Field(default=8001, env="METRICS_PORT")
    
    # Alerting
    alert_email: Optional[str] = Field(default=None, env="ALERT_EMAIL")
    alert_webhook: Optional[str] = Field(default=None, env="ALERT_WEBHOOK")
    
    # Performance thresholds
    response_time_threshold: float = Field(default=2.0, env="RESPONSE_TIME_THRESHOLD")  # seconds
    error_rate_threshold: float = Field(default=0.05, env="ERROR_RATE_THRESHOLD")  # 5%
    
    model_config = {
        "env_prefix": "MONITORING_",
        "case_sensitive": False
    }


class Settings(BaseSettings):
    """Main application settings"""
    
    # Application metadata
    app_name: str = Field(default="InsureCove Auth Service", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    app_description: str = Field(
        default="InsureCove Authentication and Authorization Service",
        env="APP_DESCRIPTION"
    )
    
    # Environment
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    testing: bool = Field(default=False, env="TESTING")
    
    # Server settings
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    workers: int = Field(default=1, env="WORKERS")
    
    # API settings
    api_prefix: str = Field(default="/api/v1", env="API_PREFIX")
    docs_url: Optional[str] = Field(default="/docs", env="DOCS_URL")
    redoc_url: Optional[str] = Field(default="/redoc", env="REDOC_URL")
    openapi_url: Optional[str] = Field(default="/openapi.json", env="OPENAPI_URL")
    
    # Feature flags
    enable_registration: bool = Field(default=True, env="ENABLE_REGISTRATION")
    enable_email_verification: bool = Field(default=True, env="ENABLE_EMAIL_VERIFICATION")
    enable_password_reset: bool = Field(default=True, env="ENABLE_PASSWORD_RESET")
    enable_mfa: bool = Field(default=False, env="ENABLE_MFA")
    enable_social_login: bool = Field(default=False, env="ENABLE_SOCIAL_LOGIN")
    
    # External integrations
    mistral_api_key: Optional[str] = Field(default=None, env="MISTRAL_API_KEY")
    
    # Sub-configurations
    database: DatabaseSettings = DatabaseSettings()
    aws: AWSSettings = AWSSettings()
    jwt: JWTSettings = JWTSettings()
    security: SecuritySettings = SecuritySettings()
    logging: LoggingSettings = LoggingSettings()
    cache: CacheSettings = CacheSettings()
    monitoring: MonitoringSettings = MonitoringSettings()
    
    @field_validator('environment')
    @classmethod
    def validate_environment(cls, v):
        valid_envs = ['development', 'staging', 'production', 'testing']
        if v.lower() not in valid_envs:
            raise ValueError(f'Environment must be one of: {valid_envs}')
        return v.lower()
    
    @model_validator(mode='after')
    def validate_production_settings(self):
        """Validate production-specific requirements"""
        environment = getattr(self, 'environment', '').lower()
        debug = getattr(self, 'debug', False)
        
        if environment == 'production':
            if debug:
                raise ValueError('Debug mode cannot be enabled in production')
            
            # Check for required production settings
            required_prod_settings = [
                ('jwt', 'jwt_secret_key'),
                ('database', 'supabase_url'),
                ('aws', 'aws_region')
            ]
            
            for section, setting in required_prod_settings:
                section_obj = getattr(self, section, None)
                if not section_obj or not getattr(section_obj, setting, None):
                    raise ValueError(f'Production requires {section}.{setting} to be set')
        
        return self
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.environment == 'production'
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.environment == 'development'
    
    @property
    def is_testing(self) -> bool:
        """Check if running in testing environment"""
        return self.environment == 'testing' or self.testing
    
    def get_database_url(self) -> Optional[str]:
        """Get database URL for SQLAlchemy"""
        if self.database.supabase_url:
            # Convert Supabase URL to PostgreSQL URL if needed
            return self.database.supabase_url.replace('https://', 'postgresql://')
        return None
    
    def get_cors_origins(self) -> List[str]:
        """Get CORS origins based on environment"""
        if self.is_production:
            # Only allow configured origins in production
            return self.security.allowed_origins
        else:
            # Allow localhost in development
            dev_origins = [
                "http://localhost:3000",
                "http://localhost:8080",
                "http://localhost:5173",  # Vite default
                "http://127.0.0.1:3000",
                "http://127.0.0.1:8080"
            ]
            return list(set(dev_origins + self.security.allowed_origins))
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore"
    }


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached application settings
    
    Returns:
        Settings: Application configuration
    """
    return Settings()


def get_environment() -> str:
    """Get current environment"""
    return get_settings().environment


def is_production() -> bool:
    """Check if running in production"""
    return get_settings().is_production


def is_development() -> bool:
    """Check if running in development"""
    return get_settings().is_development


def is_testing() -> bool:
    """Check if running in testing mode"""
    return get_settings().is_testing


# Convenience aliases for commonly used settings
settings = get_settings()
db_settings = settings.database
aws_settings = settings.aws
jwt_settings = settings.jwt
security_settings = settings.security
logging_settings = settings.logging
cache_settings = settings.cache
monitoring_settings = settings.monitoring 