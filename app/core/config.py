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
from pydantic import BaseModel, Field, field_validator


class DatabaseSettings(BaseModel):
    """Database configuration settings"""
    
    # Supabase Configuration
    supabase_url: Optional[str] = None
    supabase_anon_key: Optional[str] = None
    supabase_service_key: Optional[str] = None
    database_password: Optional[str] = None
    
    # Connection Pool Settings
    max_connections: int = 10
    connection_timeout: int = 30


class AWSSettings(BaseModel):
    """AWS service configuration"""
    
    # AWS Credentials
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "ap-east-1"
    
    # Proxy Configuration
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    
    # Secrets Manager Configuration
    secret_prefix: str = "insurecove"
    secret_cache_ttl: int = 300  # 5 minutes
    
    # S3 Configuration
    s3_bucket_name: Optional[str] = None
    max_file_size_mb: int = 10


class JWTSettings(BaseModel):
    """JWT token configuration"""
    
    # JWT Configuration
    jwt_secret_key: Optional[str] = None
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "insurecove-auth"
    jwt_audience: str = "insurecove-api"
    
    # Token Expiration
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    service_token_expire_hours: int = 24
    
    # Token Settings
    allow_refresh_token_reuse: bool = False
    require_aud_claim: bool = True


class SecuritySettings(BaseModel):
    """Security configuration"""
    
    # Password Requirements
    min_password_length: int = 8
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    
    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds
    
    # Session Management
    session_timeout_minutes: int = 60
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    
    # CORS Settings
    allowed_origins: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    allowed_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers: List[str] = ["*"]
    
    # Encryption
    encryption_key: Optional[str] = None
    encryption_salt: Optional[str] = None
    
    @field_validator('allowed_origins')
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v
    
    @field_validator('allowed_methods')
    @classmethod
    def parse_cors_methods(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v
    
    @field_validator('allowed_headers')
    @classmethod
    def parse_cors_headers(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v


class LoggingSettings(BaseModel):
    """Logging configuration"""
    
    log_level: str = "INFO"
    log_format: str = "json"
    log_requests: bool = True
    log_responses: bool = False
    log_sql_queries: bool = False
    
    # File Logging
    log_file_enabled: bool = False
    log_file_path: str = "logs/auth-service.log"
    log_file_max_size: str = "10MB"
    log_file_backup_count: int = 5
    
    # Missing attributes for compatibility
    log_file: Optional[str] = "logs/auth-service.log"
    log_max_bytes: int = 10485760  # 10MB
    log_backup_count: int = 5
    slow_query_threshold: float = 1.0  # seconds
    use_json_logging: bool = True
    
    # External Logging
    sentry_dsn: Optional[str] = None
    datadog_enabled: bool = False
    cloudwatch_enabled: bool = False


class CacheSettings(BaseModel):
    """Cache configuration"""
    
    redis_url: str = "redis://localhost:6379"
    redis_password: Optional[str] = None
    redis_db: int = 0
    redis_max_connections: int = 20
    redis_connection_timeout: int = 5
    
    # Cache Expiration (seconds)
    default_cache_ttl: int = 300  # 5 minutes
    user_cache_ttl: int = 900     # 15 minutes
    session_cache_ttl: int = 1800  # 30 minutes
    
    # Cache Prefixes
    user_cache_prefix: str = "user:"
    session_cache_prefix: str = "session:"
    rate_limit_cache_prefix: str = "rate_limit:"


class MonitoringSettings(BaseModel):
    """Monitoring and metrics configuration"""
    
    enable_metrics: bool = True
    metrics_endpoint: str = "/metrics"
    health_endpoint: str = "/health"
    
    # Prometheus Configuration
    prometheus_enabled: bool = True
    prometheus_endpoint: str = "/metrics/prometheus"
    
    # Health Check Configuration
    health_check_timeout: int = 5
    health_check_interval: int = 30
    
    # Performance Monitoring
    enable_request_timing: bool = True
    enable_db_monitoring: bool = True
    enable_cache_monitoring: bool = True


class Settings(BaseModel):
    """Main application settings"""
    
    # Application Info
    app_name: str = "InsureCove Auth Service"
    app_description: str = "Production-ready authentication service for InsureCove platform"
    app_version: str = "1.0.0"
    
    # Environment
    environment: str = "development"
    debug: bool = False
    
    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1
    
    # API Configuration
    api_prefix: str = "/api/v1"
    docs_url: str = "/docs"
    redoc_url: str = "/redoc"
    openapi_url: str = "/openapi.json"
    
    # Feature Flags
    enable_registration: bool = True
    enable_email_verification: bool = True
    enable_password_reset: bool = True
    enable_mfa: bool = False
    enable_social_login: bool = False
    
    # Component Settings
    database: DatabaseSettings = DatabaseSettings()
    aws: AWSSettings = AWSSettings()
    jwt: JWTSettings = JWTSettings()
    security: SecuritySettings = SecuritySettings()
    logging: LoggingSettings = LoggingSettings()
    cache: CacheSettings = CacheSettings()
    monitoring: MonitoringSettings = MonitoringSettings()
    
    def __init__(self, **kwargs):
        # Load from environment variables
        env_values = {}
        
        # Simple environment variable mapping
        env_mapping = {
            'supabase_url': 'SUPABASE_URL',
            'supabase_anon_key': 'SUPABASE_ANON_KEY', 
            'supabase_service_key': 'SUPABASE_SERVICE_KEY',
            'jwt_secret_key': 'JWT_SECRET_KEY',
            'environment': 'ENVIRONMENT',
            'debug': 'DEBUG',
            'host': 'HOST',
            'port': 'PORT'
        }
        
        for field, env_var in env_mapping.items():
            if env_var in os.environ:
                value = os.environ[env_var]
                # Type conversion
                if field in ['debug']:
                    value = value.lower() in ('true', '1', 'yes')
                elif field in ['port']:
                    value = int(value)
                env_values[field] = value
        
        # Merge with kwargs
        final_values = {**env_values, **kwargs}
        super().__init__(**final_values)
    
    # Computed Properties
    @property
    def is_development(self) -> bool:
        return self.environment.lower() == "development"
    
    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"
    
    @property
    def is_testing(self) -> bool:
        return self.environment.lower() == "testing"
    
    @property
    def database_url(self) -> Optional[str]:
        """Get complete database URL"""
        if self.database.supabase_url:
            return self.database.supabase_url
        return None
    
    def get_cors_origins(self) -> List[str]:
        """Get CORS allowed origins"""
        return self.security.allowed_origins


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance
    
    Returns:
        Settings: Application settings
    """
    return Settings()


# Create settings instances for easy access
settings = get_settings()
db_settings = settings.database
aws_settings = settings.aws
jwt_settings = settings.jwt
security_settings = settings.security
logging_settings = settings.logging
cache_settings = settings.cache
monitoring_settings = settings.monitoring

# Convenience properties
is_production = settings.is_production
is_development = settings.is_development
is_testing = settings.is_testing


# Environment variable validation
def validate_environment():
    """Validate required environment variables"""
    settings = get_settings()
    
    errors = []
    
    if settings.is_production:
        # Production-specific validations
        if not settings.database.supabase_url:
            errors.append("SUPABASE_URL is required in production")
        
        if not settings.database.supabase_service_key:
            errors.append("SUPABASE_SERVICE_KEY is required in production")
        
        if not settings.jwt.jwt_secret_key:
            errors.append("JWT_SECRET_KEY is required in production")
    
    if errors:
        raise ValueError(f"Environment validation failed: {', '.join(errors)}")
    
    return True


# Export commonly used settings
__all__ = [
    "Settings",
    "DatabaseSettings", 
    "AWSSettings",
    "JWTSettings",
    "SecuritySettings",
    "LoggingSettings",
    "CacheSettings",
    "MonitoringSettings",
    "get_settings",
    "validate_environment",
    "settings",
    "db_settings",
    "aws_settings", 
    "jwt_settings",
    "security_settings",
    "logging_settings",
    "cache_settings",
    "monitoring_settings",
    "is_production",
    "is_development",
    "is_testing"
]
