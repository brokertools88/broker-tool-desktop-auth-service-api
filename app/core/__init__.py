"""
InsureCove Authentication Service - Core Package

Core utilities and configurations for the authentication service:
- Configuration management
- Exception handling
- Security utilities
- Logging configuration
"""

from .config import (
    get_settings,
    settings,
    db_settings,
    aws_settings,
    jwt_settings,
    security_settings,
    logging_settings,
    cache_settings,
    monitoring_settings,
    is_production,
    is_development,
    is_testing
)

from .exceptions import (
    BaseInsureCoveException,
    AuthenticationException,
    AuthorizationException,
    InvalidCredentialsException,
    TokenExpiredException,
    TokenInvalidException,
    TokenMissingException,
    RefreshTokenInvalidException,
    InsufficientPermissionsException,
    RoleRequiredException,
    ResourceForbiddenException,
    UserNotFoundException,
    UserAlreadyExistsException,
    UserInactiveException,
    UserLockedException,
    EmailNotVerifiedException,
    WeakPasswordException,
    PasswordMismatchException,
    TooManyFailedAttemptsException,
    ValidationException,
    InvalidInputException,
    InvalidEmailFormatException,
    RateLimitException,
    AWSServiceException,
    SupabaseException,
    DatabaseException,
    CacheException,
    ConfigurationException,
    SecretNotFoundException,
    NotFoundError,
    ConflictError,
    BadRequestError,
    insurecove_exception_handler,
    http_exception_handler,
    validation_exception_handler,
    general_exception_handler
)

from .security import (
    PasswordManager,
    JWTManager,
    SecurityMiddleware,
    AuthenticationDependency,
    PermissionChecker,
    jwt_manager,
    auth_dependency,
    password_manager,
    generate_secure_token,
    hash_string,
    constant_time_compare
)

from .logging_config import (
    setup_logging,
    get_logger,
    SecurityEventLogger,
    PerformanceLogger,
    RequestLoggingMiddleware,
    security_logger,
    performance_logger,
    api_logger,
    auth_logger
)

__all__ = [
    # Config
    "get_settings",
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
    "is_testing",
    
    # Exceptions
    "BaseInsureCoveException",
    "AuthenticationException",
    "AuthorizationException",
    "InvalidCredentialsException",
    "TokenExpiredException",
    "TokenInvalidException",
    "TokenMissingException",
    "RefreshTokenInvalidException",
    "InsufficientPermissionsException",
    "RoleRequiredException",
    "ResourceForbiddenException",
    "UserNotFoundException",
    "UserAlreadyExistsException",
    "UserInactiveException",
    "UserLockedException",
    "EmailNotVerifiedException",
    "WeakPasswordException",
    "PasswordMismatchException",
    "TooManyFailedAttemptsException",
    "ValidationException",
    "InvalidInputException",
    "InvalidEmailFormatException",
    "RateLimitException",
    "AWSServiceException",
    "SupabaseException",
    "DatabaseException",
    "CacheException",
    "ConfigurationException",
    "SecretNotFoundException",
    "NotFoundError",
    "ConflictError",
    "BadRequestError",
    "insurecove_exception_handler",
    "http_exception_handler", 
    "validation_exception_handler",
    "general_exception_handler",
    
    # Security
    "PasswordManager",
    "JWTManager",
    "SecurityMiddleware",
    "AuthenticationDependency",
    "PermissionChecker",
    "jwt_manager",
    "auth_dependency",
    "password_manager",
    "generate_secure_token",
    "hash_string",
    "constant_time_compare",
    
    # Logging
    "setup_logging",
    "get_logger",
    "SecurityEventLogger",
    "PerformanceLogger", 
    "RequestLoggingMiddleware",
    "security_logger",
    "performance_logger",
    "api_logger",
    "auth_logger"
] 