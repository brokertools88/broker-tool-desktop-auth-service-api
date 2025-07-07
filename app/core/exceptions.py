"""
InsureCove Authentication Service - Exception Handling

RFC 9457 Problem Details for HTTP APIs compliant exception handling:
- Standardized error responses
- Structured error handling
- HTTP status code mapping
- Error logging and tracking
- Comprehensive authentication and authorization exceptions
"""

from typing import Any, Dict, List, Optional, Union
from enum import Enum
import traceback
import logging
from datetime import datetime

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)


class ErrorType(str, Enum):
    """Error type enumeration"""
    
    # Authentication errors
    AUTHENTICATION_FAILED = "authentication_failed"
    INVALID_CREDENTIALS = "invalid_credentials"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_INVALID = "token_invalid"
    TOKEN_MISSING = "token_missing"
    REFRESH_TOKEN_INVALID = "refresh_token_invalid"
    
    # Authorization errors
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"
    ACCESS_DENIED = "access_denied"
    ROLE_REQUIRED = "role_required"
    RESOURCE_FORBIDDEN = "resource_forbidden"
    
    # User management errors
    USER_NOT_FOUND = "user_not_found"
    USER_ALREADY_EXISTS = "user_already_exists"
    USER_INACTIVE = "user_inactive"
    USER_LOCKED = "user_locked"
    EMAIL_NOT_VERIFIED = "email_not_verified"
    
    # Password errors
    WEAK_PASSWORD = "weak_password"
    PASSWORD_MISMATCH = "password_mismatch"
    PASSWORD_RECENTLY_USED = "password_recently_used"
    TOO_MANY_FAILED_ATTEMPTS = "too_many_failed_attempts"
    
    # Validation errors
    VALIDATION_ERROR = "validation_error"
    INVALID_INPUT = "invalid_input"
    MISSING_REQUIRED_FIELD = "missing_required_field"
    INVALID_EMAIL_FORMAT = "invalid_email_format"
    INVALID_PHONE_FORMAT = "invalid_phone_format"
    
    # Rate limiting errors
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    TOO_MANY_REQUESTS = "too_many_requests"
    
    # External service errors
    AWS_SERVICE_ERROR = "aws_service_error"
    SUPABASE_ERROR = "supabase_error"
    DATABASE_ERROR = "database_error"
    CACHE_ERROR = "cache_error"
    EMAIL_SERVICE_ERROR = "email_service_error"
    
    # Configuration errors
    CONFIGURATION_ERROR = "configuration_error"
    SECRET_NOT_FOUND = "secret_not_found"
    INVALID_CONFIGURATION = "invalid_configuration"
    
    # General errors
    INTERNAL_SERVER_ERROR = "internal_server_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    BAD_REQUEST = "bad_request"


class ErrorSeverity(str, Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProblemDetail(BaseModel):
    """RFC 9457 Problem Detail model"""
    
    type: str = Field(description="A URI reference that identifies the problem type")
    title: str = Field(description="A short, human-readable summary of the problem")
    status: int = Field(description="The HTTP status code")
    detail: Optional[str] = Field(default=None, description="A human-readable explanation")
    instance: Optional[str] = Field(default=None, description="A URI reference that identifies the problem occurrence")
    
    # Extension fields
    error_code: Optional[str] = Field(default=None, description="Application-specific error code")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    severity: ErrorSeverity = Field(default=ErrorSeverity.MEDIUM)
    errors: Optional[List[Dict[str, Any]]] = Field(default=None, description="Detailed validation errors")
    trace_id: Optional[str] = Field(default=None, description="Request trace ID for debugging")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "type": "https://insurecove.com/problems/authentication-failed",
                "title": "Authentication Failed",
                "status": 401,
                "detail": "The provided credentials are invalid",
                "error_code": "AUTH001",
                "timestamp": "2025-07-07T14:30:00Z",
                "severity": "medium"
            }
        }
    }


class BaseInsureCoveException(Exception):
    """Base exception for all InsureCove authentication service errors"""
    
    def __init__(
        self,
        message: str,
        error_type: ErrorType,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code: Optional[str] = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        details: Optional[Dict[str, Any]] = None,
        errors: Optional[List[Dict[str, Any]]] = None
    ):
        self.message = message
        self.error_type = error_type
        self.status_code = status_code
        self.error_code = error_code
        self.severity = severity
        self.details = details or {}
        self.errors = errors
        self.timestamp = datetime.utcnow()
        
        super().__init__(message)
    
    def to_problem_detail(self, instance: Optional[str] = None, trace_id: Optional[str] = None) -> ProblemDetail:
        """Convert exception to RFC 9457 Problem Detail"""
        return ProblemDetail(
            type=f"https://insurecove.com/problems/{self.error_type.value.replace('_', '-')}",
            title=self.error_type.value.replace('_', ' ').title(),
            status=self.status_code,
            detail=self.message,
            instance=instance,
            error_code=self.error_code,
            timestamp=self.timestamp.isoformat(),
            severity=self.severity,
            errors=self.errors,
            trace_id=trace_id
        )


# Authentication Exceptions

class AuthenticationException(BaseInsureCoveException):
    """Base authentication exception"""
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(
            message=message,
            error_type=ErrorType.AUTHENTICATION_FAILED,
            status_code=status.HTTP_401_UNAUTHORIZED,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )


class InvalidCredentialsException(AuthenticationException):
    """Invalid username/password exception"""
    
    def __init__(self, message: str = "Invalid credentials provided"):
        super().__init__(
            message=message,
            error_type=ErrorType.INVALID_CREDENTIALS,
            error_code="AUTH001"
        )


class TokenExpiredException(AuthenticationException):
    """JWT token expired exception"""
    
    def __init__(self, message: str = "Token has expired"):
        super().__init__(
            message=message,
            error_type=ErrorType.TOKEN_EXPIRED,
            error_code="AUTH002"
        )


class TokenInvalidException(AuthenticationException):
    """Invalid JWT token exception"""
    
    def __init__(self, message: str = "Token is invalid"):
        super().__init__(
            message=message,
            error_type=ErrorType.TOKEN_INVALID,
            error_code="AUTH003"
        )


class TokenMissingException(AuthenticationException):
    """Missing JWT token exception"""
    
    def __init__(self, message: str = "Authentication token is required"):
        super().__init__(
            message=message,
            error_type=ErrorType.TOKEN_MISSING,
            error_code="AUTH004"
        )


class RefreshTokenInvalidException(AuthenticationException):
    """Invalid refresh token exception"""
    
    def __init__(self, message: str = "Refresh token is invalid or expired"):
        super().__init__(
            message=message,
            error_type=ErrorType.REFRESH_TOKEN_INVALID,
            error_code="AUTH005"
        )


# Authorization Exceptions

class AuthorizationException(BaseInsureCoveException):
    """Base authorization exception"""
    
    def __init__(self, message: str = "Access denied", **kwargs):
        super().__init__(
            message=message,
            error_type=ErrorType.ACCESS_DENIED,
            status_code=status.HTTP_403_FORBIDDEN,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )


class InsufficientPermissionsException(AuthorizationException):
    """Insufficient permissions exception"""
    
    def __init__(self, required_permission: str, message: str = None):
        if not message:
            message = f"Insufficient permissions. Required: {required_permission}"
        super().__init__(
            message=message,
            error_type=ErrorType.INSUFFICIENT_PERMISSIONS,
            error_code="AUTH101",
            details={"required_permission": required_permission}
        )


class RoleRequiredException(AuthorizationException):
    """Role required exception"""
    
    def __init__(self, required_role: str, user_role: str = None):
        message = f"Role '{required_role}' is required for this action"
        super().__init__(
            message=message,
            error_type=ErrorType.ROLE_REQUIRED,
            error_code="AUTH102",
            details={"required_role": required_role, "user_role": user_role}
        )


class ResourceForbiddenException(AuthorizationException):
    """Resource access forbidden exception"""
    
    def __init__(self, resource_id: str, action: str = "access"):
        message = f"Access to resource '{resource_id}' is forbidden"
        super().__init__(
            message=message,
            error_type=ErrorType.RESOURCE_FORBIDDEN,
            error_code="AUTH103",
            details={"resource_id": resource_id, "action": action}
        )


# User Management Exceptions

class UserException(BaseInsureCoveException):
    """Base user management exception"""
    
    def __init__(self, message: str, error_type: ErrorType, **kwargs):
        super().__init__(
            message=message,
            error_type=error_type,
            status_code=status.HTTP_400_BAD_REQUEST,
            **kwargs
        )


class UserNotFoundException(UserException):
    """User not found exception"""
    
    def __init__(self, user_id: str = None, email: str = None):
        identifier = user_id or email or "unknown"
        message = f"User '{identifier}' not found"
        super().__init__(
            message=message,
            error_type=ErrorType.USER_NOT_FOUND,
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="USER001",
            details={"user_id": user_id, "email": email}
        )


class UserAlreadyExistsException(UserException):
    """User already exists exception"""
    
    def __init__(self, email: str):
        message = f"User with email '{email}' already exists"
        super().__init__(
            message=message,
            error_type=ErrorType.USER_ALREADY_EXISTS,
            status_code=status.HTTP_409_CONFLICT,
            error_code="USER002",
            details={"email": email}
        )


class UserInactiveException(UserException):
    """User account inactive exception"""
    
    def __init__(self, user_id: str):
        message = "User account is inactive"
        super().__init__(
            message=message,
            error_type=ErrorType.USER_INACTIVE,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="USER003",
            details={"user_id": user_id}
        )


class UserLockedException(UserException):
    """User account locked exception"""
    
    def __init__(self, user_id: str, unlock_time: Optional[datetime] = None):
        message = "User account is locked due to too many failed login attempts"
        super().__init__(
            message=message,
            error_type=ErrorType.USER_LOCKED,
            status_code=status.HTTP_423_LOCKED,
            error_code="USER004",
            details={
                "user_id": user_id,
                "unlock_time": unlock_time.isoformat() if unlock_time else None
            }
        )


class EmailNotVerifiedException(UserException):
    """Email not verified exception"""
    
    def __init__(self, email: str):
        message = f"Email address '{email}' is not verified"
        super().__init__(
            message=message,
            error_type=ErrorType.EMAIL_NOT_VERIFIED,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="USER005",
            details={"email": email}
        )


# Password Exceptions

class PasswordException(BaseInsureCoveException):
    """Base password exception"""
    
    def __init__(self, message: str, error_type: ErrorType, **kwargs):
        super().__init__(
            message=message,
            error_type=error_type,
            status_code=status.HTTP_400_BAD_REQUEST,
            **kwargs
        )


class WeakPasswordException(PasswordException):
    """Weak password exception"""
    
    def __init__(self, requirements: List[str]):
        message = "Password does not meet security requirements"
        super().__init__(
            message=message,
            error_type=ErrorType.WEAK_PASSWORD,
            error_code="PWD001",
            details={"requirements": requirements}
        )


class PasswordMismatchException(PasswordException):
    """Password confirmation mismatch exception"""
    
    def __init__(self):
        super().__init__(
            message="Password and confirmation do not match",
            error_type=ErrorType.PASSWORD_MISMATCH,
            error_code="PWD002"
        )


class TooManyFailedAttemptsException(PasswordException):
    """Too many failed login attempts exception"""
    
    def __init__(self, attempts: int, lockout_time: Optional[datetime] = None):
        message = f"Too many failed login attempts ({attempts}). Account temporarily locked."
        super().__init__(
            message=message,
            error_type=ErrorType.TOO_MANY_FAILED_ATTEMPTS,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="PWD003",
            details={
                "failed_attempts": attempts,
                "lockout_time": lockout_time.isoformat() if lockout_time else None
            }
        )


# Validation Exceptions

class ValidationException(BaseInsureCoveException):
    """Base validation exception"""
    
    def __init__(self, message: str, errors: List[Dict[str, Any]] = None, **kwargs):
        super().__init__(
            message=message,
            error_type=ErrorType.VALIDATION_ERROR,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            errors=errors,
            **kwargs
        )


class InvalidInputException(ValidationException):
    """Invalid input exception"""
    
    def __init__(self, field: str, value: Any, reason: str = None):
        message = f"Invalid value for field '{field}'"
        if reason:
            message += f": {reason}"
        
        errors = [{
            "field": field,
            "value": str(value),
            "message": reason or "Invalid value"
        }]
        
        super().__init__(
            message=message,
            error_code="VAL001",
            errors=errors
        )


class InvalidEmailFormatException(ValidationException):
    """Invalid email format exception"""
    
    def __init__(self, email: str):
        super().__init__(
            message=f"Invalid email format: {email}",
            error_type=ErrorType.INVALID_EMAIL_FORMAT,
            error_code="VAL002",
            errors=[{"field": "email", "value": email, "message": "Invalid email format"}]
        )


# Rate Limiting Exceptions

class RateLimitException(BaseInsureCoveException):
    """Rate limit exceeded exception"""
    
    def __init__(self, limit: int, window: int, retry_after: int = None):
        message = f"Rate limit exceeded. Maximum {limit} requests per {window} seconds"
        super().__init__(
            message=message,
            error_type=ErrorType.RATE_LIMIT_EXCEEDED,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="RATE001",
            details={
                "limit": limit,
                "window": window,
                "retry_after": retry_after
            }
        )


# External Service Exceptions

class ExternalServiceException(BaseInsureCoveException):
    """Base external service exception"""
    
    def __init__(self, service: str, message: str, error_type: ErrorType, **kwargs):
        super().__init__(
            message=f"{service}: {message}",
            error_type=error_type,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            severity=ErrorSeverity.HIGH,
            details={"service": service},
            **kwargs
        )


class AWSServiceException(ExternalServiceException):
    """AWS service exception"""
    
    def __init__(self, message: str, service: str = "AWS", error_code: str = None):
        super().__init__(
            service=service,
            message=message,
            error_type=ErrorType.AWS_SERVICE_ERROR,
            error_code=error_code or "AWS001"
        )


class SupabaseException(ExternalServiceException):
    """Supabase service exception"""
    
    def __init__(self, message: str, operation: str = None):
        super().__init__(
            service="Supabase",
            message=message,
            error_type=ErrorType.SUPABASE_ERROR,
            error_code="SUP001",
            details={"operation": operation}
        )


class DatabaseException(ExternalServiceException):
    """Database service exception"""
    
    def __init__(self, message: str, query: str = None):
        super().__init__(
            service="Database",
            message=message,
            error_type=ErrorType.DATABASE_ERROR,
            error_code="DB001",
            details={"query": query}
        )


class CacheException(ExternalServiceException):
    """Cache service exception"""
    
    def __init__(self, message: str, operation: str = None):
        super().__init__(
            service="Cache",
            message=message,
            error_type=ErrorType.CACHE_ERROR,
            error_code="CACHE001",
            details={"operation": operation}
        )


# Configuration Exceptions

class ConfigurationException(BaseInsureCoveException):
    """Configuration error exception"""
    
    def __init__(self, message: str, config_key: str = None):
        super().__init__(
            message=message,
            error_type=ErrorType.CONFIGURATION_ERROR,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            severity=ErrorSeverity.CRITICAL,
            error_code="CFG001",
            details={"config_key": config_key}
        )


class SecretNotFoundException(ConfigurationException):
    """Secret not found exception"""
    
    def __init__(self, secret_name: str):
        super().__init__(
            message=f"Required secret '{secret_name}' not found",
            error_type=ErrorType.SECRET_NOT_FOUND,
            error_code="CFG002",
            config_key=secret_name
        )


# General HTTP Exceptions

class NotFoundError(BaseInsureCoveException):
    """Resource not found exception"""
    
    def __init__(self, resource: str, identifier: str = None):
        message = f"{resource} not found"
        if identifier:
            message += f": {identifier}"
        
        super().__init__(
            message=message,
            error_type=ErrorType.NOT_FOUND,
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="HTTP404"
        )


class ConflictError(BaseInsureCoveException):
    """Resource conflict exception"""
    
    def __init__(self, message: str, resource: str = None):
        super().__init__(
            message=message,
            error_type=ErrorType.CONFLICT,
            status_code=status.HTTP_409_CONFLICT,
            error_code="HTTP409",
            details={"resource": resource}
        )


class BadRequestError(BaseInsureCoveException):
    """Bad request exception"""
    
    def __init__(self, message: str):
        super().__init__(
            message=message,
            error_type=ErrorType.BAD_REQUEST,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="HTTP400"
        )


# Exception Handler Functions

async def insurecove_exception_handler(request: Request, exc: BaseInsureCoveException) -> JSONResponse:
    """
    Handle InsureCove custom exceptions
    
    Args:
        request: FastAPI request object
        exc: The exception that was raised
        
    Returns:
        JSONResponse with RFC 9457 Problem Detail format
    """
    # Extract trace ID from request if available
    trace_id = getattr(request.state, 'trace_id', None)
    
    # Create problem detail
    problem_detail = exc.to_problem_detail(
        instance=str(request.url),
        trace_id=trace_id
    )
    
    # Log the exception
    logger.error(
        f"Exception occurred: {exc.__class__.__name__}",
        extra={
            "error_type": exc.error_type.value,
            "error_code": exc.error_code,
            "status_code": exc.status_code,
            "severity": exc.severity.value,
            "trace_id": trace_id,
            "url": str(request.url),
            "method": request.method,
            "details": exc.details
        },
        exc_info=exc.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=problem_detail.model_dump(exclude_none=True),
        headers={
            "Content-Type": "application/problem+json",
            "X-Error-Code": exc.error_code or "",
            "X-Trace-ID": trace_id or ""
        }
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Handle FastAPI HTTP exceptions
    
    Args:
        request: FastAPI request object
        exc: The HTTP exception that was raised
        
    Returns:
        JSONResponse with RFC 9457 Problem Detail format
    """
    trace_id = getattr(request.state, 'trace_id', None)
    
    problem_detail = ProblemDetail(
        type=f"https://insurecove.com/problems/http-{exc.status_code}",
        title=exc.detail,
        status=exc.status_code,
        detail=exc.detail,
        instance=str(request.url),
        trace_id=trace_id
    )
    
    logger.warning(
        f"HTTP Exception: {exc.status_code}",
        extra={
            "status_code": exc.status_code,
            "detail": exc.detail,
            "trace_id": trace_id,
            "url": str(request.url),
            "method": request.method
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=problem_detail.model_dump(exclude_none=True),
        headers={
            "Content-Type": "application/problem+json",
            "X-Trace-ID": trace_id or ""
        }
    )


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle Pydantic validation exceptions
    
    Args:
        request: FastAPI request object
        exc: The validation exception that was raised
        
    Returns:
        JSONResponse with RFC 9457 Problem Detail format
    """
    trace_id = getattr(request.state, 'trace_id', None)
    
    # Extract validation errors
    errors = []
    if hasattr(exc, 'errors'):
        for error in exc.errors():
            errors.append({
                "field": ".".join(str(loc) for loc in error['loc']),
                "message": error['msg'],
                "type": error['type'],
                "input": error.get('input')
            })
    
    problem_detail = ProblemDetail(
        type="https://insurecove.com/problems/validation-error",
        title="Validation Error",
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="One or more fields contain invalid values",
        instance=str(request.url),
        error_code="VAL000",
        errors=errors,
        trace_id=trace_id
    )
    
    logger.warning(
        "Validation exception occurred",
        extra={
            "errors": errors,
            "trace_id": trace_id,
            "url": str(request.url),
            "method": request.method
        }
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=problem_detail.model_dump(exclude_none=True),
        headers={
            "Content-Type": "application/problem+json",
            "X-Trace-ID": trace_id or ""
        }
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle unexpected exceptions
    
    Args:
        request: FastAPI request object
        exc: The exception that was raised
        
    Returns:
        JSONResponse with RFC 9457 Problem Detail format
    """
    trace_id = getattr(request.state, 'trace_id', None)
    
    problem_detail = ProblemDetail(
        type="https://insurecove.com/problems/internal-server-error",
        title="Internal Server Error",
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="An unexpected error occurred",
        instance=str(request.url),
        error_code="INT001",
        trace_id=trace_id,
        severity=ErrorSeverity.CRITICAL
    )
    
    logger.critical(
        "Unhandled exception occurred",
        extra={
            "exception_type": exc.__class__.__name__,
            "exception_message": str(exc),
            "trace_id": trace_id,
            "url": str(request.url),
            "method": request.method,
            "traceback": traceback.format_exc()
        },
        exc_info=True
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=problem_detail.model_dump(exclude_none=True),
        headers={
            "Content-Type": "application/problem+json",
            "X-Trace-ID": trace_id or ""
        }
    ) 