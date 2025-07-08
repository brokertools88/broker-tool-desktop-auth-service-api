"""
InsureCove Authentication Service - Logging Configuration

Comprehensive logging setup with:
- Structured logging with JSON support
- Request/response logging
- Performance monitoring
- Error tracking
- Security event logging
"""

import logging
import logging.handlers
import json
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .config import get_settings

settings = get_settings()


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields directly from record attributes
        # Skip standard LogRecord attributes and add custom ones
        
        # Add common extra fields
        for attr in ['trace_id', 'user_id', 'user_email', 'request_id', 'ip_address', 'user_agent']:
            if hasattr(record, attr):
                log_data[attr] = getattr(record, attr)
        
        return json.dumps(log_data, default=str)


class SecurityEventLogger:
    """Logger for security events"""
    
    def __init__(self):
        self.logger = logging.getLogger("security")
    
    def log_login_attempt(
        self,
        email: str,
        success: bool,
        ip_address: str,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log login attempt"""
        event_data = {
            "event_type": "login_attempt",
            "email": email,
            "success": success,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details or {}
        }
        
        if success:
            self.logger.info("Login successful", extra=event_data)
        else:
            self.logger.warning("Login failed", extra=event_data)
    
    def log_token_creation(self, user_id: str, token_type: str, ip_address: str):
        """Log token creation"""
        self.logger.info(
            "Token created",
            extra={
                "event_type": "token_creation",
                "user_id": user_id,
                "token_type": token_type,
                "ip_address": ip_address
            }
        )
    
    def log_token_validation(
        self,
        success: bool,
        token_type: str,
        ip_address: str,
        error: Optional[str] = None
    ):
        """Log token validation"""
        event_data = {
            "event_type": "token_validation",
            "success": success,
            "token_type": token_type,
            "ip_address": ip_address
        }
        
        if error:
            event_data["error"] = error
        
        if success:
            self.logger.info("Token validation successful", extra=event_data)
        else:
            self.logger.warning("Token validation failed", extra=event_data)
    
    def log_permission_check(
        self,
        user_id: str,
        permission: str,
        resource: str,
        success: bool,
        ip_address: str
    ):
        """Log permission check"""
        event_data = {
            "event_type": "permission_check",
            "user_id": user_id,
            "permission": permission,
            "resource": resource,
            "success": success,
            "ip_address": ip_address
        }
        
        if success:
            self.logger.info("Permission granted", extra=event_data)
        else:
            self.logger.warning("Permission denied", extra=event_data)
    
    def log_security_violation(
        self,
        violation_type: str,
        details: Dict[str, Any],
        ip_address: str,
        user_id: Optional[str] = None
    ):
        """Log security violation"""
        self.logger.error(
            f"Security violation: {violation_type}",
            extra={
                "event_type": "security_violation",
                "violation_type": violation_type,
                "user_id": user_id,
                "ip_address": ip_address,
                "details": details
            }
        )
    
    def log_security_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: str = "unknown",
        user_agent: Optional[str] = None
    ):
        """Log a general security event"""
        event_data = {
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details or {}
        }
        
        self.logger.info(f"Security event: {event_type}", extra=event_data)


class PerformanceLogger:
    """Logger for performance metrics"""
    
    def __init__(self):
        self.logger = logging.getLogger("performance")
    
    def log_request_duration(
        self,
        method: str,
        path: str,
        duration: float,
        status_code: int,
        user_id: Optional[str] = None
    ):
        """Log request duration"""
        self.logger.info(
            "Request completed",
            extra={
                "event_type": "request_duration",
                "method": method,
                "path": path,
                "duration_ms": round(duration * 1000, 2),
                "status_code": status_code,
                "user_id": user_id
            }
        )
    
    def log_slow_query(
        self,
        query: str,
        duration: float,
        parameters: Optional[Dict[str, Any]] = None
    ):
        """Log slow database query"""
        if duration >= settings.logging.slow_query_threshold:
            self.logger.warning(
                "Slow query detected",
                extra={
                    "event_type": "slow_query",
                    "query": query[:500],  # Truncate long queries
                    "duration_seconds": round(duration, 3),
                    "parameters": parameters
                }
            )


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging HTTP requests and responses"""
    
    def __init__(self, app, logger_name: str = "api"):
        super().__init__(app)
        self.logger = logging.getLogger(logger_name)
        self.performance_logger = PerformanceLogger()
    
    async def dispatch(self, request: Request, call_next):
        """Log request and response"""
        start_time = datetime.utcnow()
        
        # Generate request ID
        request_id = self._generate_request_id()
        request.state.request_id = request_id
        
        # Extract client info
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        
        # Log request if enabled
        if settings.logging.log_requests:
            self.logger.info(
                "Request started",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "url": str(request.url),
                    "path": request.url.path,
                    "query_params": dict(request.query_params),
                    "headers": dict(request.headers) if settings.is_development else {},
                    "ip_address": client_ip,
                    "user_agent": user_agent
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        # Log response if enabled
        if settings.logging.log_responses and settings.is_development:
            self.logger.info(
                "Request completed",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": round(duration * 1000, 2),
                    "response_headers": dict(response.headers),
                    "ip_address": client_ip,
                    "user_id": getattr(request.state, 'user_id', None)
                }
            )
        
        # Log performance metrics
        self.performance_logger.log_request_duration(
            method=request.method,
            path=request.url.path,
            duration=duration,
            status_code=response.status_code,
            user_id=getattr(request.state, 'user_id', None) or "anonymous"
        )
        
        # Add response headers
        response.headers["X-Request-ID"] = request_id
        
        return response
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        import uuid
        return str(uuid.uuid4())
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address"""
        # Check for forwarded headers (behind proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct client
        if request.client:
            return request.client.host
        
        return "unknown"


def setup_logging():
    """Setup application logging configuration"""
    
    # Remove existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Set root log level
    try:
        log_level = settings.logging.log_level.upper()
    except:
        log_level = "INFO"
    
    root_logger.setLevel(getattr(logging, log_level))
    
    # Create formatters
    try:
        use_json = settings.logging.use_json_logging
    except:
        use_json = True
        
    if use_json:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if configured)
    try:
        log_file = settings.logging.log_file
        if log_file:
            log_file_path = Path(log_file)
            log_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                filename=log_file_path,
                maxBytes=settings.logging.log_max_bytes,
                backupCount=settings.logging.log_backup_count
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
    except:
        # If file logging fails, just continue with console logging
        pass
    
    # Configure specific loggers
    loggers_config = {
        # Reduce noise from external libraries
        "uvicorn.access": logging.WARNING,
        "uvicorn.error": logging.INFO,
        "fastapi": logging.INFO,
        "httpx": logging.WARNING,
        "boto3": logging.WARNING,
        "botocore": logging.WARNING,
        
        # Application loggers
        "security": logging.INFO,
        "performance": logging.INFO,
        "api": logging.INFO,
        "auth": logging.INFO,
    }
    
    for logger_name, level in loggers_config.items():
        logger = logging.getLogger(logger_name)
        logger.setLevel(level)
    
    # Setup structured logging for application
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    return logging.getLogger(name)


# Global logger instances
security_logger = SecurityEventLogger()
performance_logger = PerformanceLogger()
api_logger = get_logger("api")
auth_logger = get_logger("auth")
