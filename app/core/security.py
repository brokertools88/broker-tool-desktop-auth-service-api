"""
InsureCove Authentication Service - Security Utilities

Comprehensive security utilities including:
- Password hashing and verification
- JWT token creation and validation
- Rate limiting helpers
- Security middleware
- CORS configuration
"""

import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union, List
from functools import wraps

import jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Request, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware

# Optional imports for rate limiting
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False
    Limiter = None
    RateLimitExceeded = None
    def get_remote_address(request):
        return request.client.host if request.client else "unknown"

from .config import get_settings
from .exceptions import (
    TokenExpiredException,
    TokenInvalidException,
    TokenMissingException,
    RateLimitException,
    AuthenticationException
)

# Initialize settings
settings = get_settings()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT security scheme
security = HTTPBearer(auto_error=False)

# Rate limiter (if available)
if RATE_LIMITING_AVAILABLE and Limiter:
    limiter = Limiter(key_func=get_remote_address)
else:
    limiter = None


class PasswordManager:
    """Password hashing and verification utilities"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt
        
        Args:
            password: Plain text password
            
        Returns:
            str: Hashed password
        """
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password
            
        Returns:
            bool: True if password is correct
        """
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def generate_password(length: int = 12) -> str:
        """
        Generate a secure random password
        
        Args:
            length: Password length
            
        Returns:
            str: Generated password
        """
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def validate_password_strength(password: str) -> List[str]:
        """
        Validate password strength against security requirements
        
        Args:
            password: Password to validate
            
        Returns:
            List[str]: List of validation errors (empty if valid)
        """
        errors = []
        
        if len(password) < settings.security.min_password_length:
            errors.append(f"Password must be at least {settings.security.min_password_length} characters long")
        
        if settings.security.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if settings.security.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if settings.security.require_numbers and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
        
        if settings.security.require_special_chars and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")
        
        return errors


class JWTManager:
    """JWT token creation and validation utilities"""
    
    def __init__(self, secret_key: Optional[str] = None, algorithm: Optional[str] = None):
        secret_key_value = secret_key
        if not secret_key_value:
            try:
                secret_key_value = settings.jwt.jwt_secret_key
            except:
                # During testing or when settings aren't available, use a default
                secret_key_value = "default-secret-key-for-testing"
        
        # Ensure secret key is available
        if not secret_key_value:
            secret_key_value = "default-secret-key-for-testing"
            
        self.secret_key: str = secret_key_value
        self.algorithm = algorithm or getattr(settings.jwt, 'jwt_algorithm', 'HS256')
        self.issuer = getattr(settings.jwt, 'jwt_issuer', 'insurecove-auth')
        self.audience = getattr(settings.jwt, 'jwt_audience', 'insurecove-api')
    
    def create_access_token(
        self,
        subject: str,
        user_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a JWT access token
        
        Args:
            subject: Token subject (usually user email)
            user_id: User ID
            role: User role
            permissions: User permissions
            expires_delta: Custom expiration time
            
        Returns:
            str: JWT token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=settings.jwt.access_token_expire_minutes
            )
        
        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": self.issuer,
            "aud": self.audience,
            "type": "access"
        }
        
        if user_id:
            to_encode["user_id"] = user_id
        if role:
            to_encode["role"] = role
        if permissions:
            to_encode["permissions"] = permissions
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(
        self,
        subject: str,
        user_id: Optional[str] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a JWT refresh token
        
        Args:
            subject: Token subject (usually user email)
            user_id: User ID
            expires_delta: Custom expiration time
            
        Returns:
            str: JWT refresh token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                days=settings.jwt.refresh_token_expire_days
            )
        
        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": self.issuer,
            "aud": self.audience,
            "type": "refresh"
        }
        
        if user_id:
            to_encode["user_id"] = user_id
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token
        
        Args:
            token: JWT token to decode
            
        Returns:
            Dict[str, Any]: Token payload
            
        Raises:
            TokenExpiredException: If token is expired
            TokenInvalidException: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise TokenExpiredException()
        except jwt.InvalidTokenError:
            raise TokenInvalidException()
    
    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """
        Verify token and check its type
        
        Args:
            token: JWT token
            token_type: Expected token type
            
        Returns:
            Dict[str, Any]: Token payload
        """
        payload = self.decode_token(token)
        
        if payload.get("type") != token_type:
            raise TokenInvalidException(f"Invalid token type. Expected {token_type}")
        
        return payload


class SecurityMiddleware:
    """Security middleware utilities"""
    
    @staticmethod
    def get_cors_middleware_config():
        """Get CORS middleware configuration"""
        return {
            "allow_origins": settings.get_cors_origins(),
            "allow_credentials": True,
            "allow_methods": settings.security.allowed_methods,
            "allow_headers": settings.security.allowed_headers,
        }
    
    @staticmethod
    def rate_limit_exceeded_handler(request: Request, exc):
        """Handle rate limit exceeded exceptions"""
        if not RATE_LIMITING_AVAILABLE:
            return None
            
        response = RateLimitException(
            limit=exc.detail.split()[4] if hasattr(exc, 'detail') else 100,  # Extract limit from detail
            window=60,  # Default window
            retry_after=getattr(exc, 'retry_after', None)
        )
        return response


class AuthenticationDependency:
    """FastAPI dependency for authentication"""
    
    def __init__(self, jwt_manager: Optional[JWTManager] = None):
        self.jwt_manager = jwt_manager or JWTManager()
    
    async def __call__(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ) -> Dict[str, Any]:
        """
        Authenticate request and return user payload
        
        Args:
            request: FastAPI request
            credentials: Authorization credentials
            
        Returns:
            Dict[str, Any]: User payload from token
            
        Raises:
            TokenMissingException: If no token provided
            TokenInvalidException: If token is invalid
            TokenExpiredException: If token is expired
        """
        if not credentials:
            raise TokenMissingException()
        
        token = credentials.credentials
        payload = self.jwt_manager.verify_token(token, "access")
        
        # Add user info to request state for logging
        request.state.user_id = payload.get("user_id")
        request.state.user_email = payload.get("sub")
        request.state.user_role = payload.get("role")
        
        return payload


class PermissionChecker:
    """Permission checking utilities"""
    
    @staticmethod
    def require_role(required_role: str):
        """Decorator to require specific role"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract user payload from kwargs (assumes it's passed)
                user_payload = kwargs.get('current_user') or kwargs.get('user')
                if not user_payload:
                    raise AuthenticationException("User context not found")
                
                user_role = user_payload.get('role')
                if user_role != required_role:
                    from .exceptions import RoleRequiredException
                    raise RoleRequiredException(required_role, user_role)
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    @staticmethod
    def require_permission(required_permission: str):
        """Decorator to require specific permission"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                user_payload = kwargs.get('current_user') or kwargs.get('user')
                if not user_payload:
                    raise AuthenticationException("User context not found")
                
                user_permissions = user_payload.get('permissions', [])
                if required_permission not in user_permissions:
                    from .exceptions import InsufficientPermissionsException
                    raise InsufficientPermissionsException(required_permission)
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_string(value: str, salt: Optional[str] = None) -> str:
    """Hash a string using SHA-256"""
    if salt:
        value = f"{value}{salt}"
    return hashlib.sha256(value.encode()).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks"""
    return secrets.compare_digest(a.encode(), b.encode())


# Initialize global instances
jwt_manager = JWTManager()
auth_dependency = AuthenticationDependency(jwt_manager)
password_manager = PasswordManager()
