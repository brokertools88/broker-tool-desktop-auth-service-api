"""
InsureCove Authentication Service - Supabase Integration

This module provides comprehensive authentication functionality including:
- Supabase client integration with AWS Secrets Manager
- JWT token generation and validation
- User registration and authentication
- Password reset functionality
- Service token management
- Session handling
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum

import jwt
from supabase import create_client, Client
from gotrue.errors import AuthApiError
from pydantic import BaseModel, Field, EmailStr

# Configure logging
logger = logging.getLogger(__name__)

# Optional password hashing - use passlib if available, otherwise hashlib
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    PASSLIB_AVAILABLE = True
except ImportError:
    import hashlib
    import secrets
    pwd_context = None
    PASSLIB_AVAILABLE = False

from .aws_secrets import AWSSecretsManager, AWSSecretsManagerError


class UserRole(str, Enum):
    """User roles in the system"""
    ADMIN = "admin"
    USER = "user"
    SERVICE = "service"
    BROKER = "broker"


class TokenType(str, Enum):
    """JWT token types"""
    ACCESS = "access"
    REFRESH = "refresh"
    SERVICE = "service"
    RESET = "reset"


@dataclass
class AuthUser:
    """User authentication data"""
    id: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JWT payload"""
        return {
            "user_id": self.id,
            "email": self.email,
            "role": self.role.value,
            "is_active": self.is_active,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "metadata": self.metadata or {}
        }


class LoginRequest(BaseModel):
    """Login request model"""
    email: EmailStr
    password: str
    remember_me: bool = False


class RegisterRequest(BaseModel):
    """User registration request model"""
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.USER
    metadata: Optional[Dict[str, Any]] = None


class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class PasswordResetRequest(BaseModel):
    """Password reset request model"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation model"""
    token: str
    new_password: str


class SupabaseAuthError(Exception):
    """Base exception for Supabase authentication errors"""
    pass


class AuthenticationError(SupabaseAuthError):
    """Raised when authentication fails"""
    pass


class AuthorizationError(SupabaseAuthError):
    """Raised when authorization fails"""
    pass


class TokenError(SupabaseAuthError):
    """Raised when token operations fail"""
    pass


class SupabaseAuthManager:
    """
    Supabase Authentication Manager
    
    Provides comprehensive authentication functionality including:
    - User registration and login
    - JWT token generation and validation
    - Password reset functionality
    - Service token management
    - Integration with AWS Secrets Manager
    """
    
    def __init__(self, secrets_manager: Optional[AWSSecretsManager] = None):
        """
        Initialize Supabase Auth Manager
        
        Args:
            secrets_manager: AWS Secrets Manager instance for configuration
        """
        self.secrets_manager = secrets_manager or AWSSecretsManager()
        self._supabase_client: Optional[Client] = None
        self._db_config: Optional[Dict[str, Any]] = None
        self._jwt_config: Optional[Dict[str, Any]] = None
        
    def _get_database_config(self) -> Dict[str, Any]:
        """Get database configuration from AWS Secrets Manager"""
        if self._db_config is None:
            try:
                self._db_config = self.secrets_manager.get_database_config()
                logger.info("Database configuration loaded from AWS Secrets Manager")
            except Exception as e:
                logger.error(f"Failed to load database configuration: {e}")
                raise SupabaseAuthError(f"Database configuration error: {e}")
        return self._db_config
    
    def _get_jwt_config(self) -> Dict[str, Any]:
        """Get JWT configuration from AWS Secrets Manager"""
        if self._jwt_config is None:
            try:
                self._jwt_config = self.secrets_manager.get_jwt_config()
                logger.info("JWT configuration loaded from AWS Secrets Manager")
            except Exception as e:
                logger.error(f"Failed to load JWT configuration: {e}")
                raise SupabaseAuthError(f"JWT configuration error: {e}")
        return self._jwt_config
    
    def _get_supabase_client(self) -> Client:
        """Get or create Supabase client"""
        if self._supabase_client is None:
            try:
                db_config = self._get_database_config()
                
                supabase_url = db_config.get("supabase_url")
                supabase_key = db_config.get("supabase_anon_key")
                
                if not supabase_url or not supabase_key:
                    raise SupabaseAuthError("Missing Supabase URL or key in configuration")
                
                self._supabase_client = create_client(supabase_url, supabase_key)
                logger.info("Supabase client initialized successfully")
                
            except Exception as e:
                logger.error(f"Failed to initialize Supabase client: {e}")
                raise SupabaseAuthError(f"Supabase initialization error: {e}")
        
        return self._supabase_client
    
    def _generate_jwt_token(
        self,
        user: AuthUser,
        token_type: TokenType = TokenType.ACCESS,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Generate JWT token for user
        
        Args:
            user: User data
            token_type: Type of token to generate
            expires_delta: Token expiration time
            
        Returns:
            JWT token string
        """
        try:
            jwt_config = self._get_jwt_config()
            
            # Set expiration time
            if expires_delta is None:
                if token_type == TokenType.ACCESS:
                    expires_delta = timedelta(minutes=int(jwt_config.get("jwt_access_token_expire_minutes", 30)))
                elif token_type == TokenType.REFRESH:
                    expires_delta = timedelta(days=7)  # 7 days for refresh tokens
                elif token_type == TokenType.SERVICE:
                    expires_delta = timedelta(hours=24)  # 24 hours for service tokens
                elif token_type == TokenType.RESET:
                    expires_delta = timedelta(hours=1)  # 1 hour for reset tokens
            
            # Create token payload
            now = datetime.now(timezone.utc)
            payload = {
                **user.to_dict(),
                "token_type": token_type.value,
                "iat": now,
                "exp": now + expires_delta,
                "iss": jwt_config.get("jwt_issuer", "insurecove-auth"),
                "aud": jwt_config.get("jwt_audience", "insurecove-api")
            }
            
            # Generate token
            secret_key = jwt_config.get("jwt_secret_key")
            if not secret_key:
                raise TokenError("JWT secret key not configured")
                
            token = jwt.encode(
                payload,
                secret_key,
                algorithm=jwt_config.get("jwt_algorithm", "HS256")
            )
            
            logger.debug(f"Generated {token_type.value} token for user {user.email}")
            return token
            
        except Exception as e:
            logger.error(f"Failed to generate JWT token: {e}")
            raise TokenError(f"Token generation failed: {e}")
    
    def _verify_jwt_token(self, token: str, token_type: Optional[TokenType] = None) -> Dict[str, Any]:
        """
        Verify and decode JWT token
        
        Args:
            token: JWT token to verify
            token_type: Expected token type (optional)
            
        Returns:
            Decoded token payload
            
        Raises:
            TokenError: If token is invalid or expired
        """
        try:
            jwt_config = self._get_jwt_config()
            
            # Decode token
            secret_key = jwt_config.get("jwt_secret_key")
            if not secret_key:
                raise TokenError("JWT secret key not configured")
                
            payload = jwt.decode(
                token,
                secret_key,
                algorithms=[jwt_config.get("jwt_algorithm", "HS256")],
                audience=jwt_config.get("jwt_audience", "insurecove-api"),
                issuer=jwt_config.get("jwt_issuer", "insurecove-auth")
            )
            
            # Verify token type if specified
            if token_type and payload.get("token_type") != token_type.value:
                raise TokenError(f"Invalid token type: expected {token_type.value}")
            
            logger.debug(f"Token verified successfully for user {payload.get('email')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            raise TokenError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise TokenError(f"Invalid token: {e}")
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            raise TokenError(f"Token verification error: {e}")
    
    async def register_user(self, request: RegisterRequest) -> TokenResponse:
        """
        Register a new user
        
        Args:
            request: User registration data
            
        Returns:
            Token response with access and refresh tokens
            
        Raises:
            AuthenticationError: If registration fails
        """
        try:
            supabase = self._get_supabase_client()
            
            # Register user with Supabase Auth
            auth_response = supabase.auth.sign_up({
                "email": request.email,
                "password": request.password,
                "options": {
                    "data": {
                        "full_name": request.full_name,
                        "role": request.role.value,
                        "metadata": request.metadata or {}
                    }
                }
            })
            
            if not auth_response.user:
                raise AuthenticationError("User registration failed")
            
            # Create AuthUser object
            user_email = auth_response.user.email
            if not user_email:
                raise AuthenticationError("User email is required")
                
            user = AuthUser(
                id=auth_response.user.id,
                email=user_email,
                role=request.role,
                is_active=True,
                created_at=datetime.now(timezone.utc),
                metadata=request.metadata
            )
            
            # Generate tokens
            access_token = self._generate_jwt_token(user, TokenType.ACCESS)
            refresh_token = self._generate_jwt_token(user, TokenType.REFRESH)
            
            logger.info(f"User registered successfully: {request.email}")
            
            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=1800,  # 30 minutes
                user=user.to_dict()
            )
            
        except AuthApiError as e:
            logger.error(f"Supabase registration error: {e}")
            raise AuthenticationError(f"Registration failed: {e.message}")
        except Exception as e:
            logger.error(f"User registration failed: {e}")
            raise AuthenticationError(f"Registration error: {e}")
    
    async def authenticate_user(self, request: LoginRequest) -> TokenResponse:
        """
        Authenticate user with email and password
        
        Args:
            request: Login credentials
            
        Returns:
            Token response with access and refresh tokens
            
        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            supabase = self._get_supabase_client()
            
            # Authenticate with Supabase
            auth_response = supabase.auth.sign_in_with_password({
                "email": request.email,
                "password": request.password
            })
            
            if not auth_response.user:
                raise AuthenticationError("Invalid credentials")
            
            # Get user metadata
            user_metadata = auth_response.user.user_metadata or {}
            
            # Validate user email
            user_email = auth_response.user.email
            if not user_email:
                raise AuthenticationError("User email is required")
            
            # Create AuthUser object
            user = AuthUser(
                id=auth_response.user.id,
                email=user_email,
                role=UserRole(user_metadata.get("role", "user")),
                is_active=True,
                created_at=datetime.fromisoformat(str(auth_response.user.created_at).replace("Z", "+00:00")),
                last_login=datetime.now(timezone.utc),
                metadata=user_metadata.get("metadata", {})
            )
            
            # Generate tokens
            expires_delta = timedelta(days=30) if request.remember_me else None
            access_token = self._generate_jwt_token(user, TokenType.ACCESS, expires_delta)
            refresh_token = self._generate_jwt_token(user, TokenType.REFRESH)
            
            logger.info(f"User authenticated successfully: {request.email}")
            
            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=1800 if not request.remember_me else 2592000,  # 30 min or 30 days
                user=user.to_dict()
            )
            
        except AuthApiError as e:
            logger.error(f"Supabase authentication error: {e}")
            raise AuthenticationError(f"Authentication failed: {e.message}")
        except Exception as e:
            logger.error(f"User authentication failed: {e}")
            raise AuthenticationError(f"Authentication error: {e}")
    
    async def refresh_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh access token using refresh token
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New token response
            
        Raises:
            TokenError: If refresh token is invalid
        """
        try:
            # Verify refresh token
            payload = self._verify_jwt_token(refresh_token, TokenType.REFRESH)
            
            # Create user from token payload
            user = AuthUser(
                id=payload["user_id"],
                email=payload["email"],
                role=UserRole(payload["role"]),
                is_active=payload["is_active"],
                created_at=datetime.fromisoformat(payload.get("created_at", datetime.now().isoformat())),
                last_login=datetime.now(timezone.utc),
                metadata=payload.get("metadata", {})
            )
            
            # Generate new tokens
            new_access_token = self._generate_jwt_token(user, TokenType.ACCESS)
            new_refresh_token = self._generate_jwt_token(user, TokenType.REFRESH)
            
            logger.info(f"Token refreshed for user: {user.email}")
            
            return TokenResponse(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                expires_in=1800,  # 30 minutes
                user=user.to_dict()
            )
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise TokenError(f"Token refresh error: {e}")
    
    async def generate_service_token(self, user_id: str, service_name: str) -> str:
        """
        Generate service token for API access
        
        Args:
            user_id: User ID requesting the service token
            service_name: Name of the service requesting access
            
        Returns:
            Service token string
            
        Raises:
            AuthorizationError: If user is not authorized for service tokens
        """
        try:
            supabase = self._get_supabase_client()
            
            # Get user details
            user_response = supabase.auth.get_user()
            if not user_response or not user_response.user or user_response.user.id != user_id:
                raise AuthorizationError("User not found or unauthorized")
            
            user_metadata = user_response.user.user_metadata or {}
            user_role = UserRole(user_metadata.get("role", "user"))
            
            # Check if user can generate service tokens
            if user_role not in [UserRole.ADMIN, UserRole.SERVICE]:
                raise AuthorizationError("Insufficient privileges for service token generation")
            
            # Validate user email
            user_email = user_response.user.email
            if not user_email:
                raise AuthorizationError("User email is required")
            
            # Create service user
            service_user = AuthUser(
                id=user_id,
                email=user_email,
                role=UserRole.SERVICE,
                is_active=True,
                created_at=datetime.now(timezone.utc),
                metadata={"service_name": service_name, "original_role": user_role.value}
            )
            
            # Generate service token (24 hours)
            service_token = self._generate_jwt_token(
                service_user,
                TokenType.SERVICE,
                timedelta(hours=24)
            )
            
            logger.info(f"Service token generated for {service_name} by user {user_email}")
            return service_token
            
        except Exception as e:
            logger.error(f"Service token generation failed: {e}")
            raise AuthorizationError(f"Service token generation error: {e}")
    
    async def reset_password_request(self, request: PasswordResetRequest) -> bool:
        """
        Request password reset
        
        Args:
            request: Password reset request with email
            
        Returns:
            True if reset email was sent
        """
        try:
            supabase = self._get_supabase_client()
            
            # Send password reset email
            supabase.auth.reset_password_email(request.email)
            
            logger.info(f"Password reset requested for: {request.email}")
            return True
            
        except Exception as e:
            logger.error(f"Password reset request failed: {e}")
            # Don't reveal if email exists or not
            return True
    
    async def verify_user_token(self, token: str) -> AuthUser:
        """
        Verify user token and return user data
        
        Args:
            token: JWT access token
            
        Returns:
            AuthUser object
            
        Raises:
            TokenError: If token is invalid
        """
        try:
            payload = self._verify_jwt_token(token, TokenType.ACCESS)
            
            return AuthUser(
                id=payload["user_id"],
                email=payload["email"],
                role=UserRole(payload["role"]),
                is_active=payload["is_active"],
                created_at=datetime.fromisoformat(payload.get("created_at", datetime.now().isoformat())),
                last_login=datetime.fromisoformat(payload["last_login"]) if payload.get("last_login") else None,
                metadata=payload.get("metadata", {})
            )
            
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            raise TokenError(f"Invalid token: {e}")
    
    async def logout_user(self, token: str) -> bool:
        """
        Logout user (invalidate session)
        
        Args:
            token: Access token to invalidate
            
        Returns:
            True if logout successful
        """
        try:
            # Verify token first
            payload = self._verify_jwt_token(token, TokenType.ACCESS)
            
            # In a production system, you'd want to add token to a blacklist
            # For now, we'll just log the logout
            logger.info(f"User logged out: {payload.get('email')}")
            return True
            
        except Exception as e:
            logger.error(f"Logout failed: {e}")
            return False


# Convenience functions
_auth_manager: Optional[SupabaseAuthManager] = None


def get_auth_manager() -> SupabaseAuthManager:
    """Get singleton auth manager instance"""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = SupabaseAuthManager()
    return _auth_manager


async def authenticate_request(token: str) -> AuthUser:
    """
    Authenticate API request using JWT token
    
    Args:
        token: Bearer token from request header
        
    Returns:
        Authenticated user data
        
    Raises:
        TokenError: If authentication fails
    """
    # Remove 'Bearer ' prefix if present
    if token.startswith("Bearer "):
        token = token[7:]
    
    auth_manager = get_auth_manager()
    return await auth_manager.verify_user_token(token)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    if not pwd_context:
        # Fallback to simple comparison (not recommended for production)
        return plain_password == hashed_password
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash"""
    if not pwd_context:
        # Fallback to simple hash (not recommended for production)
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()
    return pwd_context.hash(password)


if __name__ == "__main__":
    # Basic test
    import asyncio
    
    async def test_auth():
        """Test authentication system"""
        auth_manager = SupabaseAuthManager()
        
        # Test configuration loading
        try:
            db_config = auth_manager._get_database_config()
            jwt_config = auth_manager._get_jwt_config()
            print("✅ Configuration loaded successfully")
        except Exception as e:
            print(f"❌ Configuration error: {e}")
            return
        
        print("🔐 Supabase Auth Manager initialized successfully")
    
    asyncio.run(test_auth()) 