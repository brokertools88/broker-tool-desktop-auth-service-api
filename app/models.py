"""
InsureCove Authentication Service - API Models

Pydantic models for request/response validation:
- Authentication models
- User management models
- Token models
- Error models
- Response models
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from enum import Enum

from pydantic import BaseModel, Field, EmailStr, field_validator, model_validator


class UserRole(str, Enum):
    """User role enumeration"""
    BROKER = "broker"
    CLIENT = "client"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class TokenType(str, Enum):
    """Token type enumeration"""
    ACCESS = "access"
    REFRESH = "refresh"
    SERVICE = "service"


class UserStatus(str, Enum):
    """User status enumeration"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"


# Base Models

class TimestampedModel(BaseModel):
    """Base model with timestamps"""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ResponseModel(BaseModel):
    """Base response model"""
    success: bool = True
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# Authentication Models

class LoginRequest(BaseModel):
    """Login request model"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")
    remember_me: bool = Field(default=False, description="Keep user logged in")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "john.doe@example.com",
                "password": "SecurePassword123!",
                "remember_me": False
            }
        }
    }


class TokenRefreshRequest(BaseModel):
    """Token refresh request model"""
    refresh_token: str = Field(..., description="Valid refresh token")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }
    }


class TokenVerifyRequest(BaseModel):
    """Token verification request model"""
    token: str = Field(..., description="Token to verify")
    token_type: TokenType = Field(default=TokenType.ACCESS, description="Type of token")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "access"
            }
        }
    }


class LogoutRequest(BaseModel):
    """Logout request model"""
    refresh_token: Optional[str] = Field(default=None, description="Refresh token to invalidate")
    logout_all_devices: bool = Field(default=False, description="Logout from all devices")


# User Management Models

class UserBase(BaseModel):
    """Base user model"""
    email: EmailStr = Field(..., description="User email address")
    first_name: str = Field(..., min_length=1, max_length=50, description="First name")
    last_name: str = Field(..., min_length=1, max_length=50, description="Last name")
    phone: Optional[str] = Field(default=None, max_length=20, description="Phone number")
    role: UserRole = Field(..., description="User role")
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        """Validate phone number format"""
        if v and not v.replace('+', '').replace('-', '').replace(' ', '').isdigit():
            raise ValueError('Invalid phone number format')
        return v


class BrokerCreateRequest(UserBase):
    """Broker creation request model"""
    password: str = Field(..., min_length=8, description="User password")
    company_name: str = Field(..., min_length=1, max_length=100, description="Company name")
    license_number: Optional[str] = Field(default=None, max_length=50, description="Broker license number")
    
    role: UserRole = Field(default=UserRole.BROKER, description="User role (always broker)")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "broker@insurecove.com",
                "password": "SecurePassword123!",
                "first_name": "John",
                "last_name": "Doe",
                "phone": "+1-555-123-4567",
                "company_name": "ABC Insurance Brokerage",
                "license_number": "BRK-12345"
            }
        }
    }


class ClientCreateRequest(UserBase):
    """Client creation request model"""
    password: str = Field(..., min_length=8, description="User password")
    date_of_birth: Optional[datetime] = Field(default=None, description="Date of birth")
    address: Optional[str] = Field(default=None, max_length=200, description="Address")
    
    role: UserRole = Field(default=UserRole.CLIENT, description="User role (always client)")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "client@example.com",
                "password": "SecurePassword123!",
                "first_name": "Jane",
                "last_name": "Smith",
                "phone": "+1-555-987-6543",
                "date_of_birth": "1990-01-15T00:00:00Z",
                "address": "123 Main St, Anytown, ST 12345"
            }
        }
    }


class UserUpdateRequest(BaseModel):
    """User update request model"""
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    phone: Optional[str] = Field(default=None, max_length=20)
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        """Validate phone number format"""
        if v and not v.replace('+', '').replace('-', '').replace(' ', '').isdigit():
            raise ValueError('Invalid phone number format')
        return v


class PasswordChangeRequest(BaseModel):
    """Password change request model"""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")
    confirm_password: str = Field(..., description="Confirm new password")
    
    @model_validator(mode='after')
    def validate_passwords_match(self):
        """Validate that new passwords match"""
        if self.new_password and self.confirm_password and self.new_password != self.confirm_password:
            raise ValueError('New passwords do not match')
        return self


class PasswordResetRequest(BaseModel):
    """Password reset request model"""
    email: EmailStr = Field(..., description="Email address for password reset")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "user@example.com"
            }
        }
    }


class PasswordResetConfirmRequest(BaseModel):
    """Password reset confirmation model"""
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, description="New password")
    confirm_password: str = Field(..., description="Confirm new password")
    
    @model_validator(mode='after')
    def validate_passwords_match(self):
        """Validate that passwords match"""
        if self.new_password and self.confirm_password and self.new_password != self.confirm_password:
            raise ValueError('Passwords do not match')
        return self


# Response Models

class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800
            }
        }
    }


class UserResponse(TimestampedModel):
    """User response model"""
    id: str = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email")
    first_name: str = Field(..., description="First name")
    last_name: str = Field(..., description="Last name")
    phone: Optional[str] = Field(default=None, description="Phone number")
    role: UserRole = Field(..., description="User role")
    status: UserStatus = Field(..., description="User status")
    email_verified: bool = Field(default=False, description="Email verification status")
    last_login: Optional[datetime] = Field(default=None, description="Last login timestamp")
    
    # Role-specific fields
    company_name: Optional[str] = Field(default=None, description="Company name (brokers only)")
    license_number: Optional[str] = Field(default=None, description="License number (brokers only)")
    date_of_birth: Optional[datetime] = Field(default=None, description="Date of birth (clients only)")
    address: Optional[str] = Field(default=None, description="Address (clients only)")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "user_123456789",
                "email": "john.doe@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "phone": "+1-555-123-4567",
                "role": "broker",
                "status": "active",
                "email_verified": True,
                "last_login": "2025-07-07T14:30:00Z",
                "company_name": "ABC Insurance Brokerage",
                "license_number": "BRK-12345",
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-07-07T14:30:00Z"
            }
        }
    }


class SessionResponse(BaseModel):
    """Current session response model"""
    user: UserResponse = Field(..., description="Current user information")
    session_id: str = Field(..., description="Session ID")
    expires_at: datetime = Field(..., description="Session expiration time")
    permissions: List[str] = Field(default=[], description="User permissions")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "user": {
                    "id": "user_123456789",
                    "email": "john.doe@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "role": "broker",
                    "status": "active"
                },
                "session_id": "session_abcd1234",
                "expires_at": "2025-07-07T16:30:00Z",
                "permissions": ["read:profile", "write:profile", "read:clients"]
            }
        }
    }


class TokenVerifyResponse(BaseModel):
    """Token verification response model"""
    valid: bool = Field(..., description="Whether token is valid")
    token_type: TokenType = Field(..., description="Type of token")
    user_id: Optional[str] = Field(default=None, description="User ID from token")
    email: Optional[str] = Field(default=None, description="Email from token")
    role: Optional[UserRole] = Field(default=None, description="Role from token")
    expires_at: Optional[datetime] = Field(default=None, description="Token expiration time")
    permissions: List[str] = Field(default=[], description="User permissions")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "valid": True,
                "token_type": "access",
                "user_id": "user_123456789",
                "email": "john.doe@example.com",
                "role": "broker",
                "expires_at": "2025-07-07T16:00:00Z",
                "permissions": ["read:profile", "write:profile"]
            }
        }
    }


class LoginResponse(ResponseModel):
    """Login response model"""
    tokens: TokenResponse = Field(..., description="Authentication tokens")
    user: UserResponse = Field(..., description="User information")
    session_id: str = Field(..., description="Session ID")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "message": "Login successful",
                "timestamp": "2025-07-07T14:30:00Z",
                "tokens": {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "token_type": "bearer",
                    "expires_in": 1800
                },
                "user": {
                    "id": "user_123456789",
                    "email": "john.doe@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "role": "broker",
                    "status": "active"
                },
                "session_id": "session_abcd1234"
            }
        }
    }


class UserCreateResponse(ResponseModel):
    """User creation response model"""
    user: UserResponse = Field(..., description="Created user information")
    verification_required: bool = Field(default=True, description="Whether email verification is required")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "message": "User created successfully",
                "timestamp": "2025-07-07T14:30:00Z",
                "user": {
                    "id": "user_123456789",
                    "email": "john.doe@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "role": "broker",
                    "status": "pending_verification"
                },
                "verification_required": True
            }
        }
    }


# Health Check Models

class HealthStatus(str, Enum):
    """Health status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ServiceHealth(BaseModel):
    """Individual service health model"""
    status: HealthStatus = Field(..., description="Service health status")
    response_time_ms: Optional[float] = Field(default=None, description="Response time in milliseconds")
    details: Optional[str] = Field(default=None, description="Additional details")


class HealthCheckResponse(BaseModel):
    """Health check response model"""
    status: HealthStatus = Field(..., description="Overall health status")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Check timestamp")
    services: Dict[str, ServiceHealth] = Field(default={}, description="Individual service statuses")
    version: str = Field(..., description="Application version")
    uptime_seconds: float = Field(..., description="Uptime in seconds")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "status": "healthy",
                "timestamp": "2025-07-07T14:30:00Z",
                "services": {
                    "database": {
                        "status": "healthy",
                        "response_time_ms": 45.2
                    },
                    "aws_secrets": {
                        "status": "healthy",
                        "response_time_ms": 120.5
                    },
                    "redis": {
                        "status": "healthy",
                        "response_time_ms": 12.1
                    }
                },
                "version": "1.0.0",
                "uptime_seconds": 86400.0
            }
        }
    }


# Metrics Models

class MetricsResponse(BaseModel):
    """Metrics response model"""
    requests_total: int = Field(..., description="Total number of requests")
    requests_per_second: float = Field(..., description="Current requests per second")
    average_response_time_ms: float = Field(..., description="Average response time")
    active_sessions: int = Field(..., description="Number of active sessions")
    error_rate: float = Field(..., description="Current error rate")
    uptime_seconds: float = Field(..., description="Uptime in seconds")
    memory_usage_mb: float = Field(..., description="Memory usage in MB")
    cpu_usage_percent: float = Field(..., description="CPU usage percentage")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "requests_total": 1250,
                "requests_per_second": 5.2,
                "average_response_time_ms": 125.5,
                "active_sessions": 48,
                "error_rate": 0.02,
                "uptime_seconds": 86400.0,
                "memory_usage_mb": 256.8,
                "cpu_usage_percent": 15.3
            }
        }
    }
