"""
InsureCove Authentication Service - Auth Module

This module provides authentication and authorization functionality including:
- AWS Secrets Manager integration
- JWT token handling
- User authentication
- Security utilities
- Supabase integration
"""

from .aws_secrets import (
    AWSSecretsManager,
    AWSSecretsConfig,
    SecretValue,
    AWSSecretsManagerError,
    SecretNotFoundError,
    SecretAccessDeniedError,
    get_secrets_manager,
    get_database_config,
    get_jwt_config,
    get_mistral_api_key,
    test_aws_connection
)

from .supabase_auth import (
    SupabaseAuthManager,
    AuthUser,
    UserRole,
    TokenType,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    PasswordResetRequest,
    PasswordResetConfirm,
    SupabaseAuthError,
    AuthenticationError,
    AuthorizationError,
    TokenError,
    get_auth_manager,
    authenticate_request,
    verify_password,
    get_password_hash
)

__all__ = [
    # AWS Secrets
    "AWSSecretsManager",
    "AWSSecretsConfig", 
    "SecretValue",
    "AWSSecretsManagerError",
    "SecretNotFoundError",
    "SecretAccessDeniedError",
    "get_secrets_manager",
    "get_database_config",
    "get_jwt_config",
    "get_mistral_api_key",
    "test_aws_connection",
    
    # Supabase Auth
    "SupabaseAuthManager",
    "AuthUser",
    "UserRole",
    "TokenType",
    "LoginRequest",
    "RegisterRequest", 
    "TokenResponse",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    "SupabaseAuthError",
    "AuthenticationError",
    "AuthorizationError",
    "TokenError",
    "get_auth_manager",
    "authenticate_request",
    "verify_password",
    "get_password_hash"
] 