"""
InsureCove Authentication Service - Auth Module

This module provides authentication and authorization functionality including:
- AWS Secrets Manager integration
- JWT token handling
- User authentication
- Security utilities
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

__all__ = [
    "AWSSecretsManager",
    "InsureCoveSecrets", 
    "get_secrets_manager",
    "get_insurecove_secrets",
    "test_secrets_connection",
    "SecretNotFoundException",
    "AWSSecretsError"
] 