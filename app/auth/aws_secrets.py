"""
AWS Secrets Manager Integration for InsureCove Auth Service

This module provides a secure and efficient way to retrieve secrets from AWS Secrets Manager
with support for:
- Caching for performance
- Proxy configuration for corporate networks
- Error handling and retry logic
- JSON and string secret formats
"""

import json
import logging
import os
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass
from functools import lru_cache

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
try:
    from pydantic_settings import BaseSettings
    from pydantic import Field
except ImportError:
    # Fallback for older pydantic versions
    from pydantic import BaseSettings, Field


# Configure logging
logger = logging.getLogger(__name__)


class AWSSecretsConfig(BaseSettings):
    """Configuration for AWS Secrets Manager"""
    
    aws_region: str = Field(default="ap-east-1", description="AWS region")
    aws_access_key_id: Optional[str] = Field(default=None, description="AWS access key ID")
    aws_secret_access_key: Optional[str] = Field(default=None, description="AWS secret access key")
    
    # Proxy settings for corporate networks
    http_proxy: Optional[str] = Field(default=None, description="HTTP proxy URL")
    https_proxy: Optional[str] = Field(default=None, description="HTTPS proxy URL")
    
    # Secret name prefix
    secret_prefix: str = Field(default="insurecove", description="Prefix for secret names")
    
    # Cache settings
    cache_ttl: int = Field(default=300, description="Cache TTL in seconds")  # 5 minutes
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore"
    }


@dataclass
class SecretValue:
    """Container for secret values with metadata"""
    value: Union[str, Dict[str, Any]]
    version_id: str
    created_date: str
    secret_name: str
    
    def as_dict(self) -> Dict[str, Any]:
        """Convert secret value to dictionary if it's JSON"""
        if isinstance(self.value, str):
            try:
                return json.loads(self.value)
            except json.JSONDecodeError:
                raise ValueError(f"Secret '{self.secret_name}' is not valid JSON")
        return self.value
    
    def as_string(self) -> str:
        """Convert secret value to string"""
        if isinstance(self.value, dict):
            return json.dumps(self.value)
        return str(self.value)


class AWSSecretsManagerError(Exception):
    """Base exception for AWS Secrets Manager operations"""
    pass


class SecretNotFoundError(AWSSecretsManagerError):
    """Raised when a requested secret is not found"""
    pass


class SecretAccessDeniedError(AWSSecretsManagerError):
    """Raised when access to a secret is denied"""
    pass


class AWSSecretsManager:
    """
    AWS Secrets Manager client with caching and proxy support
    
    This class provides a high-level interface for retrieving secrets from AWS Secrets Manager
    with built-in caching, error handling, and proxy support for corporate environments.
    """
    
    def __init__(self, config: Optional[AWSSecretsConfig] = None):
        """
        Initialize AWS Secrets Manager client
        
        Args:
            config: Configuration object. If None, will be created from environment variables.
        """
        self.config = config or AWSSecretsConfig()
        self._client = None
        self._cache = {}
        
    def _get_client(self):
        """Get or create boto3 secrets manager client with proxy configuration"""
        if self._client is not None:
            return self._client
            
        try:
            # Prepare session configuration
            session_config = {}
            
            # Configure proxy if specified
            if self.config.http_proxy or self.config.https_proxy:
                session_config['proxies'] = {}
                if self.config.http_proxy:
                    session_config['proxies']['http'] = self.config.http_proxy
                if self.config.https_proxy:
                    session_config['proxies']['https'] = self.config.https_proxy
            
            # Create boto3 session
            session = boto3.Session(
                aws_access_key_id=self.config.aws_access_key_id,
                aws_secret_access_key=self.config.aws_secret_access_key,
                region_name=self.config.aws_region
            )
            
            # Create secrets manager client
            client_config = {}
            if session_config.get('proxies'):
                client_config['proxies'] = session_config['proxies']
                
            self._client = session.client(
                'secretsmanager',
                region_name=self.config.aws_region,
                **client_config
            )
            
            logger.info(f"AWS Secrets Manager client initialized for region: {self.config.aws_region}")
            return self._client
            
        except (NoCredentialsError, PartialCredentialsError) as e:
            error_msg = f"AWS credentials not configured properly: {str(e)}"
            logger.error(error_msg)
            raise AWSSecretsManagerError(error_msg) from e
        except Exception as e:
            error_msg = f"Failed to initialize AWS Secrets Manager client: {str(e)}"
            logger.error(error_msg)
            raise AWSSecretsManagerError(error_msg) from e
    
    def _get_cache_key(self, secret_name: str, version_id: Optional[str] = None) -> str:
        """Generate cache key for secret"""
        key = f"{self.config.secret_prefix}/{secret_name}"
        if version_id:
            key += f":{version_id}"
        return key
    
    def _is_cache_valid(self, cache_entry: Dict[str, Any]) -> bool:
        """Check if cache entry is still valid"""
        import time
        return (time.time() - cache_entry['timestamp']) < self.config.cache_ttl
    
    def get_secret(self, secret_name: str, version_id: Optional[str] = None, use_cache: bool = True) -> SecretValue:
        """
        Retrieve a secret from AWS Secrets Manager
        
        Args:
            secret_name: Name of the secret (without prefix)
            version_id: Specific version of the secret to retrieve
            use_cache: Whether to use cached value if available
            
        Returns:
            SecretValue object containing the secret data and metadata
            
        Raises:
            SecretNotFoundError: If the secret doesn't exist
            SecretAccessDeniedError: If access to the secret is denied
            AWSSecretsManagerError: For other AWS-related errors
        """
        # Check cache first
        cache_key = self._get_cache_key(secret_name, version_id)
        if use_cache and cache_key in self._cache:
            cache_entry = self._cache[cache_key]
            if self._is_cache_valid(cache_entry):
                logger.debug(f"Retrieved secret '{secret_name}' from cache")
                return cache_entry['secret']
        
        # Full secret name with prefix
        full_secret_name = f"{self.config.secret_prefix}/{secret_name}"
        
        try:
            client = self._get_client()
            
            # Prepare request parameters
            request_params = {
                'SecretId': full_secret_name
            }
            if version_id:
                request_params['VersionId'] = version_id
            
            # Get secret from AWS
            logger.debug(f"Retrieving secret '{full_secret_name}' from AWS Secrets Manager")
            response = client.get_secret_value(**request_params)
            
            # Parse secret value
            if 'SecretString' in response:
                secret_value = response['SecretString']
                # Try to parse as JSON
                try:
                    secret_value = json.loads(secret_value)
                except json.JSONDecodeError:
                    # Keep as string if not valid JSON
                    pass
            else:
                # Binary secret
                secret_value = response['SecretBinary']
            
            # Create SecretValue object
            secret = SecretValue(
                value=secret_value,
                version_id=response.get('VersionId', ''),
                created_date=response.get('CreatedDate', '').isoformat() if response.get('CreatedDate') else '',
                secret_name=full_secret_name
            )
            
            # Cache the result
            if use_cache:
                import time
                self._cache[cache_key] = {
                    'secret': secret,
                    'timestamp': time.time()
                }
            
            logger.info(f"Successfully retrieved secret '{secret_name}'")
            return secret
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            if error_code == 'ResourceNotFoundException':
                raise SecretNotFoundError(f"Secret '{full_secret_name}' not found: {error_message}")
            elif error_code in ['AccessDeniedException', 'UnauthorizedOperation']:
                raise SecretAccessDeniedError(f"Access denied to secret '{full_secret_name}': {error_message}")
            else:
                raise AWSSecretsManagerError(f"AWS error retrieving secret '{full_secret_name}': {error_message}")
        except Exception as e:
            raise AWSSecretsManagerError(f"Unexpected error retrieving secret '{secret_name}': {str(e)}")
    
    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration from secrets"""
        try:
            secret = self.get_secret("production/database")
            return secret.as_dict()
        except Exception as e:
            logger.error(f"Failed to retrieve database configuration: {e}")
            raise
    
    def get_jwt_config(self) -> Dict[str, Any]:
        """Get JWT configuration from secrets"""
        try:
            secret = self.get_secret("production/jwt")
            return secret.as_dict()
        except Exception as e:
            logger.error(f"Failed to retrieve JWT configuration: {e}")
            raise
    
    def get_mistral_api_key(self) -> str:
        """Get Mistral AI API key"""
        try:
            secret = self.get_secret("mistral-api-key")
            if isinstance(secret.value, dict):
                return secret.value.get('api_key', '')
            return secret.as_string()
        except Exception as e:
            logger.error(f"Failed to retrieve Mistral API key: {e}")
            raise
    
    def test_connection(self) -> bool:
        """Test connection to AWS Secrets Manager"""
        try:
            client = self._get_client()
            # Try to list secrets to test connection
            client.list_secrets(MaxResults=1)
            logger.info("AWS Secrets Manager connection test successful")
            return True
        except Exception as e:
            logger.error(f"AWS Secrets Manager connection test failed: {e}")
            return False
    
    def clear_cache(self):
        """Clear the secrets cache"""
        self._cache.clear()
        logger.info("Secrets cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        import time
        current_time = time.time()
        
        stats = {
            'total_entries': len(self._cache),
            'valid_entries': 0,
            'expired_entries': 0,
            'cache_ttl': self.config.cache_ttl
        }
        
        for entry in self._cache.values():
            if (current_time - entry['timestamp']) < self.config.cache_ttl:
                stats['valid_entries'] += 1
            else:
                stats['expired_entries'] += 1
        
        return stats


# Convenience functions for easy usage
@lru_cache(maxsize=1)
def get_secrets_manager() -> AWSSecretsManager:
    """Get a cached instance of AWSSecretsManager"""
    return AWSSecretsManager()


def get_database_config() -> Dict[str, Any]:
    """Convenience function to get database configuration"""
    return get_secrets_manager().get_database_config()


def get_jwt_config() -> Dict[str, Any]:
    """Convenience function to get JWT configuration"""
    return get_secrets_manager().get_jwt_config()


def get_mistral_api_key() -> str:
    """Convenience function to get Mistral API key"""
    return get_secrets_manager().get_mistral_api_key()


def test_aws_connection() -> bool:
    """Convenience function to test AWS connection"""
    return get_secrets_manager().test_connection()


if __name__ == "__main__":
    # Basic test when run directly
    logging.basicConfig(level=logging.INFO)
    
    try:
        secrets_manager = AWSSecretsManager()
        print("✅ AWS Secrets Manager initialized successfully")
        
        if secrets_manager.test_connection():
            print("✅ AWS connection test passed")
        else:
            print("❌ AWS connection test failed")
            
    except Exception as e:
        print(f"❌ Error: {e}")
