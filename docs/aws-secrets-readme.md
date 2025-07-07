# AWS Secrets Manager Integration Guide

## 📋 Overview

This document provides a comprehensive guide for using AWS Secrets Manager in the InsureCove Authentication Service. The implementation provides secure storage and retrieval of sensitive configuration data including API keys, database credentials, JWT signing keys, and other sensitive information.

## 🏗️ Architecture

The AWS Secrets Manager integration consists of:

- **`AWSSecretsManager`**: Core class for interacting with AWS Secrets Manager
- **`AWSSecretsConfig`**: Configuration management using Pydantic settings
- **`SecretValue`**: Data container for secret values with metadata
- **Caching Layer**: In-memory caching for performance optimization
- **Error Handling**: Comprehensive error handling with custom exceptions
- **Proxy Support**: Corporate network proxy configuration

## 🚀 Quick Start

### 1. Installation

The required dependencies are already included in `requirements.txt`:

```txt
boto3==1.29.0
botocore==1.32.0
pydantic-settings==2.1.0
```

### 2. Configuration

Create a `.env` file based on `.env.example`:

```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_DEFAULT_REGION=ap-east-1

# Proxy Configuration (if needed)
HTTP_PROXY=http://proxy.example.com:8080
HTTPS_PROXY=https://proxy.example.com:8080

# Secrets Configuration
SECRET_PREFIX=insurecove
SECRET_CACHE_TTL=300
```

### 3. Basic Usage

```python
from app.auth.aws_secrets import AWSSecretsManager

# Initialize the secrets manager
secrets_manager = AWSSecretsManager()

# Test connection
if secrets_manager.test_connection():
    print("✅ Connected to AWS Secrets Manager")

# Retrieve a secret
try:
    secret = secrets_manager.get_secret("mistral-api-key")
    api_key = secret.as_string()
    print(f"API Key: {api_key}")
except SecretNotFoundError:
    print("Secret not found")
```

## 🔐 Available Secrets

The following secrets are available in AWS Secrets Manager:

### 1. Mistral AI API Key
- **Secret Name**: `insurecove/mistral-api-key`
- **Usage**: AI/ML model integration
- **Format**: String

### 2. Database Configuration
- **Secret Name**: `insurecove/production/database`
- **Usage**: Supabase database connection
- **Format**: JSON with fields:
  - `supabase_url`
  - `supabase_anon_key`
  - `supabase_service_key`
  - `database_password`

### 3. JWT Configuration
- **Secret Name**: `insurecove/production/jwt`
- **Usage**: JWT token signing and verification
- **Format**: JSON with fields:
  - `jwt_secret_key`
  - `jwt_algorithm` (HS256)
  - `jwt_issuer`
  - `jwt_audience`
  - `jwt_access_token_expire_minutes`

### 4. AWS Services Configuration
- **Secret Name**: `insurecove/production/aws-services`
- **Usage**: AWS service configuration
- **Format**: JSON with fields:
  - `aws_ses_region`
  - `aws_end_user_messaging_region`
  - `s3_bucket_name`
  - `max_file_size_mb`

### 5. Security Configuration
- **Secret Name**: `insurecove/production/security`
- **Usage**: Application security settings
- **Format**: JSON with fields:
  - `encryption_key`
  - `encryption_salt`
  - `allowed_hosts`
  - `cors_origins`

## 📚 API Reference

### AWSSecretsManager Class

#### Methods

##### `__init__(config: Optional[AWSSecretsConfig] = None)`
Initialize the AWS Secrets Manager client.

##### `get_secret(secret_name: str, version_id: Optional[str] = None, use_cache: bool = True) -> SecretValue`
Retrieve a secret from AWS Secrets Manager.

**Parameters:**
- `secret_name`: Name of the secret (without prefix)
- `version_id`: Specific version to retrieve (optional)
- `use_cache`: Whether to use cached value (default: True)

**Returns:** `SecretValue` object containing the secret data

**Raises:**
- `SecretNotFoundError`: Secret doesn't exist
- `SecretAccessDeniedError`: Access denied
- `AWSSecretsManagerError`: Other AWS errors

##### `test_connection() -> bool`
Test connection to AWS Secrets Manager.

##### `clear_cache()`
Clear the secrets cache.

##### `get_cache_stats() -> Dict[str, Any]`
Get cache statistics including total entries, valid entries, and expired entries.

### Convenience Methods

##### `get_database_config() -> Dict[str, Any]`
Get database configuration as a dictionary.

##### `get_jwt_config() -> Dict[str, Any]`
Get JWT configuration as a dictionary.

##### `get_mistral_api_key() -> str`
Get Mistral API key as a string.

### SecretValue Class

#### Properties
- `value`: The secret value (string or dict)
- `version_id`: Version identifier
- `created_date`: Creation timestamp
- `secret_name`: Full secret name

#### Methods
- `as_dict()`: Convert JSON secret to dictionary
- `as_string()`: Convert secret to string representation

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AWS_ACCESS_KEY_ID` | AWS access key ID | None | Yes* |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key | None | Yes* |
| `AWS_DEFAULT_REGION` | AWS region | ap-east-1 | No |
| `HTTP_PROXY` | HTTP proxy URL | None | No |
| `HTTPS_PROXY` | HTTPS proxy URL | None | No |
| `SECRET_PREFIX` | Secret name prefix | insurecove | No |
| `SECRET_CACHE_TTL` | Cache TTL in seconds | 300 | No |

*Required unless using IAM roles or other AWS authentication methods.

### Proxy Configuration

For corporate networks requiring proxy:

```python
config = AWSSecretsConfig(
    http_proxy="http://proxy.company.com:8080",
    https_proxy="https://proxy.company.com:8080"
)
secrets_manager = AWSSecretsManager(config)
```

## ⚡ Performance Features

### Caching

- **In-memory caching**: Reduces AWS API calls
- **TTL-based expiration**: Configurable cache timeout
- **Per-secret caching**: Each secret cached independently
- **Cache statistics**: Monitor cache performance

### Connection Pooling

- **Persistent connections**: Reuses AWS client connections
- **Lazy initialization**: Client created only when needed

## 🛡️ Security Best Practices

### 1. Credentials Management
- **Use IAM roles** in production instead of access keys
- **Rotate credentials** regularly
- **Use least privilege** access policies

### 2. Network Security
- **Use HTTPS proxy** when required
- **Restrict network access** to AWS endpoints
- **Monitor access logs**

### 3. Application Security
- **Clear sensitive data** from memory when possible
- **Use caching judiciously** for sensitive secrets
- **Log access patterns** for monitoring

## 🚨 Error Handling

### Exception Hierarchy

```
AWSSecretsManagerError (base)
├── SecretNotFoundError
├── SecretAccessDeniedError
└── AWSSecretsManagerError (other AWS errors)
```

### Error Handling Example

```python
from app.auth.aws_secrets import (
    AWSSecretsManager,
    SecretNotFoundError,
    SecretAccessDeniedError,
    AWSSecretsManagerError
)

try:
    secret = secrets_manager.get_secret("my-secret")
    value = secret.as_dict()
except SecretNotFoundError:
    logger.error("Secret not found - check secret name")
except SecretAccessDeniedError:
    logger.error("Access denied - check IAM permissions")
except AWSSecretsManagerError as e:
    logger.error(f"AWS error: {e}")
except Exception as e:
    logger.error(f"Unexpected error: {e}")
```

## 🧪 Testing

### Unit Tests

Run the AWS Secrets Manager tests:

```bash
# Test the implementation
py -3 test_aws_secrets_new.py

# Run with debugging
py -3 -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from app.auth.aws_secrets import AWSSecretsManager
secrets_manager = AWSSecretsManager()
print('✅ Success' if secrets_manager.test_connection() else '❌ Failed')
"
```

### Integration Tests

```python
def test_secret_retrieval():
    """Test secret retrieval with real AWS"""
    secrets_manager = AWSSecretsManager()
    
    # Test connection
    assert secrets_manager.test_connection()
    
    # Test secret retrieval
    secret = secrets_manager.get_secret("mistral-api-key")
    assert secret.value is not None
    
    # Test caching
    secret2 = secrets_manager.get_secret("mistral-api-key")
    assert secret.value == secret2.value
```

## 🔍 Monitoring & Debugging

### Logging

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Now all AWS operations will be logged
secrets_manager = AWSSecretsManager()
```

### Cache Monitoring

```python
# Get cache statistics
stats = secrets_manager.get_cache_stats()
print(f"Cache entries: {stats['total_entries']}")
print(f"Valid entries: {stats['valid_entries']}")
print(f"Cache hit ratio: {stats['valid_entries'] / max(1, stats['total_entries']):.2%}")
```

### Health Checks

```python
def health_check():
    """Application health check including AWS connectivity"""
    try:
        secrets_manager = AWSSecretsManager()
        if not secrets_manager.test_connection():
            return {"status": "unhealthy", "aws_secrets": "disconnected"}
        
        cache_stats = secrets_manager.get_cache_stats()
        return {
            "status": "healthy",
            "aws_secrets": "connected",
            "cache_stats": cache_stats
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
```

## 🚀 Production Deployment

### IAM Policy

Recommended IAM policy for production:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SecretsManagerAccess",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret"
            ],
            "Resource": [
                "arn:aws:secretsmanager:ap-east-1:150248166610:secret:insurecove/*"
            ]
        }
    ]
}
```

### Environment Configuration

Production environment variables:

```bash
# Use IAM roles instead of access keys
AWS_DEFAULT_REGION=ap-east-1
SECRET_PREFIX=insurecove
SECRET_CACHE_TTL=300
LOG_LEVEL=INFO
```

### Docker Configuration

```dockerfile
# Install AWS CLI for debugging (optional)
RUN pip install awscli

# Set environment variables
ENV AWS_DEFAULT_REGION=ap-east-1
ENV SECRET_PREFIX=insurecove
ENV SECRET_CACHE_TTL=300
```

## 📖 Examples

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from app.auth.aws_secrets import get_database_config, get_jwt_config

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    """Initialize secrets on startup"""
    try:
        db_config = get_database_config()
        jwt_config = get_jwt_config()
        print("✅ Secrets loaded successfully")
    except Exception as e:
        print(f"❌ Failed to load secrets: {e}")
        raise

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        from app.auth.aws_secrets import test_aws_connection
        aws_healthy = test_aws_connection()
        return {
            "status": "healthy" if aws_healthy else "degraded",
            "aws_secrets": "connected" if aws_healthy else "disconnected"
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
```

### Database Connection

```python
from app.auth.aws_secrets import get_database_config
from supabase import create_client, Client

def create_supabase_client() -> Client:
    """Create Supabase client using secrets"""
    config = get_database_config()
    
    supabase: Client = create_client(
        config["supabase_url"],
        config["supabase_anon_key"]
    )
    return supabase
```

### JWT Configuration

```python
from app.auth.aws_secrets import get_jwt_config
import jwt

def create_access_token(data: dict) -> str:
    """Create JWT access token"""
    config = get_jwt_config()
    
    return jwt.encode(
        data,
        config["jwt_secret_key"],
        algorithm=config["jwt_algorithm"]
    )
```

## 🔗 Related Documentation

- [AWS Secrets Setup Guide](./secrets/aws-secrets-setup-guideline.md)
- [Secrets Created Summary](./secrets/secrets-created-summary.md)
- [Setup Guide](./secrets/SETUP-GUIDE.md)
- [Project Design](./design/auth-service-design.md)

## 🆘 Troubleshooting

### Common Issues

#### 1. Connection Timeouts
```bash
Error: Could not connect to the endpoint URL
```
**Solutions:**
- Check internet connectivity
- Verify proxy configuration
- Confirm AWS region settings
- Check firewall rules

#### 2. Access Denied
```bash
Error: AccessDeniedException
```
**Solutions:**
- Verify AWS credentials
- Check IAM permissions
- Confirm secret ARN
- Review resource policies

#### 3. Secret Not Found
```bash
Error: ResourceNotFoundException
```
**Solutions:**
- Verify secret name and prefix
- Check AWS region
- Confirm secret exists in AWS console
- Validate secret naming convention

#### 4. Import Errors
```bash
ImportError: cannot import name 'BaseSettings'
```
**Solutions:**
- Update pydantic: `pip install pydantic-settings`
- Check Python version compatibility
- Verify requirements.txt dependencies

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from app.auth.aws_secrets import AWSSecretsManager
secrets_manager = AWSSecretsManager()
```

---

## 📄 License

This implementation is part of the InsureCove Authentication Service and follows the project's licensing terms.

## 🤝 Contributing

When contributing to the AWS Secrets Manager integration:

1. **Test thoroughly** with different AWS configurations
2. **Update documentation** for any API changes
3. **Follow security best practices**
4. **Add comprehensive error handling**
5. **Include unit tests** for new functionality

---

*Last updated: July 7, 2025*