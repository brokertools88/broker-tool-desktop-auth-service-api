#!/usr/bin/env python3
"""
Test script for AWS Secrets Manager integration
"""

import sys
import os
from pathlib import Path

# Add the app directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "app"))

from auth.aws_secrets import (
    AWSSecretsManager,
    AWSSecretsConfig,
    AWSSecretsManagerError,
    SecretNotFoundError,
    test_aws_connection
)


def main():
    """Main test function"""
    print("🔐 InsureCove AWS Secrets Manager Test")
    print("=" * 50)
    
    # Test 1: Configuration
    print("\n1. Testing Configuration...")
    config = AWSSecretsConfig()
    print(f"   AWS Region: {config.aws_region}")
    print(f"   Secret Prefix: {config.secret_prefix}")
    print(f"   Cache TTL: {config.cache_ttl}s")
    
    # Test 2: AWS Connection
    print("\n2. Testing AWS Connection...")
    try:
        connected = test_aws_connection()
        if connected:
            print("   ✅ Connected to AWS Secrets Manager")
        else:
            print("   ❌ Failed to connect to AWS Secrets Manager")
    except Exception as e:
        print(f"   ❌ Connection error: {e}")
    
    # Test 3: Initialize Secrets Manager
    print("\n3. Testing Secrets Manager Initialization...")
    try:
        secrets_manager = AWSSecretsManager()
        print("   ✅ Secrets Manager initialized successfully")
        
        # Test cache stats
        stats = secrets_manager.get_cache_stats()
        print(f"   Cache stats: {stats}")
        
    except Exception as e:
        print(f"   ❌ Failed to initialize Secrets Manager: {e}")
        return
    
    # Test 4: Test Connection Method
    print("\n4. Testing Connection Method...")
    try:
        if secrets_manager.test_connection():
            print("   ✅ Connection test passed")
        else:
            print("   ❌ Connection test failed")
    except Exception as e:
        print(f"   ❌ Connection test error: {e}")
    
    # Test 5: Try to retrieve a secret (will likely fail without real AWS setup)
    print("\n5. Testing Secret Retrieval...")
    try:
        secret = secrets_manager.get_secret("mistral-api-key")
        print(f"   ✅ Retrieved secret: {secret.secret_name}")
        print(f"   Version: {secret.version_id}")
    except SecretNotFoundError:
        print("   ℹ️  Secret not found (expected without real AWS setup)")
    except AWSSecretsManagerError as e:
        print(f"   ℹ️  AWS error (expected without credentials): {e}")
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
    
    # Test 6: Test specific convenience functions
    print("\n6. Testing Convenience Functions...")
    
    test_functions = [
        ("Database Config", secrets_manager.get_database_config),
        ("JWT Config", secrets_manager.get_jwt_config),
        ("Mistral API Key", secrets_manager.get_mistral_api_key),
    ]
    
    for name, func in test_functions:
        try:
            result = func()
            print(f"   ✅ {name}: Retrieved successfully")
        except (SecretNotFoundError, AWSSecretsManagerError):
            print(f"   ℹ️  {name}: Not found (expected without real AWS setup)")
        except Exception as e:
            print(f"   ❌ {name}: Error - {e}")
    
    print("\n" + "=" * 50)
    print("🏁 Test completed!")
    print("\nNote: Some failures are expected without proper AWS credentials and secrets setup.")


if __name__ == "__main__":
    main()
