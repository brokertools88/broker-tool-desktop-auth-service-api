#!/usr/bin/env python3
"""
Generate and store a secure JWT secret key in AWS Secrets Manager
"""

import os
import secrets
import string
import json
import subprocess
import sys
from datetime import datetime

def generate_secure_jwt_key(length=64):
    """Generate a cryptographically secure JWT secret key"""
    # Use a mix of letters, digits, and special characters for maximum entropy
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Generate secure random key
    secret_key = ''.join(secrets.choice(alphabet) for _ in range(length))
    return secret_key

def create_jwt_config(secret_key):
    """Create JWT configuration JSON"""
    jwt_config = {
        "jwt_secret_key": secret_key,
        "jwt_algorithm": "HS256",
        "jwt_issuer": "insurecove-auth",
        "jwt_audience": "insurecove-api", 
        "jwt_access_token_expire_minutes": 30,
        "jwt_refresh_token_expire_days": 7,
        "generated_at": datetime.now().isoformat(),
        "key_version": "v2.0"
    }
    return jwt_config

def update_aws_secret(jwt_config, proxy_url="<PROXY_URL>"):
    """Update the JWT secret in AWS Secrets Manager"""
    
    # Set proxy environment variables
    env = os.environ.copy()
    if proxy_url:
        env['HTTP_PROXY'] = proxy_url
        env['HTTPS_PROXY'] = proxy_url
    
    # Convert config to JSON string
    secret_string = json.dumps(jwt_config)
    
    # AWS CLI command to update the secret
    cmd = [
        "python", "-m", "awscli", "secretsmanager", "update-secret",
        "--secret-id", "insurecove/production/jwt",
        "--secret-string", secret_string,
        "--region", "ap-east-1",
        "--description", "InsureCove JWT signing configuration - Updated " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ]
    
    try:
        print("🔄 Updating JWT secret in AWS Secrets Manager...")
        print(f"   Secret ID: insurecove/production/jwt")
        print(f"   Region: ap-east-1")
        print(f"   Proxy: {proxy_url}")
        
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            response = json.loads(result.stdout)
            print("✅ JWT secret updated successfully!")
            print(f"   Secret ARN: {response.get('ARN', 'N/A')}")
            print(f"   Version ID: {response.get('VersionId', 'N/A')}")
            return True
        else:
            print("❌ Failed to update JWT secret!")
            print(f"   Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ AWS CLI command timed out!")
        return False
    except json.JSONDecodeError:
        print("❌ Invalid response from AWS CLI!")
        print(f"   Output: {result.stdout}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_secret_retrieval():
    """Test retrieving the secret to verify it was stored correctly"""
    
    env = os.environ.copy()
    env['HTTP_PROXY'] = "<HTTP_PROXY>"
    env['HTTPS_PROXY'] = "<HTTPS_PROXY>"
    
    cmd = [
        "python", "-m", "awscli", "secretsmanager", "get-secret-value",
        "--secret-id", "insurecove/production/jwt",
        "--region", "ap-east-1",
        "--query", "SecretString",
        "--output", "text"
    ]
    
    try:
        print("\n🧪 Testing secret retrieval...")
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            retrieved_config = json.loads(result.stdout)
            print("✅ Secret retrieval test passed!")
            print(f"   Algorithm: {retrieved_config.get('jwt_algorithm')}")
            print(f"   Issuer: {retrieved_config.get('jwt_issuer')}")
            print(f"   Audience: {retrieved_config.get('jwt_audience')}")
            print(f"   Token Expiry: {retrieved_config.get('jwt_access_token_expire_minutes')} minutes")
            print(f"   Generated At: {retrieved_config.get('generated_at')}")
            print(f"   Key Version: {retrieved_config.get('key_version')}")
            print(f"   Secret Key Length: {len(retrieved_config.get('jwt_secret_key', ''))} characters")
            return True
        else:
            print("❌ Secret retrieval test failed!")
            print(f"   Error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Test error: {e}")
        return False

def main():
    """Main function to generate and store JWT secret"""
    print("🔐 JWT Secret Key Generator for InsureCove")
    print("=" * 50)
    
    # Step 1: Generate secure key
    print("\n1. Generating secure JWT secret key...")
    secret_key = generate_secure_jwt_key(64)  # 64 characters = 384 bits
    print(f"   ✅ Generated {len(secret_key)}-character secret key")
    print(f"   Key preview: {secret_key[:8]}...{secret_key[-8:]}")
    
    # Step 2: Create JWT configuration
    print("\n2. Creating JWT configuration...")
    jwt_config = create_jwt_config(secret_key)
    print("   ✅ JWT configuration created")
    print(f"   Algorithm: {jwt_config['jwt_algorithm']}")
    print(f"   Issuer: {jwt_config['jwt_issuer']}")
    print(f"   Audience: {jwt_config['jwt_audience']}")
    print(f"   Access Token Expiry: {jwt_config['jwt_access_token_expire_minutes']} minutes")
    
    # Step 3: Confirm before updating AWS
    print("\n⚠️  This will update the JWT secret in AWS Secrets Manager!")
    print("   Secret: insurecove/production/jwt")
    print("   Region: ap-east-1")
    
    confirm = input("\n   Continue? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print("   Operation cancelled.")
        return
    
    # Step 4: Update AWS Secrets Manager
    print("\n3. Updating AWS Secrets Manager...")
    success = update_aws_secret(jwt_config)
    
    if not success:
        print("\n❌ Failed to update AWS secret!")
        return
    
    # Step 5: Test retrieval
    test_success = test_secret_retrieval()
    
    # Summary
    print("\n" + "=" * 50)
    if success and test_success:
        print("🎉 JWT Secret Key Successfully Generated and Stored!")
        print("\n📝 Summary:")
        print(f"   • Secret Location: AWS Secrets Manager")
        print(f"   • Secret Name: insurecove/production/jwt")
        print(f"   • Key Length: {len(secret_key)} characters")
        print(f"   • Algorithm: HS256")
        print(f"   • Generated: {jwt_config['generated_at']}")
        print(f"   • Version: {jwt_config['key_version']}")
        
        print("\n🔒 Security Notes:")
        print("   • The secret key is now stored securely in AWS")
        print("   • Previous tokens signed with old key will be invalid")
        print("   • Your application will automatically use the new key")
        print("   • Consider restarting your application to refresh cached config")
        
    else:
        print("❌ Operation completed with errors!")
        print("   Please check the error messages above and try again.")

if __name__ == "__main__":
    main()
