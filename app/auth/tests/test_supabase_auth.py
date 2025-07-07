#!/usr/bin/env python3
"""
Test script for Supabase Authentication integration
"""

import sys
import asyncio
from pathlib import Path

# Add app directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "app"))

from auth.supabase_auth import (
    SupabaseAuthManager,
    LoginRequest,
    RegisterRequest,
    UserRole,
    AuthenticationError,
    TokenError,
    get_auth_manager
)


async def test_auth_manager():
    """Test the Supabase Auth Manager"""
    print("🔐 InsureCove Supabase Authentication Test")
    print("=" * 50)
    
    # Test 1: Initialize Auth Manager
    print("\n1. Testing Auth Manager Initialization...")
    try:
        auth_manager = get_auth_manager()
        print("   ✅ Auth Manager initialized successfully")
    except Exception as e:
        print(f"   ❌ Failed to initialize Auth Manager: {e}")
        return
    
    # Test 2: Configuration Loading
    print("\n2. Testing Configuration Loading...")
    try:
        db_config = auth_manager._get_database_config()
        jwt_config = auth_manager._get_jwt_config()
        print("   ✅ Database and JWT configurations loaded")
        print(f"   Database config keys: {list(db_config.keys())}")
        print(f"   JWT config keys: {list(jwt_config.keys())}")
    except Exception as e:
        print(f"   ❌ Configuration loading failed: {e}")
        return
    
    # Test 3: Supabase Client Initialization
    print("\n3. Testing Supabase Client...")
    try:
        supabase_client = auth_manager._get_supabase_client()
        print("   ✅ Supabase client initialized successfully")
    except Exception as e:
        print(f"   ❌ Supabase client initialization failed: {e}")
        print("   (This is expected without proper Supabase credentials)")
    
    # Test 4: JWT Token Generation (Mock User)
    print("\n4. Testing JWT Token Generation...")
    try:
        from auth.supabase_auth import AuthUser, TokenType
        from datetime import datetime, timezone
        
        # Create a mock user
        mock_user = AuthUser(
            id="test-user-123",
            email="test@insurecove.com",
            role=UserRole.USER,
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
        
        # Generate access token
        access_token = auth_manager._generate_jwt_token(mock_user, TokenType.ACCESS)
        print(f"   ✅ Access token generated: {len(access_token)} characters")
        
        # Generate refresh token
        refresh_token = auth_manager._generate_jwt_token(mock_user, TokenType.REFRESH)
        print(f"   ✅ Refresh token generated: {len(refresh_token)} characters")
        
        # Generate service token
        service_token = auth_manager._generate_jwt_token(mock_user, TokenType.SERVICE)
        print(f"   ✅ Service token generated: {len(service_token)} characters")
        
    except Exception as e:
        print(f"   ❌ JWT token generation failed: {e}")
    
    # Test 5: JWT Token Verification
    print("\n5. Testing JWT Token Verification...")
    try:
        # Verify the access token we just generated
        payload = auth_manager._verify_jwt_token(access_token, TokenType.ACCESS)
        print("   ✅ Access token verification successful")
        print(f"   Token payload: user_id={payload.get('user_id')}, email={payload.get('email')}")
        
        # Test invalid token
        try:
            auth_manager._verify_jwt_token("invalid-token")
            print("   ❌ Invalid token should have failed")
        except TokenError:
            print("   ✅ Invalid token correctly rejected")
            
    except Exception as e:
        print(f"   ❌ JWT token verification failed: {e}")
    
    # Test 6: User Registration (Mock)
    print("\n6. Testing User Registration Flow...")
    try:
        register_request = RegisterRequest(
            email="testuser@insurecove.com",
            password="SecurePassword123!",
            full_name="Test User",
            role=UserRole.USER
        )
        
        # This will likely fail without real Supabase setup
        try:
            response = await auth_manager.register_user(register_request)
            print("   ✅ User registration successful")
            print(f"   Access token: {len(response.access_token)} chars")
            print(f"   User ID: {response.user['user_id']}")
        except AuthenticationError as e:
            print(f"   ℹ️  Registration failed (expected without Supabase): {e}")
        except Exception as e:
            print(f"   ℹ️  Registration error (expected): {e}")
            
    except Exception as e:
        print(f"   ❌ Registration test setup failed: {e}")
    
    # Test 7: User Authentication (Mock)
    print("\n7. Testing User Authentication Flow...")
    try:
        login_request = LoginRequest(
            email="testuser@insurecove.com",
            password="SecurePassword123!",
            remember_me=False
        )
        
        # This will likely fail without real Supabase setup
        try:
            response = await auth_manager.authenticate_user(login_request)
            print("   ✅ User authentication successful")
            print(f"   Access token: {len(response.access_token)} chars")
        except AuthenticationError as e:
            print(f"   ℹ️  Authentication failed (expected without Supabase): {e}")
        except Exception as e:
            print(f"   ℹ️  Authentication error (expected): {e}")
            
    except Exception as e:
        print(f"   ❌ Authentication test setup failed: {e}")
    
    # Test 8: Password Utilities
    print("\n8. Testing Password Utilities...")
    try:
        from auth.supabase_auth import get_password_hash, verify_password
        
        password = "TestPassword123!"
        hashed = get_password_hash(password)
        print(f"   ✅ Password hashed: {len(hashed)} characters")
        
        # Verify correct password
        if verify_password(password, hashed):
            print("   ✅ Password verification successful")
        else:
            print("   ❌ Password verification failed")
        
        # Verify incorrect password
        if not verify_password("WrongPassword", hashed):
            print("   ✅ Incorrect password correctly rejected")
        else:
            print("   ❌ Incorrect password incorrectly accepted")
            
    except Exception as e:
        print(f"   ❌ Password utilities test failed: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 Supabase Authentication Test Completed!")
    print("\nNote: Some failures are expected without proper Supabase configuration.")


async def test_convenience_functions():
    """Test convenience functions"""
    print("\n" + "=" * 50)
    print("🔧 Testing Convenience Functions")
    print("=" * 50)
    
    # Test singleton auth manager
    print("\n1. Testing Singleton Auth Manager...")
    try:
        auth1 = get_auth_manager()
        auth2 = get_auth_manager()
        
        if auth1 is auth2:
            print("   ✅ Singleton pattern working correctly")
        else:
            print("   ❌ Singleton pattern not working")
    except Exception as e:
        print(f"   ❌ Singleton test failed: {e}")
    
    # Test authenticate_request function
    print("\n2. Testing Request Authentication...")
    try:
        from auth.supabase_auth import authenticate_request
        
        # This will fail without a valid token
        try:
            await authenticate_request("Bearer invalid-token")
            print("   ❌ Invalid token should have failed")
        except TokenError:
            print("   ✅ Invalid token correctly rejected")
        except Exception as e:
            print(f"   ℹ️  Expected error: {e}")
            
    except Exception as e:
        print(f"   ❌ Request authentication test failed: {e}")


if __name__ == "__main__":
    async def main():
        await test_auth_manager()
        await test_convenience_functions()
    
    asyncio.run(main())
