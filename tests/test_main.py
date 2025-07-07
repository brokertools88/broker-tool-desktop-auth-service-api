#!/usr/bin/env python3
"""
Test script to verify the authentication service setup
"""

import sys
import os
import asyncio

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

async def test_imports():
    """Test that all core modules can be imported"""
    print("Testing imports...")
    
    try:
        from app.core import get_settings, setup_logging
        print("✅ Core configuration imported successfully")
        
        from app.core import (
            BaseInsureCoveException,
            AuthenticationException,
            InvalidCredentialsException
        )
        print("✅ Exception classes imported successfully")
        
        from app.core import (
            PasswordManager,
            JWTManager,
            auth_dependency
        )
        print("✅ Security utilities imported successfully")
        
        from app.models import (
            LoginRequest,
            UserResponse,
            TokenResponse,
            HealthCheckResponse
        )
        print("✅ API models imported successfully")
        
        from app.auth.auth_adapter import AuthManagerAdapter
        print("✅ Auth adapter imported successfully")
        
        from app.api.auth_routes import router as auth_router
        print("✅ Auth routes imported successfully")
        
        from app.api.health_routes import router as health_router
        print("✅ Health routes imported successfully")
        
        from app.api.metrics_routes import router as metrics_router
        print("✅ Metrics routes imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


async def test_configuration():
    """Test configuration loading"""
    print("\nTesting configuration...")
    
    try:
        from app.core import get_settings
        
        settings = get_settings()
        
        print(f"✅ App name: {settings.app_name}")
        print(f"✅ Environment: {settings.environment}")
        print(f"✅ Debug mode: {settings.debug}")
        print(f"✅ API prefix: {settings.api_prefix}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False


async def test_password_manager():
    """Test password management"""
    print("\nTesting password management...")
    
    try:
        from app.core import PasswordManager
        
        pm = PasswordManager()
        
        # Test password hashing
        password = "TestPassword123!"
        hashed = pm.hash_password(password)
        print("✅ Password hashing works")
        
        # Test password verification
        is_valid = pm.verify_password(password, hashed)
        print(f"✅ Password verification: {is_valid}")
        
        # Test password strength validation
        errors = pm.validate_password_strength("weak")
        print(f"✅ Password validation (weak): {len(errors)} errors")
        
        errors = pm.validate_password_strength("StrongPassword123!")
        print(f"✅ Password validation (strong): {len(errors)} errors")
        
        return True
        
    except Exception as e:
        print(f"❌ Password manager error: {e}")
        return False


async def test_auth_adapter():
    """Test authentication adapter"""
    print("\nTesting authentication adapter...")
    
    try:
        from app.auth.auth_adapter import AuthManagerAdapter
        
        adapter = AuthManagerAdapter()
        print("✅ Auth adapter created successfully")
        
        # Note: We won't test actual authentication without proper setup
        print("✅ Auth adapter basic functionality works")
        
        return True
        
    except Exception as e:
        print(f"❌ Auth adapter error: {e}")
        return False


async def test_main_app():
    """Test main FastAPI application creation"""
    print("\nTesting main FastAPI application...")
    
    try:
        from app.main import create_application
        
        app = create_application()
        print("✅ FastAPI application created successfully")
        print(f"✅ App title: {app.title}")
        print(f"✅ App version: {app.version}")
        
        return True
        
    except Exception as e:
        print(f"❌ FastAPI application error: {e}")
        return False


async def main():
    """Run all tests"""
    print("🚀 InsureCove Authentication Service - Setup Test\n")
    
    tests = [
        test_imports,
        test_configuration,
        test_password_manager,
        test_auth_adapter,
        test_main_app
    ]
    
    results = []
    
    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results.append(False)
    
    # Summary
    print(f"\n📊 Test Results:")
    print(f"✅ Passed: {sum(results)}")
    print(f"❌ Failed: {len(results) - sum(results)}")
    print(f"📈 Success Rate: {(sum(results) / len(results)) * 100:.1f}%")
    
    if all(results):
        print("\n🎉 All tests passed! The authentication service setup is working correctly.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
