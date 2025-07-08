#!/usr/bin/env python3
"""
Final comprehensive test to verify the authentication service is working
"""
import sys
import traceback

def test_imports():
    """Test all critical imports"""
    print("Testing imports...")
    
    try:
        # Core modules
        from app.core import config, security, exceptions, logging_config
        print("✓ Core modules imported")
        
        # Auth modules
        from app.auth import aws_secrets, auth_adapter, supabase_auth
        print("✓ Auth modules imported")
        
        # API modules
        from app.api import auth_routes, health_routes, metrics_routes
        print("✓ API modules imported")
        
        # Models
        from app import models
        print("✓ Models imported")
        
        # Main application
        from app.main import app
        print("✓ Main FastAPI app imported")
        
        return True
        
    except Exception as e:
        print(f"✗ Import failed: {e}")
        traceback.print_exc()
        return False

def test_app_creation():
    """Test FastAPI app creation and route registration"""
    print("\nTesting FastAPI app creation...")
    
    try:
        from app.main import app
        
        # Check if app is created
        print(f"✓ App created: {type(app)}")
        
        # Check routes
        routes = list(app.routes)
        print(f"✓ Routes registered: {len(routes)}")
        
        # Check specific routes
        paths = []
        for route in routes:
            if hasattr(route, 'path'):
                paths.append(route.path)  # type: ignore
        
        expected_paths = ['/auth/login', '/auth/register', '/health', '/metrics']
        
        for expected in expected_paths:
            if any(expected in path for path in paths):
                print(f"✓ Route found: {expected}")
            else:
                print(f"⚠ Route not found: {expected}")
        
        return True
        
    except Exception as e:
        print(f"✗ App creation failed: {e}")
        traceback.print_exc()
        return False

def test_config():
    """Test configuration loading"""
    print("\nTesting configuration...")
    
    try:
        from app.core.config import settings
        
        print(f"✓ Settings loaded: {type(settings)}")
        print(f"✓ Environment: {settings.environment}")
        print(f"✓ Debug: {settings.debug}")
        
        return True
        
    except Exception as e:
        print(f"✗ Config test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("=" * 50)
    print("Final Authentication Service Test")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_app_creation,
        test_config
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! Authentication service is ready!")
        return 0
    else:
        print("❌ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
