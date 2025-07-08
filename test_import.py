#!/usr/bin/env python3
"""Test import script to check for issues"""

try:
    print("Testing imports...")
    
    print("1. Testing core imports...")
    from app.core import get_settings
    print("   ✅ get_settings imported")
    
    from app.core import settings  
    print("   ✅ settings imported")
    
    from app.core import jwt_manager, auth_dependency
    print("   ✅ security components imported")
    
    print("2. Testing auth imports...")
    from app.auth.auth_adapter import AuthManagerAdapter
    print("   ✅ AuthManagerAdapter imported")
    
    print("3. Testing models...")
    from app.models import UserResponse
    print("   ✅ models imported")
    
    print("4. Testing routes...")
    from app.api.auth_routes import router
    print("   ✅ auth routes imported")
    
    print("5. Testing main app...")
    from app.main import app
    print("   ✅ main app imported")
    
    print("\n🎉 All imports successful!")
    
except Exception as e:
    print(f"\n❌ Import failed: {e}")
    import traceback
    traceback.print_exc()
