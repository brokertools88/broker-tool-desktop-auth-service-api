# 🔗 InsureCove Authentication Service - File Linkage Documentation

## 📋 **Overview**

This document provides a comprehensive guide to each Python file in the authentication service, their purposes, dependencies, and how they link together to form a cohesive system.

---

## 🏠 **Main Application Entry Point**

### **📄 `app/main.py`** - FastAPI Application Entry Point

**Purpose**: Main FastAPI application with middleware, error handlers, and route registration.

**Key Functions**:
- Application lifecycle management
- Middleware configuration (CORS, security, logging)
- Exception handler registration
- Route mounting and API versioning
- Health and metrics integration

**Dependencies**:
```python
# Internal dependencies
from app.core.config import get_settings
from app.core.logging_config import setup_logging, RequestLoggingMiddleware
from app.core.security import SecurityMiddleware
from app.core.exceptions import (exception handlers)
from app.api.auth_routes import router as auth_router
from app.api.health_routes import router as health_router
from app.api.metrics_routes import router as metrics_router

# External dependencies
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
```

**Links to**:
- All route modules (`app/api/*.py`)
- All core modules (`app/core/*.py`)
- Configuration and settings management

**Used by**:
- ASGI server (uvicorn/gunicorn)
- Docker container startup
- Development server

---

## 🎯 **Core System Components**

### **📄 `app/core/config.py`** - Configuration Management

**Purpose**: Centralized configuration using Pydantic Settings with environment variable support.

**Key Classes**:
- `Settings`: Main configuration class
- Environment-based configuration loading
- Type validation and default values
- Secret management integration

**Dependencies**:
```python
from pydantic import BaseSettings, Field, validator
from typing import List, Optional, Union
import os
```

**Links to**:
- `app/auth/aws_secrets.py` (for secret retrieval)
- All other modules (for configuration access)

**Used by**:
- Every module that needs configuration
- `get_settings()` dependency injection

---

### **📄 `app/core/exceptions.py`** - Exception Handling

**Purpose**: RFC 9457-compliant error handling with structured exception hierarchy.

**Key Classes**:
- `BaseInsureCoveException`: Base exception class
- `ValidationException`, `AuthenticationException`, etc.
- `ProblemDetails`: RFC 9457 error response model
- Exception handlers for FastAPI

**Dependencies**:
```python
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
```

**Links to**:
- `app/models.py` (for error response models)
- `app/core/logging_config.py` (for error logging)

**Used by**:
- All route modules for error handling
- `app/main.py` for exception handler registration
- Business logic modules for raising specific errors

---

### **📄 `app/core/security.py`** - Security and JWT Management

**Purpose**: Security utilities, password hashing, JWT token management, and security middleware.

**Key Functions**:
- Password hashing and verification (bcrypt)
- JWT token creation and validation
- Security middleware implementation
- Rate limiting support

**Dependencies**:
```python
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from app.core.config import get_settings
from app.auth.aws_secrets import get_secret
```

**Links to**:
- `app/core/config.py` (for security settings)
- `app/auth/aws_secrets.py` (for JWT signing keys)
- `app/core/exceptions.py` (for security exceptions)

**Used by**:
- `app/auth/supabase_auth.py` (for password operations)
- `app/api/auth_routes.py` (for JWT operations)
- `app/main.py` (for security middleware)

---

### **📄 `app/core/logging_config.py`** - Logging Configuration

**Purpose**: Structured logging setup with correlation IDs, security event logging, and performance monitoring.

**Key Components**:
- Structured JSON logging
- Request/response logging middleware
- Security event logging
- Performance monitoring
- Log correlation IDs

**Dependencies**:
```python
import logging
import time
import uuid
from fastapi import Request, Response
from typing import Callable, Dict, Any
```

**Links to**:
- `app/core/config.py` (for logging settings)
- All modules (for logging instances)

**Used by**:
- `app/main.py` (for logging middleware)
- All route and business logic modules
- Error handling and monitoring

---

## 📋 **API Models and Schemas**

### **📄 `app/models.py`** - Pydantic API Models

**Purpose**: All Pydantic models for API requests, responses, and data validation.

**Key Model Categories**:
- **Request Models**: `BrokerCreateRequest`, `ClientCreateRequest`, `LoginRequest`, etc.
- **Response Models**: `LoginResponse`, `UserCreateResponse`, `SessionResponse`, etc.
- **Base Models**: `ResponseModel`, `UserResponse`, `TokenResponse`
- **Validation Models**: Password strength, email validation, etc.

**Dependencies**:
```python
from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum
```

**Links to**:
- All API route modules (for request/response typing)
- `app/core/exceptions.py` (for error models)

**Used by**:
- All route modules (`app/api/*.py`)
- `app/auth/auth_adapter.py` (for data transformation)
- API documentation generation

---

## 🔐 **Authentication Layer**

### **📄 `app/auth/supabase_auth.py`** - Supabase Integration

**Purpose**: Core authentication logic using Supabase for user management and authentication.

**Key Classes**:
- `SupabaseAuthManager`: Main authentication manager
- User registration and login
- Password reset functionality
- Session management
- JWT token generation

**Dependencies**:
```python
from supabase import create_client, Client
from app.core.config import get_settings
from app.core.security import get_password_hash, verify_password, create_access_token
from app.auth.aws_secrets import get_secret
```

**Links to**:
- `app/core/config.py` (for Supabase settings)
- `app/core/security.py` (for password and JWT operations)
- `app/auth/aws_secrets.py` (for secret retrieval)
- `app/core/exceptions.py` (for authentication errors)

**Used by**:
- `app/auth/auth_adapter.py` (for API integration)
- Direct integration in route handlers

---

### **📄 `app/auth/aws_secrets.py`** - AWS Secrets Manager

**Purpose**: Secure retrieval of secrets from AWS Secrets Manager with caching and proxy support.

**Key Functions**:
- `get_secret()`: Retrieve secrets from AWS
- Secret caching for performance
- Proxy configuration support
- Error handling and retry logic

**Dependencies**:
```python
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import json
import os
from typing import Dict, Any, Optional
```

**Links to**:
- `app/core/config.py` (for AWS settings)
- `app/core/logging_config.py` (for logging)
- `app/core/exceptions.py` (for AWS-related errors)

**Used by**:
- `app/core/security.py` (for JWT signing keys)
- `app/auth/supabase_auth.py` (for Supabase credentials)
- `app/core/config.py` (for configuration secrets)

---

### **📄 `app/auth/auth_adapter.py`** - Authentication Adapter

**Purpose**: Adapter pattern to bridge SupabaseAuthManager with API models and provide a clean interface.

**Key Functions**:
- Convert between internal auth models and API models
- Standardize response formats
- Handle authentication business logic
- Provide clean API for route handlers

**Dependencies**:
```python
from app.auth.supabase_auth import SupabaseAuthManager
from app.models import (all API models)
from app.core.exceptions import (authentication exceptions)
from typing import Dict, Any, Optional
```

**Links to**:
- `app/auth/supabase_auth.py` (for core auth operations)
- `app/models.py` (for API model conversion)
- `app/core/exceptions.py` (for error handling)

**Used by**:
- All authentication route handlers
- Business logic that needs user operations

---

## 🌐 **API Route Modules**

### **📄 `app/api/auth_routes.py`** - Authentication Endpoints

**Purpose**: RESTful authentication endpoints following 2024 API standards.

**Key Endpoints**:
- `POST /auth/brokers` - Create broker account
- `POST /auth/clients` - Create client account
- `POST /auth/sessions` - Login/authenticate
- `GET /auth/sessions/current` - Get current session
- `DELETE /auth/sessions` - Logout
- `POST /auth/tokens/refresh` - Refresh access token
- `POST /auth/tokens/verify` - Verify token
- `POST /auth/password/*` - Password management

**Dependencies**:
```python
from fastapi import APIRouter, Depends, HTTPException, Request, status
from app.auth.auth_adapter import AuthManagerAdapter
from app.models import (all auth-related models)
from app.core import (auth_dependency, security_logger, exceptions)
```

**Links to**:
- `app/auth/auth_adapter.py` (for authentication operations)
- `app/models.py` (for request/response models)
- `app/core/security.py` (for JWT dependency)
- `app/core/exceptions.py` (for error handling)

**Used by**:
- `app/main.py` (route registration)
- Client applications (API consumers)

---

### **📄 `app/api/health_routes.py`** - Health Check Endpoints

**Purpose**: Comprehensive health monitoring endpoints for service reliability.

**Key Endpoints**:
- `GET /health` - Detailed health check
- `GET /health/ready` - Readiness probe (Kubernetes)
- `GET /health/live` - Liveness probe (Kubernetes)
- `GET /health/startup` - Startup probe (Kubernetes)

**Dependencies**:
```python
from fastapi import APIRouter, Depends
from app.core.config import get_settings
from app.models import (health response models)
import psutil  # Optional for system metrics
```

**Links to**:
- `app/core/config.py` (for service configuration)
- `app/models.py` (for health response models)
- External services (for dependency health checks)

**Used by**:
- `app/main.py` (route registration)
- Load balancers and orchestrators
- Monitoring systems

---

### **📄 `app/api/metrics_routes.py`** - Metrics and Monitoring

**Purpose**: Application metrics collection for monitoring and observability.

**Key Endpoints**:
- `GET /metrics` - Detailed JSON metrics
- `GET /metrics/summary` - Summary metrics
- `GET /metrics/prometheus` - Prometheus format
- `GET /metrics/auth` - Authentication-specific metrics

**Dependencies**:
```python
from fastapi import APIRouter, Depends, Response
from app.core.config import get_settings
from app.models import (metrics response models)
import psutil  # Optional for system metrics
```

**Links to**:
- `app/core/config.py` (for metrics settings)
- `app/models.py` (for metrics response models)
- Application state and statistics

**Used by**:
- `app/main.py` (route registration)
- Prometheus and monitoring systems
- Operations teams

---

## 🧪 **Testing and Utilities**

### **📄 `test_setup.py`** - Setup Validation

**Purpose**: Comprehensive test to validate all components are working correctly.

**Key Tests**:
- Import validation for all modules
- Configuration loading
- Password management functionality
- Authentication adapter operations
- FastAPI application creation

**Dependencies**:
```python
from app.core.config import get_settings
from app.core.security import get_password_hash, verify_password
from app.auth.auth_adapter import AuthManagerAdapter
from app.main import app
```

**Links to**:
- All major application modules
- Core functionality validation

**Used by**:
- Development setup validation
- CI/CD pipeline health checks
- Deployment verification

---

### **📄 `generate_jwt_secret.py`** - JWT Secret Management

**Purpose**: Utility script to generate and rotate JWT signing keys in AWS Secrets Manager.

**Key Functions**:
- Generate RSA key pairs for JWT signing
- Store keys securely in AWS Secrets Manager
- Support for key rotation
- Proxy configuration support

**Dependencies**:
```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import boto3
from app.auth.aws_secrets import get_secret
```

**Links to**:
- `app/auth/aws_secrets.py` (for secret management)
- `app/core/security.py` (for JWT operations)

**Used by**:
- Deployment scripts
- Key rotation procedures
- Initial setup processes

---

## 📁 **Module Initialization Files**

### **📄 `app/__init__.py`** - Main App Module
**Purpose**: Main application module initialization.

### **📄 `app/core/__init__.py`** - Core Module Exports
**Purpose**: Exports commonly used core components for easy importing.

**Key Exports**:
```python
from .config import get_settings
from .exceptions import (all exceptions and handlers)
from .security import (auth dependencies and JWT functions)
from .logging_config import (loggers and middleware)
```

### **📄 `app/api/__init__.py`** - API Module
**Purpose**: API module initialization and common utilities.

### **📄 `app/auth/__init__.py`** - Auth Module Exports
**Purpose**: Exports authentication components.

**Key Exports**:
```python
from .supabase_auth import SupabaseAuthManager
from .auth_adapter import AuthManagerAdapter
from .aws_secrets import get_secret
```

---

## 🔄 **Dependency Flow Diagram**

```
┌─────────────────┐
│   app/main.py   │ ← Entry Point
└─────────┬───────┘
          │
    ┌─────▼─────┐ ┌─────────────┐ ┌──────────────┐
    │ API Routes│ │ Core Modules│ │ Auth Modules │
    └─────┬─────┘ └─────┬───────┘ └──────┬───────┘
          │             │                │
    ┌─────▼─────┐ ┌─────▼───────┐ ┌──────▼───────┐
    │  Models   │ │ Config/Sec  │ │ Supabase/AWS │
    └───────────┘ └─────────────┘ └──────────────┘
```

---

## 🎯 **Key Integration Points**

### **1. Configuration Flow**
```
Environment Variables → app/core/config.py → All Modules
AWS Secrets Manager → app/auth/aws_secrets.py → app/core/config.py
```

### **2. Authentication Flow**
```
API Request → app/api/auth_routes.py → app/auth/auth_adapter.py → app/auth/supabase_auth.py → Supabase
```

### **3. Security Flow**
```
JWT Keys ← app/auth/aws_secrets.py ← app/core/security.py → JWT Operations
```

### **4. Error Handling Flow**
```
Exception → app/core/exceptions.py → Structured Response → Client
```

### **5. Logging Flow**
```
All Modules → app/core/logging_config.py → Structured Logs → CloudWatch
```

---

## 📋 **Module Summary Table**

| Module | Purpose | Key Dependencies | Used By |
|--------|---------|------------------|---------|
| `main.py` | FastAPI app entry point | All core, API, auth modules | ASGI server |
| `core/config.py` | Configuration management | `aws_secrets.py` | All modules |
| `core/exceptions.py` | Error handling | `models.py` | All modules |
| `core/security.py` | Security & JWT | `config.py`, `aws_secrets.py` | Auth modules |
| `core/logging_config.py` | Logging setup | None | All modules |
| `models.py` | API models | None | API routes, adapters |
| `auth/supabase_auth.py` | Supabase integration | `security.py`, `aws_secrets.py` | `auth_adapter.py` |
| `auth/aws_secrets.py` | AWS Secrets Manager | None | Security, config |
| `auth/auth_adapter.py` | Auth API adapter | `supabase_auth.py`, `models.py` | API routes |
| `api/auth_routes.py` | Auth endpoints | `auth_adapter.py`, `models.py` | `main.py` |
| `api/health_routes.py` | Health endpoints | `config.py`, `models.py` | `main.py` |
| `api/metrics_routes.py` | Metrics endpoints | `config.py`, `models.py` | `main.py` |

---

## 🚀 **Best Practices for File Usage**

### **1. Import Patterns**
```python
# Core utilities - use from app.core
from app.core import get_settings, get_password_hash, security_logger

# API models - import specific models
from app.models import LoginRequest, LoginResponse

# Auth operations - use adapter pattern
from app.auth.auth_adapter import AuthManagerAdapter
```

### **2. Configuration Access**
```python
# Always use dependency injection
def some_function(settings: Settings = Depends(get_settings)):
    return settings.database_url
```

### **3. Error Handling**
```python
# Use specific exception types
from app.core.exceptions import InvalidCredentialsException
raise InvalidCredentialsException("Invalid email or password")
```

### **4. Logging**
```python
# Use structured logging
from app.core.logging_config import get_logger
logger = get_logger(__name__)
logger.info("Operation completed", extra={"user_id": user_id})
```

---

**Last Updated**: January 15, 2024  
**Documentation Version**: 1.0.0
