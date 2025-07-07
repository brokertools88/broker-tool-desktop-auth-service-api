# 📋 RESTful API Standards 2024 - Updated from Context7

*Last Updated: December 2024*
*Sources: Zalando API Guidelines, FastAPI Official Docs, FastAPI Best Practices*

## 📖 Table of Contents

1. [Overview](#overview)
2. [URL Design & Naming](#url-design--naming)
3. [HTTP Methods & Status Codes](#http-methods--status-codes)
4. [Request & Response Standards](#request--response-standards)
5. [Error Handling (RFC 9457)](#error-handling-rfc-9457)
6. [Authentication & Security](#authentication--security)
7. [Data Validation & Schemas](#data-validation--schemas)
8. [Performance & Caching](#performance--caching)
9. [Documentation Standards](#documentation-standards)
10. [Production Best Practices](#production-best-practices)

---

## 🎯 Overview

This document consolidates the latest RESTful API standards from industry leaders including Zalando's API Guidelines, FastAPI's official documentation, and proven production best practices for 2024.

### Core Principles

1. **Resource-Oriented Design**: URLs represent resources, not actions
2. **HTTP Semantics**: Proper use of HTTP methods and status codes
3. **Stateless**: Each request contains all necessary information
4. **Cacheable**: Responses should be cacheable where appropriate
5. **Layered System**: Support for intermediary components
6. **Code on Demand**: Optional executable code in responses

---

## 🔗 URL Design & Naming

### Resource Naming

```http
# ✅ Good - Resource-based URLs
GET /users/123
GET /users/123/orders
POST /users
PUT /users/123

# ❌ Bad - Action-based URLs
GET /getUser?id=123
POST /createUser
PUT /updateUser/123
```

### Naming Conventions

- **Use kebab-case** for URL segments:
```http
GET /shipment-orders/{shipment-order-id}
GET /user-profiles/{profile-id}/settings
```

- **Use snake_case** for JSON properties:
```json
{
  "customer_number": "12345",
  "sales_order_number": "SO-2024-001",
  "billing_address": {
    "street_name": "Main Street",
    "postal_code": "12345"
  }
}
```

### Compound Keys

When resources have compound keys, expose them in URLs:
```http
# Individual key components as path parameters
GET /article-size-advices/{sku}/{sales-channel-id}

# Or as search parameters for filtering
GET /article-size-advices?skus=sku-1,sku-2&sales_channel_id=sid-1
```

### Nested Resources

Structure nested resources logically:
```http
# Sub-resources that depend on parent
GET /customers/{customer-id}/orders/{order-id}

# Independent resources (avoid deep nesting)
GET /orders/{order-id}  # Better than /customers/{customer-id}/orders/{order-id}
```

---

## 🛠 HTTP Methods & Status Codes

### HTTP Methods

| Method | Purpose | Idempotent | Safe |
|--------|---------|------------|------|
| GET | Retrieve resource(s) | ✅ | ✅ |
| POST | Create resource | ❌ | ❌ |
| PUT | Update/Replace resource | ✅ | ❌ |
| PATCH | Partial update | ❌ | ❌ |
| DELETE | Remove resource | ✅ | ❌ |

### Status Codes

#### Success (2xx)
- **200 OK**: Standard successful response
- **201 Created**: Resource successfully created
- **202 Accepted**: Request accepted for processing
- **204 No Content**: Successful with no response body

#### Client Errors (4xx)
- **400 Bad Request**: Invalid request syntax
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Access denied
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource conflict
- **422 Unprocessable Entity**: Validation errors
- **429 Too Many Requests**: Rate limit exceeded

#### Server Errors (5xx)
- **500 Internal Server Error**: Generic server error
- **502 Bad Gateway**: Invalid upstream response
- **503 Service Unavailable**: Service temporarily unavailable

### FastAPI Implementation

```python
from fastapi import FastAPI, status
from pydantic import BaseModel

app = FastAPI()

@app.post(
    "/users/", 
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "Invalid user data"},
        status.HTTP_409_CONFLICT: {"description": "User already exists"}
    }
)
async def create_user(user: UserCreate):
    # Implementation
    pass
```

---

## 📥 Request & Response Standards

### Content Types

**Request Headers:**
```http
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>
```

**Response Headers:**
```http
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-RateLimit-Remaining: 95
```

### Request Body Structure

```python
# Pydantic models for validation
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(min_length=8)
    age: int = Field(ge=18, le=120)
    
class UserResponse(BaseModel):
    id: UUID4
    username: str
    email: EmailStr
    created_at: datetime
    updated_at: Optional[datetime] = None
```

### Response Body Structure

```json
{
  "data": {
    "id": "123e4567-e89b-12d3-a456-426655440000",
    "username": "john_doe",
    "email": "john@example.com",
    "created_at": "2024-12-19T10:30:00Z"
  },
  "meta": {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-12-19T10:30:00Z"
  }
}
```

### Pagination

Use cursor-based pagination for scalability:

```yaml
# Cursor structure
Cursor:
  type: object
  properties:
    position:
      description: Object containing keys pointing to anchor element
      type: object
    element:
      description: Whether anchor element should be included/excluded
      type: string
      enum: [INCLUDED, EXCLUDED]
    direction:
      description: Retrieval direction from anchor position
      type: string
      enum: [ASCENDING, DESCENDING]
```

**Response format:**
```json
{
  "items": [...],
  "pagination": {
    "self": "https://api.example.com/users?cursor=current",
    "next": "https://api.example.com/users?cursor=next",
    "prev": "https://api.example.com/users?cursor=prev",
    "first": "https://api.example.com/users?cursor=first",
    "last": "https://api.example.com/users?cursor=last"
  }
}
```

---

## ⚠️ Error Handling (RFC 9457)

### Problem Details Standard

All errors should follow RFC 9457 Problem Details format:

```python
from fastapi import HTTPException

class APIException(HTTPException):
    def __init__(
        self,
        status_code: int,
        title: str,
        detail: str,
        type_uri: str = None,
        instance: str = None
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.title = title
        self.type = type_uri
        self.instance = instance
```

**Error Response Structure:**
```json
{
  "type": "https://example.com/problems/validation-error",
  "title": "Validation Error",
  "status": 422,
  "detail": "The request contains invalid data",
  "instance": "/users/create",
  "invalid_params": [
    {
      "name": "email",
      "reason": "Invalid email format"
    }
  ],
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Common Error Scenarios

```python
# Validation Error
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "type": "/problems/validation-error",
            "title": "Validation Error",
            "status": 422,
            "detail": "Request validation failed",
            "errors": exc.errors(),
            "request_id": request.headers.get("X-Request-ID")
        }
    )
```

---

## 🔐 Authentication & Security

### OAuth2 with JWT Bearer Tokens

```python
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return await get_user_by_id(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### OpenAPI Security Scheme

```yaml
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

security:
  - BearerAuth: []
```

### Rate Limiting

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, credentials: LoginRequest):
    # Implementation
    pass
```

### Security Headers

```python
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Security headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response
```

---

## ✅ Data Validation & Schemas

### Pydantic Models with Advanced Validation

```python
from pydantic import BaseModel, Field, field_validator, model_validator
from enum import Enum
import re

class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=30, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(min_length=8)
    role: UserRole = UserRole.USER
    
    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)", password):
            raise ValueError(
                "Password must contain at least one lowercase letter, "
                "one uppercase letter, and one digit"
            )
        return password
    
    @model_validator(mode="after")
    def validate_model(self):
        # Cross-field validation
        return self
```

### Custom Base Model

```python
from datetime import datetime
from zoneinfo import ZoneInfo
from pydantic import BaseModel, ConfigDict

def datetime_to_gmt_str(dt: datetime) -> str:
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    return dt.strftime("%Y-%m-%dT%H:%M:%S%z")

class CustomModel(BaseModel):
    model_config = ConfigDict(
        json_encoders={datetime: datetime_to_gmt_str},
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True
    )
    
    def serializable_dict(self, **kwargs):
        """Return a dict with only serializable fields."""
        return self.model_dump(exclude_unset=True, **kwargs)
```

---

## ⚡ Performance & Caching

### Caching Headers

```python
from fastapi import Response

@app.get("/users/{user_id}")
async def get_user(user_id: str, response: Response):
    user = await get_user_from_db(user_id)
    
    # Set caching headers
    response.headers["Cache-Control"] = "private, max-age=300"
    response.headers["ETag"] = f'"{user.updated_at.timestamp()}"'
    response.headers["Last-Modified"] = user.updated_at.strftime("%a, %d %b %Y %H:%M:%S GMT")
    
    return user
```

### Conditional Requests (Optimistic Locking)

```python
from fastapi import Header

@app.put("/users/{user_id}")
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    if_match: str = Header(None)
):
    current_user = await get_user_from_db(user_id)
    current_etag = f'"{current_user.updated_at.timestamp()}"'
    
    if if_match and if_match != current_etag:
        raise HTTPException(status_code=412, detail="Precondition Failed")
    
    updated_user = await update_user_in_db(user_id, user_data)
    return updated_user
```

### Field Filtering

```python
from typing import Optional, Set

@app.get("/users/{user_id}")
async def get_user(
    user_id: str,
    fields: Optional[str] = Query(None, description="Comma-separated fields to include")
):
    user = await get_user_from_db(user_id)
    
    if fields:
        field_set = set(fields.split(","))
        return user.model_dump(include=field_set)
    
    return user
```

---

## 📚 Documentation Standards

### OpenAPI Specification

```python
from fastapi import FastAPI

app = FastAPI(
    title="InsureCove Authentication API",
    description="""
    # Authentication Service API
    
    This API provides authentication and authorization services for the InsureCove platform.
    
    ## Authentication
    
    This API uses OAuth2 with JWT tokens. Include the token in the Authorization header:
    ```
    Authorization: Bearer <your-jwt-token>
    ```
    
    ## Rate Limiting
    
    Requests are rate-limited per IP address:
    - Authentication endpoints: 5 requests per minute
    - General endpoints: 100 requests per minute
    """,
    version="1.0.0",
    terms_of_service="https://insure-cove.com/terms",
    contact={
        "name": "InsureCove API Team",
        "url": "https://insure-cove.com/contact",
        "email": "api@insure-cove.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
)
```

### Route Documentation

```python
@app.post(
    "/auth/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account",
    description="""
    Create a new user account with the provided information.
    
    - **username**: Must be unique and 3-30 characters
    - **email**: Must be a valid email address
    - **password**: Must be at least 8 characters with mixed case and numbers
    """,
    responses={
        201: {"description": "User successfully created"},
        400: {"description": "Invalid request data"},
        409: {"description": "Username or email already exists"},
        422: {"description": "Validation error"}
    },
    tags=["Authentication"]
)
async def create_user(user: UserCreate):
    """Create a new user account."""
    # Implementation
    pass
```

---

## 🚀 Production Best Practices

### Project Structure (Domain-Driven)

```
src/
├── auth/
│   ├── router.py
│   ├── schemas.py      # Pydantic models
│   ├── models.py       # Database models
│   ├── dependencies.py # FastAPI dependencies
│   ├── service.py      # Business logic
│   ├── exceptions.py   # Custom exceptions
│   └── config.py       # Auth-specific config
├── users/
│   ├── router.py
│   ├── schemas.py
│   ├── models.py
│   ├── dependencies.py
│   ├── service.py
│   └── exceptions.py
├── core/
│   ├── config.py       # Global configuration
│   ├── database.py     # Database connection
│   ├── security.py     # Security utilities
│   └── middleware.py   # Custom middleware
└── main.py             # FastAPI application
```

### Configuration Management

```python
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str
    
    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    
    # Rate Limiting
    RATE_LIMIT_REDIS_URL: Optional[str] = None
    
    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    
    class Config:
        env_file = ".env"

settings = Settings()
```

### Dependency Injection

```python
# dependencies.py
from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await get_user_by_id(db, user_id)
    if user is None:
        raise credentials_exception
    
    return user

# Usage in routes
@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    return current_user
```

### Async/Await Best Practices

```python
import asyncio
from fastapi.concurrency import run_in_threadpool

# ✅ Good - Non-blocking async operation
@app.get("/async-operation")
async def async_operation():
    await asyncio.sleep(1)  # Non-blocking
    return {"status": "completed"}

# ✅ Good - Blocking operation in thread pool
@app.get("/sync-operation")
async def sync_operation():
    result = await run_in_threadpool(blocking_io_operation)
    return {"result": result}

# ❌ Bad - Blocking operation in async function
@app.get("/blocking-operation")
async def blocking_operation():
    time.sleep(1)  # This blocks the entire event loop!
    return {"status": "completed"}
```

### Testing

```python
import pytest
from httpx import AsyncClient
from fastapi.testclient import TestClient

# Sync testing
def test_create_user():
    with TestClient(app) as client:
        response = client.post(
            "/auth/users",
            json={
                "username": "testuser",
                "email": "test@example.com",
                "password": "SecurePass123"
            }
        )
        assert response.status_code == 201
        assert response.json()["username"] == "testuser"

# Async testing
@pytest.mark.asyncio
async def test_create_user_async():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post(
            "/auth/users",
            json={
                "username": "testuser",
                "email": "test@example.com", 
                "password": "SecurePass123"
            }
        )
        assert response.status_code == 201
```

### Monitoring & Observability

```python
import logging
from fastapi import Request
import uuid

# Request ID middleware
@app.middleware("http")
async def add_request_id_header(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

# Structured logging
logger = logging.getLogger(__name__)

@app.post("/auth/login")
async def login(request: Request, credentials: LoginRequest):
    request_id = request.state.request_id
    
    logger.info(
        "Login attempt",
        extra={
            "request_id": request_id,
            "username": credentials.username,
            "ip_address": request.client.host
        }
    )
    
    # Implementation
    pass
```

---

## 📋 Checklist for Implementation

### ✅ API Design
- [ ] Resource-based URLs with kebab-case
- [ ] Proper HTTP method usage
- [ ] Appropriate status codes
- [ ] RFC 9457 error handling
- [ ] Consistent request/response formats

### ✅ Security
- [ ] JWT authentication with proper validation
- [ ] Rate limiting implemented
- [ ] CORS configured correctly
- [ ] Security headers added
- [ ] Input validation with Pydantic

### ✅ Performance
- [ ] Caching headers implemented
- [ ] Conditional requests support
- [ ] Field filtering available
- [ ] Async/await used correctly
- [ ] Database queries optimized

### ✅ Documentation
- [ ] OpenAPI specification complete
- [ ] All endpoints documented
- [ ] Examples provided
- [ ] Authentication requirements clear
- [ ] Error responses documented

### ✅ Production Ready
- [ ] Environment-based configuration
- [ ] Structured logging
- [ ] Health checks
- [ ] Metrics collection
- [ ] Comprehensive tests

---

## 🔗 References

- [Zalando RESTful API Guidelines](https://opensource.zalando.com/restful-api-guidelines/)
- [FastAPI Official Documentation](https://fastapi.tiangolo.com/)
- [RFC 9457 - Problem Details](https://tools.ietf.org/rfc/rfc9457.txt)
- [OpenAPI Specification 3.0](https://spec.openapis.org/oas/v3.0.3)
- [HTTP Status Code Registry](https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml)

---

*This document represents the latest industry standards for RESTful API design as of December 2024, incorporating best practices from leading technology companies and official specifications.* 