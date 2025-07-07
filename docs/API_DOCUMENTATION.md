# 📚 InsureCove Authentication Service - API Documentation

## 🚀 **Overview**

The InsureCove Authentication Service provides secure, production-ready authentication endpoints following 2024 REST API standards. Built with FastAPI, it includes comprehensive error handling, rate limiting, monitoring, and integration with Supabase and AWS Secrets Manager.

**Base URL**: `http://localhost:8000` (development) | `https://api.insurecove.com` (production)  
**API Version**: `v1`  
**API Prefix**: `/api/v1`

---

## 🔐 **Authentication Endpoints**

### **POST** `/auth/brokers` - Create Broker Account
Create a new broker account with company information.

**Request Body:**
```json
{
  "email": "broker@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+852-1234-5678",
  "company_name": "ABC Insurance Brokers",
  "license_number": "BRK123456",
  "license_expiry": "2025-12-31",
  "company_address": "123 Central, Hong Kong",
  "business_registration": "BR123456789",
  "website": "https://abcbrokers.com"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Broker account created successfully",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "broker@example.com",
    "user_type": "broker",
    "created_at": "2024-01-15T10:30:00Z",
    "is_verified": false
  },
  "metadata": {
    "request_id": "req_123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **POST** `/auth/clients` - Create Client Account
Create a new client account with personal information.

**Request Body:**
```json
{
  "email": "client@example.com",
  "password": "SecurePassword123!",
  "first_name": "Jane",
  "last_name": "Smith",
  "phone_number": "+852-9876-5432",
  "date_of_birth": "1990-05-15",
  "hkid_number": "A123456(7)",
  "address": "456 Kowloon, Hong Kong",
  "occupation": "Software Engineer",
  "annual_income": 500000
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Client account created successfully",
  "data": {
    "user_id": "660e8400-e29b-41d4-a716-446655440001",
    "email": "client@example.com",
    "user_type": "client",
    "created_at": "2024-01-15T10:30:00Z",
    "is_verified": false
  },
  "metadata": {
    "request_id": "req_124",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **POST** `/auth/sessions` - Login/Authenticate
Authenticate user and create a new session.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "remember_me": true
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 3600,
    "user": {
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "user_type": "broker",
      "first_name": "John",
      "last_name": "Doe",
      "is_verified": true,
      "last_login": "2024-01-15T10:30:00Z"
    }
  },
  "metadata": {
    "request_id": "req_125",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **GET** `/auth/sessions/current` - Get Current Session
Get information about the current authenticated session.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Session retrieved successfully",
  "data": {
    "session_id": "sess_123456",
    "user": {
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "user_type": "broker",
      "first_name": "John",
      "last_name": "Doe",
      "is_verified": true
    },
    "created_at": "2024-01-15T10:30:00Z",
    "expires_at": "2024-01-15T11:30:00Z",
    "is_active": true
  },
  "metadata": {
    "request_id": "req_126",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **DELETE** `/auth/sessions` - Logout
Logout user and invalidate session.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Request Body:**
```json
{
  "everywhere": false
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Logged out successfully",
  "data": null,
  "metadata": {
    "request_id": "req_127",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **POST** `/auth/tokens/refresh` - Refresh Access Token
Refresh an expired access token using a refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 3600
  },
  "metadata": {
    "request_id": "req_128",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **POST** `/auth/tokens/verify` - Verify Token
Verify the validity of an access token.

**Request Body:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Token is valid",
  "data": {
    "is_valid": true,
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "expires_at": "2024-01-15T11:30:00Z",
    "token_type": "access"
  },
  "metadata": {
    "request_id": "req_129",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **POST** `/auth/password/change` - Change Password
Change user's password (requires authentication).

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Request Body:**
```json
{
  "current_password": "OldPassword123!",
  "new_password": "NewSecurePassword456!",
  "confirm_password": "NewSecurePassword456!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password changed successfully",
  "data": null,
  "metadata": {
    "request_id": "req_130",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **POST** `/auth/password/reset` - Request Password Reset
Request a password reset email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset email sent",
  "data": null,
  "metadata": {
    "request_id": "req_131",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **POST** `/auth/password/reset/confirm` - Confirm Password Reset
Confirm password reset with token.

**Request Body:**
```json
{
  "token": "reset_token_123456",
  "new_password": "NewSecurePassword789!",
  "confirm_password": "NewSecurePassword789!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset successfully",
  "data": null,
  "metadata": {
    "request_id": "req_132",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

## 🏥 **Health Check Endpoints**

### **GET** `/health` - Comprehensive Health Check
Get detailed health status of all service components.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Service is healthy",
  "data": {
    "status": "healthy",
    "timestamp": "2024-01-15T10:30:00Z",
    "version": "1.0.0",
    "environment": "production",
    "uptime_seconds": 86400,
    "checks": {
      "database": {
        "status": "healthy",
        "response_time_ms": 15,
        "last_checked": "2024-01-15T10:30:00Z"
      },
      "supabase": {
        "status": "healthy",
        "response_time_ms": 45,
        "last_checked": "2024-01-15T10:30:00Z"
      },
      "aws_secrets": {
        "status": "healthy",
        "response_time_ms": 20,
        "last_checked": "2024-01-15T10:30:00Z"
      },
      "redis": {
        "status": "healthy",
        "response_time_ms": 8,
        "last_checked": "2024-01-15T10:30:00Z"
      }
    },
    "system": {
      "cpu_usage_percent": 15.5,
      "memory_usage_percent": 45.2,
      "disk_usage_percent": 65.8
    }
  },
  "metadata": {
    "request_id": "req_133",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **GET** `/health/ready` - Readiness Probe
Check if service is ready to accept requests (Kubernetes readiness probe).

**Response (200 OK):**
```json
{
  "status": "ready",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### **GET** `/health/live` - Liveness Probe
Check if service is alive (Kubernetes liveness probe).

**Response (200 OK):**
```json
{
  "status": "alive",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### **GET** `/health/startup` - Startup Probe
Check if service has started successfully (Kubernetes startup probe).

**Response (200 OK):**
```json
{
  "status": "started",
  "timestamp": "2024-01-15T10:30:00Z",
  "startup_time_seconds": 5.2
}
```

---

## 📊 **Metrics Endpoints**

### **GET** `/metrics` - Detailed JSON Metrics
Get comprehensive service metrics in JSON format.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Metrics retrieved successfully",
  "data": {
    "timestamp": "2024-01-15T10:30:00Z",
    "uptime_seconds": 86400,
    "version": "1.0.0",
    "environment": "production",
    "system": {
      "cpu_usage_percent": 15.5,
      "memory_usage_mb": 512,
      "memory_usage_percent": 45.2,
      "disk_usage_percent": 65.8,
      "load_average": [1.2, 1.1, 1.0]
    },
    "application": {
      "total_requests": 15420,
      "requests_per_second": 12.5,
      "active_connections": 45,
      "error_rate_percent": 0.2,
      "average_response_time_ms": 85
    },
    "authentication": {
      "total_logins": 1250,
      "successful_logins": 1235,
      "failed_logins": 15,
      "active_sessions": 890,
      "tokens_issued": 2340,
      "tokens_refreshed": 450
    },
    "database": {
      "total_queries": 8750,
      "average_query_time_ms": 12,
      "active_connections": 15,
      "connection_pool_usage_percent": 30
    }
  },
  "metadata": {
    "request_id": "req_134",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **GET** `/metrics/summary` - Summary Metrics
Get high-level service metrics summary.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Metrics summary retrieved successfully",
  "data": {
    "status": "healthy",
    "uptime_hours": 24,
    "total_requests": 15420,
    "error_rate_percent": 0.2,
    "active_users": 890,
    "cpu_usage_percent": 15.5,
    "memory_usage_percent": 45.2
  },
  "metadata": {
    "request_id": "req_135",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **GET** `/metrics/prometheus` - Prometheus Format
Get metrics in Prometheus format for monitoring systems.

**Response (200 OK, Content-Type: text/plain):**
```prometheus
# HELP auth_service_uptime_seconds Total uptime of the authentication service
# TYPE auth_service_uptime_seconds counter
auth_service_uptime_seconds 86400

# HELP auth_service_requests_total Total number of HTTP requests
# TYPE auth_service_requests_total counter
auth_service_requests_total{method="GET",endpoint="/health"} 5420
auth_service_requests_total{method="POST",endpoint="/auth/sessions"} 1250

# HELP auth_service_response_time_seconds HTTP request response time
# TYPE auth_service_response_time_seconds histogram
auth_service_response_time_seconds_bucket{le="0.1"} 12500
auth_service_response_time_seconds_bucket{le="0.5"} 14800
auth_service_response_time_seconds_bucket{le="1.0"} 15200
auth_service_response_time_seconds_bucket{le="+Inf"} 15420

# HELP auth_service_active_sessions Current number of active user sessions
# TYPE auth_service_active_sessions gauge
auth_service_active_sessions 890

# HELP auth_service_cpu_usage_percent Current CPU usage percentage
# TYPE auth_service_cpu_usage_percent gauge
auth_service_cpu_usage_percent 15.5
```

---

### **GET** `/metrics/auth` - Authentication-Specific Metrics
Get detailed authentication and authorization metrics.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Authentication metrics retrieved successfully",
  "data": {
    "sessions": {
      "total_active": 890,
      "total_created_today": 245,
      "average_session_duration_minutes": 45,
      "expired_today": 180
    },
    "logins": {
      "total_today": 245,
      "successful_today": 240,
      "failed_today": 5,
      "success_rate_percent": 97.96
    },
    "users": {
      "total_brokers": 150,
      "total_clients": 1200,
      "verified_users": 1180,
      "new_registrations_today": 8
    },
    "tokens": {
      "access_tokens_issued_today": 245,
      "refresh_tokens_used_today": 45,
      "expired_tokens_today": 180,
      "invalid_tokens_today": 2
    },
    "security": {
      "failed_login_attempts_today": 5,
      "suspicious_activities_today": 1,
      "rate_limited_requests_today": 12,
      "blocked_ips_today": 2
    }
  },
  "metadata": {
    "request_id": "req_136",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

## ❌ **Error Responses**

All error responses follow RFC 9457 Problem Details format:

### **400 Bad Request** - Validation Error
```json
{
  "success": false,
  "error": {
    "type": "https://api.insurecove.com/problems/validation-error",
    "title": "Validation Error",
    "status": 400,
    "detail": "The request body contains invalid data",
    "instance": "/auth/brokers",
    "errors": [
      {
        "field": "email",
        "message": "Invalid email format",
        "code": "INVALID_EMAIL"
      },
      {
        "field": "password",
        "message": "Password must be at least 8 characters",
        "code": "WEAK_PASSWORD"
      }
    ]
  },
  "metadata": {
    "request_id": "req_137",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **401 Unauthorized** - Invalid Credentials
```json
{
  "success": false,
  "error": {
    "type": "https://api.insurecove.com/problems/invalid-credentials",
    "title": "Invalid Credentials",
    "status": 401,
    "detail": "The provided email or password is incorrect",
    "instance": "/auth/sessions"
  },
  "metadata": {
    "request_id": "req_138",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **403 Forbidden** - Token Expired
```json
{
  "success": false,
  "error": {
    "type": "https://api.insurecove.com/problems/token-expired",
    "title": "Token Expired",
    "status": 403,
    "detail": "The access token has expired",
    "instance": "/auth/sessions/current"
  },
  "metadata": {
    "request_id": "req_139",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **409 Conflict** - User Already Exists
```json
{
  "success": false,
  "error": {
    "type": "https://api.insurecove.com/problems/user-exists",
    "title": "User Already Exists",
    "status": 409,
    "detail": "A user with this email already exists",
    "instance": "/auth/brokers"
  },
  "metadata": {
    "request_id": "req_140",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **429 Too Many Requests** - Rate Limited
```json
{
  "success": false,
  "error": {
    "type": "https://api.insurecove.com/problems/rate-limit-exceeded",
    "title": "Rate Limit Exceeded",
    "status": 429,
    "detail": "Too many requests. Please try again later",
    "instance": "/auth/sessions",
    "retry_after": 60
  },
  "metadata": {
    "request_id": "req_141",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

### **500 Internal Server Error** - Server Error
```json
{
  "success": false,
  "error": {
    "type": "https://api.insurecove.com/problems/internal-error",
    "title": "Internal Server Error",
    "status": 500,
    "detail": "An unexpected error occurred. Please try again later",
    "instance": "/auth/sessions"
  },
  "metadata": {
    "request_id": "req_142",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

## 🔧 **Rate Limiting**

The API implements rate limiting to prevent abuse:

- **Authentication endpoints**: 60 requests/minute per IP
- **Registration endpoints**: 10 requests/minute per IP
- **Password reset**: 5 requests/minute per IP
- **Health checks**: 100 requests/minute per IP
- **Metrics**: 30 requests/minute per IP

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1642248600
```

---

## 🔐 **Security Features**

### **Password Requirements**
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number
- At least 1 special character
- Cannot be a common password

### **Token Security**
- JWT tokens with RS256 signing
- Access token lifetime: 1 hour
- Refresh token lifetime: 30 days
- Automatic token rotation
- Secure token storage recommendations

### **Request Security**
- HTTPS enforcement in production
- CORS protection
- Request size limits
- Input validation and sanitization
- SQL injection prevention
- XSS protection

---

## 📋 **Testing the API**

### **Using cURL**

```bash
# Register a new broker
curl -X POST "http://localhost:8000/api/v1/auth/brokers" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@broker.com",
    "password": "SecurePass123!",
    "first_name": "Test",
    "last_name": "Broker",
    "company_name": "Test Brokers Ltd",
    "license_number": "TEST123"
  }'

# Login
curl -X POST "http://localhost:8000/api/v1/auth/sessions" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@broker.com",
    "password": "SecurePass123!"
  }'

# Get current session (use token from login response)
curl -X GET "http://localhost:8000/api/v1/auth/sessions/current" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### **Using Python Requests**

```python
import requests

# Base URL
BASE_URL = "http://localhost:8000/api/v1"

# Register broker
broker_data = {
    "email": "test@broker.com",
    "password": "SecurePass123!",
    "first_name": "Test",
    "last_name": "Broker",
    "company_name": "Test Brokers Ltd",
    "license_number": "TEST123"
}

response = requests.post(f"{BASE_URL}/auth/brokers", json=broker_data)
print(response.json())

# Login
login_data = {
    "email": "test@broker.com",
    "password": "SecurePass123!"
}

response = requests.post(f"{BASE_URL}/auth/sessions", json=login_data)
token_data = response.json()
access_token = token_data["data"]["access_token"]

# Get current session
headers = {"Authorization": f"Bearer {access_token}"}
response = requests.get(f"{BASE_URL}/auth/sessions/current", headers=headers)
print(response.json())
```

---

## 🚀 **OpenAPI Documentation**

Interactive API documentation is available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

---

## 📞 **Support**

For API support or questions:
- **Documentation**: See project README and design documents
- **Issues**: Create GitHub issue with API tag
- **Email**: support@insurecove.com (if available)

---

**Last Updated**: January 15, 2024  
**API Version**: 1.0.0  
**Documentation Version**: 1.0.0
