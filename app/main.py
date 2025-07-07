"""
InsureCove Authentication Service - Main Application Entry Point

Production-ready FastAPI application with:
- 2024 REST API standards compliance
- Rate limiting and security middleware
- CORS configuration
- Comprehensive error handling
- Health checks and metrics
- Request/response logging
- OpenAPI documentation
"""

import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError

# Core imports
from app.core.config import get_settings
from app.core.logging_config import setup_logging, RequestLoggingMiddleware
from app.core.security import SecurityMiddleware
from app.core.exceptions import (
    insurecove_exception_handler,
    http_exception_handler,
    validation_exception_handler,
    general_exception_handler,
    BaseInsureCoveException
)

# API routes
from app.api.auth_routes import router as auth_router
from app.api.health_routes import router as health_router
from app.api.metrics_routes import router as metrics_router

# Initialize settings
settings = get_settings()

# Application startup time
app_start_time = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    setup_logging()
    
    # Store startup time in app state
    app.state.start_time = app_start_time
    
    print(f"🚀 {settings.app_name} v{settings.app_version} starting...")
    print(f"📊 Environment: {settings.environment}")
    print(f"🌐 Host: {settings.host}:{settings.port}")
    print(f"📚 Docs: {settings.docs_url}")
    
    yield
    
    # Shutdown
    print(f"🛑 {settings.app_name} shutting down...")


def create_application() -> FastAPI:
    """Create and configure FastAPI application"""
    
    # Determine if docs should be enabled
    docs_url = settings.docs_url if not settings.is_production else None
    redoc_url = settings.redoc_url if not settings.is_production else None
    openapi_url = settings.openapi_url if not settings.is_production else None
    
    # Create FastAPI app
    app = FastAPI(
        title=settings.app_name,
        description=settings.app_description,
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
        # RFC 9457 Problem Details support
        default_response_class=JSONResponse,
    )
    
    # Add security middleware
    if settings.is_production:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*"]  # Configure based on your domain
        )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.get_cors_origins(),
        allow_credentials=True,
        allow_methods=settings.security.allowed_methods,
        allow_headers=settings.security.allowed_headers,
    )
    
    # Add request logging middleware
    app.add_middleware(RequestLoggingMiddleware)
    
    # Add rate limiting if available
    try:
        from slowapi import Limiter, _rate_limit_exceeded_handler
        from slowapi.util import get_remote_address
        from slowapi.errors import RateLimitExceeded
        
        limiter = Limiter(key_func=get_remote_address)
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    except ImportError:
        pass
    
    # Add exception handlers
    app.add_exception_handler(BaseInsureCoveException, insurecove_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(ValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
    
    # Include routers
    app.include_router(
        auth_router,
        prefix=f"{settings.api_prefix}/auth",
        tags=["Authentication"]
    )
    
    app.include_router(
        health_router,
        prefix="/health",
        tags=["Health"]
    )
    
    app.include_router(
        metrics_router,
        prefix="/metrics",
        tags=["Metrics"]
    )
    
    return app


# Create the application instance
app = create_application()


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add process time header to responses"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint"""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "status": "running",
        "timestamp": time.time(),
        "docs_url": settings.docs_url if not settings.is_production else None
    }


@app.get(f"{settings.api_prefix}/info", tags=["Info"])
async def api_info():
    """API information endpoint"""
    return {
        "name": settings.app_name,
        "description": settings.app_description,
        "version": settings.app_version,
        "environment": settings.environment,
        "api_prefix": settings.api_prefix,
        "features": {
            "registration": settings.enable_registration,
            "email_verification": settings.enable_email_verification,
            "password_reset": settings.enable_password_reset,
            "mfa": settings.enable_mfa,
            "social_login": settings.enable_social_login
        },
        "security": {
            "jwt_algorithm": settings.jwt.jwt_algorithm,
            "access_token_expire_minutes": settings.jwt.access_token_expire_minutes,
            "refresh_token_expire_days": settings.jwt.refresh_token_expire_days
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        reload=settings.is_development,
        log_level=settings.logging.log_level.lower(),
        access_log=settings.logging.log_requests
    ) 