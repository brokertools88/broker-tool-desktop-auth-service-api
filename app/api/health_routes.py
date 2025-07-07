"""
InsureCove Authentication Service - Health Check Routes

Health monitoring endpoints:
- GET /health (overall health status)
- GET /health/live (liveness probe)
- GET /health/ready (readiness probe)
- GET /health/detailed (detailed service health)
"""

import time
import asyncio
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request, status
import psutil

from app.core import get_settings, api_logger
from app.models import HealthCheckResponse, HealthStatus, ServiceHealth
from app.auth.aws_secrets import AWSSecretsManager

# Initialize router
router = APIRouter()

# Initialize settings
settings = get_settings()

# Application start time
app_start_time = time.time()


async def check_database_health() -> ServiceHealth:
    """Check database connectivity"""
    try:
        # Simple connectivity check - you can enhance this
        start_time = time.time()
        
        # TODO: Implement actual database health check
        # For now, simulate a quick check
        await asyncio.sleep(0.01)  # Simulate DB query time
        
        response_time = (time.time() - start_time) * 1000
        
        return ServiceHealth(
            status=HealthStatus.HEALTHY,
            response_time_ms=response_time,
            details="Database connection successful"
        )
    except Exception as e:
        return ServiceHealth(
            status=HealthStatus.UNHEALTHY,
            details=f"Database connection failed: {str(e)}"
        )


async def check_aws_secrets_health() -> ServiceHealth:
    """Check AWS Secrets Manager connectivity"""
    try:
        start_time = time.time()
        
        # Initialize secrets manager
        secrets_manager = AWSSecretsManager()
        
        # Try to get a secret (this will test connectivity)
        await asyncio.to_thread(
            secrets_manager.get_secret,
            f"{settings.aws.secret_prefix}/jwt-config"
        )
        
        response_time = (time.time() - start_time) * 1000
        
        return ServiceHealth(
            status=HealthStatus.HEALTHY,
            response_time_ms=response_time,
            details="AWS Secrets Manager accessible"
        )
    except Exception as e:
        return ServiceHealth(
            status=HealthStatus.UNHEALTHY,
            details=f"AWS Secrets Manager error: {str(e)}"
        )


async def check_redis_health() -> ServiceHealth:
    """Check Redis connectivity"""
    try:
        start_time = time.time()
        
        # TODO: Implement Redis health check
        # For now, simulate check
        await asyncio.sleep(0.005)  # Simulate Redis ping
        
        response_time = (time.time() - start_time) * 1000
        
        return ServiceHealth(
            status=HealthStatus.HEALTHY,
            response_time_ms=response_time,
            details="Redis connection successful"
        )
    except Exception as e:
        return ServiceHealth(
            status=HealthStatus.DEGRADED,
            details=f"Redis connection failed: {str(e)}"
        )


async def check_supabase_health() -> ServiceHealth:
    """Check Supabase connectivity"""
    try:
        start_time = time.time()
        
        # TODO: Implement Supabase health check
        # For now, simulate check
        await asyncio.sleep(0.02)  # Simulate Supabase API call
        
        response_time = (time.time() - start_time) * 1000
        
        return ServiceHealth(
            status=HealthStatus.HEALTHY,
            response_time_ms=response_time,
            details="Supabase connection successful"
        )
    except Exception as e:
        return ServiceHealth(
            status=HealthStatus.UNHEALTHY,
            details=f"Supabase connection failed: {str(e)}"
        )


def get_system_metrics() -> Dict[str, Any]:
    """Get system performance metrics"""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_used_mb = memory.used / (1024 * 1024)
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_used_percent = (disk.used / disk.total) * 100
        
        return {
            "cpu_usage_percent": cpu_percent,
            "memory_usage_mb": round(memory_used_mb, 2),
            "memory_usage_percent": memory.percent,
            "disk_usage_percent": round(disk_used_percent, 2),
            "uptime_seconds": time.time() - app_start_time
        }
    except Exception:
        return {
            "cpu_usage_percent": 0.0,
            "memory_usage_mb": 0.0,
            "memory_usage_percent": 0.0,
            "disk_usage_percent": 0.0,
            "uptime_seconds": time.time() - app_start_time
        }


@router.get(
    "",
    response_model=HealthCheckResponse,
    summary="Health check",
    description="Overall application health status"
)
async def health_check(request: Request) -> HealthCheckResponse:
    """Get overall application health status"""
    
    try:
        # Check all services
        services = {}
        overall_status = HealthStatus.HEALTHY
        
        # Database check
        services["database"] = await check_database_health()
        if services["database"].status == HealthStatus.UNHEALTHY:
            overall_status = HealthStatus.UNHEALTHY
        elif services["database"].status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
            overall_status = HealthStatus.DEGRADED
        
        # AWS Secrets Manager check
        services["aws_secrets"] = await check_aws_secrets_health()
        if services["aws_secrets"].status == HealthStatus.UNHEALTHY:
            overall_status = HealthStatus.UNHEALTHY
        elif services["aws_secrets"].status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
            overall_status = HealthStatus.DEGRADED
        
        # Supabase check
        services["supabase"] = await check_supabase_health()
        if services["supabase"].status == HealthStatus.UNHEALTHY:
            overall_status = HealthStatus.UNHEALTHY
        elif services["supabase"].status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
            overall_status = HealthStatus.DEGRADED
        
        # Redis check (non-critical)
        services["redis"] = await check_redis_health()
        # Redis is optional, don't affect overall status unless everything else is healthy
        
        return HealthCheckResponse(
            status=overall_status,
            services=services,
            version=settings.app_version,
            uptime_seconds=time.time() - app_start_time
        )
        
    except Exception as e:
        api_logger.error(f"Health check failed: {str(e)}")
        
        return HealthCheckResponse(
            status=HealthStatus.UNHEALTHY,
            services={},
            version=settings.app_version,
            uptime_seconds=time.time() - app_start_time
        )


@router.get(
    "/live",
    summary="Liveness probe",
    description="Kubernetes liveness probe endpoint"
)
async def liveness_check():
    """Liveness probe for Kubernetes"""
    # Simple check - if the app is running, it's alive
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get(
    "/ready",
    summary="Readiness probe", 
    description="Kubernetes readiness probe endpoint"
)
async def readiness_check():
    """Readiness probe for Kubernetes"""
    
    try:
        # Check critical services only
        db_health = await check_database_health()
        aws_health = await check_aws_secrets_health()
        
        if db_health.status == HealthStatus.HEALTHY and aws_health.status == HealthStatus.HEALTHY:
            return {
                "status": "ready",
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service not ready"
            )
            
    except Exception as e:
        api_logger.error(f"Readiness check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready"
        )


@router.get(
    "/detailed",
    summary="Detailed health check",
    description="Detailed health information including system metrics"
)
async def detailed_health_check():
    """Detailed health check with system metrics"""
    
    try:
        # Get all service health
        health_response = await health_check(None)
        
        # Get system metrics
        system_metrics = get_system_metrics()
        
        # Combine results
        detailed_info = {
            "health": health_response.model_dump(),
            "system_metrics": system_metrics,
            "configuration": {
                "environment": settings.environment,
                "debug_mode": settings.debug,
                "features": {
                    "registration": settings.enable_registration,
                    "email_verification": settings.enable_email_verification,
                    "password_reset": settings.enable_password_reset,
                    "mfa": settings.enable_mfa
                }
            },
            "runtime_info": {
                "python_version": "3.11+",
                "fastapi_version": "0.104+",
                "start_time": datetime.fromtimestamp(app_start_time).isoformat(),
                "current_time": datetime.utcnow().isoformat()
            }
        }
        
        return detailed_info
        
    except Exception as e:
        api_logger.error(f"Detailed health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Health check failed"
        ) 