"""
InsureCove Authentication Service - Metrics Routes

Production metrics collection:
- GET /metrics (detailed JSON metrics)
- GET /metrics/summary (summary metrics)
- GET /metrics/prometheus (Prometheus format)
- GET /metrics/auth (auth-specific metrics)
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import APIRouter, Response, Request
from fastapi.responses import PlainTextResponse

from app.core import get_settings, api_logger
from app.models import MetricsResponse

# Initialize router
router = APIRouter()

# Initialize settings
settings = get_settings()

# Simple in-memory metrics store (in production, use Redis or similar)
metrics_store = {
    "requests_total": 0,
    "requests_by_endpoint": {},
    "requests_by_status": {},
    "response_times": [],
    "errors_total": 0,
    "active_sessions": 0,
    "auth_events": {
        "logins_total": 0,
        "registrations_total": 0,
        "token_refreshes_total": 0,
        "failed_logins_total": 0
    },
    "start_time": time.time()
}


def update_request_metrics(endpoint: str, status_code: int, response_time: float):
    """Update request metrics"""
    metrics_store["requests_total"] += 1
    
    # Track by endpoint
    if endpoint not in metrics_store["requests_by_endpoint"]:
        metrics_store["requests_by_endpoint"][endpoint] = 0
    metrics_store["requests_by_endpoint"][endpoint] += 1
    
    # Track by status code
    status_group = f"{status_code // 100}xx"
    if status_group not in metrics_store["requests_by_status"]:
        metrics_store["requests_by_status"][status_group] = 0
    metrics_store["requests_by_status"][status_group] += 1
    
    # Track response times (keep last 1000)
    metrics_store["response_times"].append(response_time)
    if len(metrics_store["response_times"]) > 1000:
        metrics_store["response_times"] = metrics_store["response_times"][-1000:]
    
    # Track errors
    if status_code >= 400:
        metrics_store["errors_total"] += 1


def update_auth_metrics(event_type: str):
    """Update authentication metrics"""
    if event_type in metrics_store["auth_events"]:
        metrics_store["auth_events"][event_type] += 1


def get_system_metrics() -> Dict[str, Any]:
    """Get system performance metrics"""
    try:
        # Try to import psutil for system metrics
        import psutil
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_used_mb = memory.used / (1024 * 1024)
        
        return {
            "cpu_usage_percent": cpu_percent,
            "memory_usage_mb": round(memory_used_mb, 2),
            "memory_usage_percent": memory.percent
        }
    except ImportError:
        # Fallback if psutil not available
        return {
            "cpu_usage_percent": 0.0,
            "memory_usage_mb": 0.0,
            "memory_usage_percent": 0.0
        }


def calculate_metrics() -> Dict[str, Any]:
    """Calculate current metrics"""
    current_time = time.time()
    uptime_seconds = current_time - metrics_store["start_time"]
    
    # Calculate RPS (requests per second)
    requests_per_second = metrics_store["requests_total"] / max(uptime_seconds, 1)
    
    # Calculate average response time
    response_times = metrics_store["response_times"]
    if response_times:
        avg_response_time_ms = sum(response_times) / len(response_times) * 1000
    else:
        avg_response_time_ms = 0.0
    
    # Calculate error rate
    error_rate = metrics_store["errors_total"] / max(metrics_store["requests_total"], 1)
    
    # Get system metrics
    system_metrics = get_system_metrics()
    
    return {
        "requests_total": metrics_store["requests_total"],
        "requests_per_second": round(requests_per_second, 2),
        "average_response_time_ms": round(avg_response_time_ms, 2),
        "active_sessions": metrics_store["active_sessions"],
        "error_rate": round(error_rate, 4),
        "uptime_seconds": round(uptime_seconds, 2),
        "memory_usage_mb": system_metrics["memory_usage_mb"],
        "cpu_usage_percent": system_metrics["cpu_usage_percent"],
        "errors_total": metrics_store["errors_total"],
        "requests_by_endpoint": metrics_store["requests_by_endpoint"],
        "requests_by_status": metrics_store["requests_by_status"],
        "auth_events": metrics_store["auth_events"]
    }


@router.get(
    "",
    response_model=MetricsResponse,
    summary="Application metrics",
    description="Get detailed application metrics in JSON format"
)
async def get_metrics() -> MetricsResponse:
    """Get application metrics"""
    
    try:
        metrics_data = calculate_metrics()
        
        return MetricsResponse(
            requests_total=metrics_data["requests_total"],
            requests_per_second=metrics_data["requests_per_second"],
            average_response_time_ms=metrics_data["average_response_time_ms"],
            active_sessions=metrics_data["active_sessions"],
            error_rate=metrics_data["error_rate"],
            uptime_seconds=metrics_data["uptime_seconds"],
            memory_usage_mb=metrics_data["memory_usage_mb"],
            cpu_usage_percent=metrics_data["cpu_usage_percent"]
        )
        
    except Exception as e:
        api_logger.error(f"Failed to get metrics: {str(e)}")
        
        # Return basic metrics on error
        return MetricsResponse(
            requests_total=0,
            requests_per_second=0.0,
            average_response_time_ms=0.0,
            active_sessions=0,
            error_rate=0.0,
            uptime_seconds=0.0,
            memory_usage_mb=0.0,
            cpu_usage_percent=0.0
        )


@router.get(
    "/summary",
    summary="Metrics summary",
    description="Get a summary of key metrics"
)
async def get_metrics_summary():
    """Get metrics summary"""
    
    try:
        metrics_data = calculate_metrics()
        
        return {
            "status": "healthy" if metrics_data["error_rate"] < 0.05 else "degraded",
            "uptime_hours": round(metrics_data["uptime_seconds"] / 3600, 2),
            "total_requests": metrics_data["requests_total"],
            "current_rps": metrics_data["requests_per_second"],
            "error_rate_percent": round(metrics_data["error_rate"] * 100, 2),
            "avg_response_time_ms": metrics_data["average_response_time_ms"],
            "resource_usage": {
                "cpu_percent": metrics_data["cpu_usage_percent"],
                "memory_mb": metrics_data["memory_usage_mb"]
            },
            "authentication": {
                "total_logins": metrics_data["auth_events"]["logins_total"],
                "failed_logins": metrics_data["auth_events"]["failed_logins_total"],
                "success_rate": round(
                    (metrics_data["auth_events"]["logins_total"] / 
                     max(metrics_data["auth_events"]["logins_total"] + metrics_data["auth_events"]["failed_logins_total"], 1)) * 100, 2
                )
            }
        }
        
    except Exception as e:
        api_logger.error(f"Failed to get metrics summary: {str(e)}")
        return {"error": "Failed to retrieve metrics"}


@router.get(
    "/prometheus",
    response_class=PlainTextResponse,
    summary="Prometheus metrics",
    description="Get metrics in Prometheus format"
)
async def get_prometheus_metrics():
    """Get metrics in Prometheus format"""
    
    try:
        metrics_data = calculate_metrics()
        
        prometheus_metrics = []
        
        # Basic metrics
        prometheus_metrics.append(f"# HELP insurecove_requests_total Total number of HTTP requests")
        prometheus_metrics.append(f"# TYPE insurecove_requests_total counter")
        prometheus_metrics.append(f"insurecove_requests_total {metrics_data['requests_total']}")
        
        prometheus_metrics.append(f"# HELP insurecove_requests_per_second Current requests per second")
        prometheus_metrics.append(f"# TYPE insurecove_requests_per_second gauge")
        prometheus_metrics.append(f"insurecove_requests_per_second {metrics_data['requests_per_second']}")
        
        prometheus_metrics.append(f"# HELP insurecove_response_time_ms Average response time in milliseconds")
        prometheus_metrics.append(f"# TYPE insurecove_response_time_ms gauge")
        prometheus_metrics.append(f"insurecove_response_time_ms {metrics_data['average_response_time_ms']}")
        
        prometheus_metrics.append(f"# HELP insurecove_error_rate Current error rate")
        prometheus_metrics.append(f"# TYPE insurecove_error_rate gauge")
        prometheus_metrics.append(f"insurecove_error_rate {metrics_data['error_rate']}")
        
        prometheus_metrics.append(f"# HELP insurecove_uptime_seconds Application uptime in seconds")
        prometheus_metrics.append(f"# TYPE insurecove_uptime_seconds gauge")
        prometheus_metrics.append(f"insurecove_uptime_seconds {metrics_data['uptime_seconds']}")
        
        prometheus_metrics.append(f"# HELP insurecove_cpu_usage_percent CPU usage percentage")
        prometheus_metrics.append(f"# TYPE insurecove_cpu_usage_percent gauge")
        prometheus_metrics.append(f"insurecove_cpu_usage_percent {metrics_data['cpu_usage_percent']}")
        
        prometheus_metrics.append(f"# HELP insurecove_memory_usage_mb Memory usage in MB")
        prometheus_metrics.append(f"# TYPE insurecove_memory_usage_mb gauge")
        prometheus_metrics.append(f"insurecove_memory_usage_mb {metrics_data['memory_usage_mb']}")
        
        # Authentication metrics
        for event, count in metrics_data["auth_events"].items():
            prometheus_metrics.append(f"# HELP insurecove_auth_{event} Authentication event count")
            prometheus_metrics.append(f"# TYPE insurecove_auth_{event} counter")
            prometheus_metrics.append(f"insurecove_auth_{event} {count}")
        
        # HTTP status code metrics
        for status_group, count in metrics_data["requests_by_status"].items():
            prometheus_metrics.append(f"# HELP insurecove_http_requests_{status_group} HTTP requests by status group")
            prometheus_metrics.append(f"# TYPE insurecove_http_requests_{status_group} counter")
            prometheus_metrics.append(f"insurecove_http_requests_{status_group} {count}")
        
        return "\n".join(prometheus_metrics)
        
    except Exception as e:
        api_logger.error(f"Failed to generate Prometheus metrics: {str(e)}")
        return "# ERROR: Failed to generate metrics"


@router.get(
    "/auth",
    summary="Authentication metrics",
    description="Get authentication-specific metrics"
)
async def get_auth_metrics():
    """Get authentication-specific metrics"""
    
    try:
        metrics_data = calculate_metrics()
        auth_data = metrics_data["auth_events"]
        
        total_auth_attempts = auth_data["logins_total"] + auth_data["failed_logins_total"]
        success_rate = (auth_data["logins_total"] / max(total_auth_attempts, 1)) * 100
        
        return {
            "authentication_summary": {
                "total_login_attempts": total_auth_attempts,
                "successful_logins": auth_data["logins_total"],
                "failed_logins": auth_data["failed_logins_total"],
                "success_rate_percent": round(success_rate, 2)
            },
            "registration_summary": {
                "total_registrations": auth_data["registrations_total"]
            },
            "token_summary": {
                "token_refreshes": auth_data["token_refreshes_total"]
            },
            "security_insights": {
                "high_failure_rate": success_rate < 80,
                "failure_rate_threshold": 80,
                "recommendations": [
                    "Monitor for brute force attacks" if success_rate < 50 else None,
                    "Review password policies" if auth_data["failed_logins_total"] > 100 else None
                ]
            }
        }
        
    except Exception as e:
        api_logger.error(f"Failed to get auth metrics: {str(e)}")
        return {"error": "Failed to retrieve authentication metrics"}


# Middleware integration functions (to be called by middleware)

def record_request_metric(endpoint: str, status_code: int, response_time: float):
    """Record request metric (called by middleware)"""
    update_request_metrics(endpoint, status_code, response_time)


def record_auth_event(event_type: str):
    """Record authentication event (called by auth routes)"""
    update_auth_metrics(event_type)


def increment_active_sessions():
    """Increment active sessions count"""
    metrics_store["active_sessions"] += 1


def decrement_active_sessions():
    """Decrement active sessions count"""
    metrics_store["active_sessions"] = max(0, metrics_store["active_sessions"] - 1) 