"""
health.py

Health check endpoint for RemediationAgent dependencies.

This module implements health checks for Kubernetes API and Redis
to ensure the remediation system is operational.

Validates: Requirements 14.2, 14.3, 14.4
"""

import logging
import subprocess
from typing import Dict, Any
from flask import Blueprint, jsonify

logger = logging.getLogger(__name__)

# Create Flask blueprint
health_bp = Blueprint("remediation_health", __name__, url_prefix="/api/remediation")


def check_kubernetes_api() -> tuple[bool, str]:
    """
    Check if Kubernetes API is reachable.
    
    Returns:
        Tuple of (healthy: bool, message: str)
    """
    try:
        # Try a simple kubectl command
        result = subprocess.run(
            ["kubectl", "version", "--client"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return True, "Kubernetes API reachable"
        else:
            return False, f"kubectl failed: {result.stderr}"
    
    except subprocess.TimeoutExpired:
        return False, "Kubernetes API timeout"
    
    except FileNotFoundError:
        return False, "kubectl not found"
    
    except Exception as e:
        return False, f"Kubernetes check failed: {str(e)}"


def check_redis() -> tuple[bool, str]:
    """
    Check if Redis is reachable.
    
    Returns:
        Tuple of (healthy: bool, message: str)
    """
    try:
        import redis
        import os
        
        redis_host = os.getenv("REDIS_HOST", "localhost")
        redis_port = int(os.getenv("REDIS_PORT", "6379"))
        redis_db = int(os.getenv("REDIS_DB", "0"))
        redis_password = os.getenv("REDIS_PASSWORD")
        
        client = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_password,
            socket_connect_timeout=5
        )
        
        # Test connection
        client.ping()
        return True, "Redis reachable"
    
    except ImportError:
        return False, "Redis client not installed"
    
    except Exception as e:
        return False, f"Redis check failed: {str(e)}"


@health_bp.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint for RemediationAgent.
    
    Checks:
    - Kubernetes API reachability
    - Redis reachability
    
    Returns:
        200 OK if all dependencies healthy
        503 Service Unavailable if any dependency unreachable
    
    Requirements:
        14.2: Return 200 OK when all dependencies reachable
        14.3: Return 503 when Kubernetes API unreachable
        14.4: Return 503 when Redis unreachable
    """
    k8s_healthy, k8s_message = check_kubernetes_api()
    redis_healthy, redis_message = check_redis()
    
    all_healthy = k8s_healthy and redis_healthy
    
    response = {
        "status": "healthy" if all_healthy else "unhealthy",
        "dependencies": {
            "kubernetes": {
                "healthy": k8s_healthy,
                "message": k8s_message
            },
            "redis": {
                "healthy": redis_healthy,
                "message": redis_message
            }
        }
    }
    
    status_code = 200 if all_healthy else 503
    
    if not all_healthy:
        logger.warning(f"Health check failed: {response}")
    
    return jsonify(response), status_code
