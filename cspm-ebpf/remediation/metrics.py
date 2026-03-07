"""
metrics.py

Prometheus metrics for RemediationAgent observability.

This module implements Prometheus metrics collection for monitoring
remediation agent performance and outcomes.

Validates: Requirements 14.1
"""

import logging
from prometheus_client import Counter, Histogram

logger = logging.getLogger(__name__)

# ============================================================================
# PROMETHEUS METRICS
# ============================================================================

# Total actions attempted (labeled by action_type and status)
actions_total = Counter(
    "remediation_actions_total",
    "Total number of remediation actions attempted",
    ["action_type", "status"]
)

# Successful actions (labeled by action_type)
actions_succeeded = Counter(
    "remediation_actions_succeeded",
    "Number of successful remediation actions",
    ["action_type"]
)

# Failed actions (labeled by action_type and reason)
actions_failed = Counter(
    "remediation_actions_failed",
    "Number of failed remediation actions",
    ["action_type", "reason"]
)

# Processing duration histogram
processing_duration_seconds = Histogram(
    "remediation_processing_duration_seconds",
    "Time spent processing remediation events",
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)


def record_action(action_type: str, status: str, reason: str = ""):
    """
    Record a remediation action in Prometheus metrics.
    
    Args:
        action_type: Type of action ("SIGKILL", "YAML", or empty)
        status: Execution status ("succeeded", "failed", "skipped", "dry_run")
        reason: Failure reason if status is "failed"
    
    Requirements:
        14.1: Implement Prometheus metrics
    """
    try:
        # Increment total counter
        actions_total.labels(action_type=action_type, status=status).inc()
        
        # Increment specific counters
        if status == "succeeded":
            actions_succeeded.labels(action_type=action_type).inc()
        elif status == "failed":
            actions_failed.labels(action_type=action_type, reason=reason).inc()
    
    except Exception as e:
        logger.error(f"Failed to record metrics: {e}")


def record_processing_duration(duration_seconds: float):
    """
    Record processing duration in Prometheus histogram.
    
    Args:
        duration_seconds: Processing duration in seconds
    """
    try:
        processing_duration_seconds.observe(duration_seconds)
    except Exception as e:
        logger.error(f"Failed to record duration metric: {e}")
