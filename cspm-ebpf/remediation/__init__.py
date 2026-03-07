"""
remediation package

Autonomous remediation agent for Sentinel-Core security orchestration.

This package implements Node D in the LangGraph pipeline, providing
confidence-gated execution of Kubernetes YAML patches and process
termination actions for ML-triaged security events.

Main Components:
    - RemediationConfig: Configuration management with runtime updates
    - RemediationAgent: Main orchestration component
    - DecisionGate: Confidence-based action approval
    - RoutingEngine: MITRE tactic-based action routing
    - ExecutionEngine: Kubernetes command execution
    - AuditLogger: Comprehensive audit trail logging

Configuration Hierarchy:
    1. Environment variables (boot defaults)
    2. Runtime updates via API endpoint
    3. Per-event flags (test/debug only)

Default Configuration:
    - autonomy_mode: "tiered"
    - dry_run: True
    - sigkill_threshold: 0.92
    - yaml_threshold: 0.95
    - kubeconfig_path: None (in-cluster auth)
"""

from .config import RemediationConfig, AutonomyMode
from .agent import remediation_agent, RemediationAgent
from .decision_gate import DecisionGate
from .routing_engine import RoutingEngine
from .executor import ExecutionEngine
from .audit_logger import AuditLogger

__all__ = [
    "RemediationConfig",
    "AutonomyMode",
    "remediation_agent",
    "RemediationAgent",
    "DecisionGate",
    "RoutingEngine",
    "ExecutionEngine",
    "AuditLogger",
]

__version__ = "0.1.0"
