"""
agent.py

Main RemediationAgent orchestrator (Node D in LangGraph pipeline).

This module implements the RemediationAgent that coordinates all remediation
components to execute security remediation actions autonomously.

Validates: Requirements 1.4, 1.5, 2.4, 2.5, 5.1-5.4, 16.1-16.5, 18.1-18.5
"""

import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from .config import RemediationConfig
from .decision_gate import DecisionGate
from .routing_engine import RoutingEngine
from .executor import ExecutionEngine
from .audit_logger import AuditLogger
from .metrics import record_action, record_processing_duration

logger = logging.getLogger(__name__)


class RemediationAgent:
    """
    Main orchestrator for autonomous security remediation.
    
    The RemediationAgent coordinates all remediation components to:
    1. Validate and filter events (TP only)
    2. Check idempotency (avoid duplicate execution)
    3. Route actions based on MITRE tactics
    4. Gate actions based on confidence thresholds
    5. Execute approved actions (SIGKILL or YAML)
    6. Log all decisions and outcomes to audit trail
    """
    
    def __init__(self, config: RemediationConfig):
        """
        Initialize RemediationAgent with configuration.
        
        Args:
            config: RemediationConfig instance
        """
        self.config = config
        self.decision_gate = DecisionGate(
            sigkill_threshold=config.sigkill_threshold,
            yaml_threshold=config.yaml_threshold
        )
        self.routing_engine = RoutingEngine()
        self.executor = ExecutionEngine(
            kubeconfig_path=config.kubeconfig_path
        )
        self.audit_logger = AuditLogger()
        
        logger.info(
            f"RemediationAgent initialized: "
            f"autonomy_mode={config.autonomy_mode}, "
            f"dry_run={config.dry_run}"
        )
    
    def _validate_event(self, state: Dict[str, Any]) -> tuple[bool, str]:
        """
        Validate that event has required fields.
        
        Args:
            state: SentinelState dictionary
        
        Returns:
            Tuple of (valid: bool, error_message: str)
        
        Requirements:
            2.4: Validate required fields present
            2.5: Log error and skip if fields missing
        """
        required_fields = ["event_id", "mitre_techniques", "guide_score", "guide_grade"]
        
        for field in required_fields:
            if field not in state or state[field] is None:
                error_msg = f"Missing required field: {field}"
                logger.error(error_msg)
                return False, error_msg
        
        # Additional validation
        if not isinstance(state["mitre_techniques"], list):
            error_msg = "mitre_techniques must be a list"
            logger.error(error_msg)
            return False, error_msg
        
        return True, ""
    
    def _check_idempotency(self, event_id: str) -> tuple[bool, str]:
        """
        Check if event was recently remediated to avoid duplicates.
        
        Args:
            event_id: Event ID to check
        
        Returns:
            Tuple of (should_skip: bool, reason: str)
        
        Requirements:
            18.1: Check audit trail before executing
            18.2: Skip if successful remediation within 5 minutes
            18.3: Allow retry if failed remediation older than 1 minute
            18.4: Record duplicate attempts
        """
        recent_records = self.audit_logger.query_by_event_id(event_id)
        
        if not recent_records:
            return False, ""
        
        now = datetime.now(timezone.utc)
        
        for record in reversed(recent_records):  # Most recent first
            try:
                record_time = datetime.fromisoformat(record["timestamp"])
                age_seconds = (now - record_time).total_seconds()
                status = record.get("execution_status", "")
                
                # Skip if successful remediation within 5 minutes
                if status == "succeeded" and age_seconds < 300:
                    reason = (
                        f"Event already remediated successfully {age_seconds:.0f}s ago "
                        f"(audit_id: {record.get('audit_id')})"
                    )
                    logger.info(f"Idempotency check: {reason}")
                    return True, reason
                
                # Allow retry if failed remediation older than 1 minute
                if status == "failed" and age_seconds >= 60:
                    logger.info(
                        f"Allowing retry for failed remediation from {age_seconds:.0f}s ago"
                    )
                    return False, ""
            
            except Exception as e:
                logger.warning(f"Error parsing audit record timestamp: {e}")
                continue
        
        return False, ""
    
    def _extract_event_context(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract pod, namespace, and pid from raw event.
        
        Args:
            raw_event: Raw security event dictionary
        
        Returns:
            Dict with keys: pod, namespace, pid
        
        Requirements:
            6.6: Extract pod, namespace, pid from event context
        """
        # Events may have telemetry nested or fields at top level
        telemetry = raw_event.get("telemetry", {})
        return {
            "pod": (
                telemetry.get("pod")
                or raw_event.get("pod_name")
                or raw_event.get("pod", "unknown")
            ),
            "namespace": (
                telemetry.get("namespace")
                or raw_event.get("namespace", "default")
            ),
            "pid": (
                telemetry.get("pid")
                or raw_event.get("pid", 0)
            ),
        }
    
    def _requires_human_approval(self, action_type: str) -> bool:
        """
        Determine if human approval is required based on autonomy mode.
        
        Args:
            action_type: "SIGKILL" or "YAML"
        
        Returns:
            True if human approval required, False otherwise
        
        Requirements:
            5.1: Autonomous mode - no confirmation
            5.2: Tiered mode - confirm SIGKILL only
            5.3: Human-in-loop mode - confirm all
        """
        if self.config.autonomy_mode == "autonomous":
            return False
        elif self.config.autonomy_mode == "tiered":
            return action_type == "SIGKILL"
        elif self.config.autonomy_mode == "human-in-loop":
            return True
        else:
            # Default to requiring approval for unknown modes
            logger.warning(f"Unknown autonomy mode: {self.config.autonomy_mode}")
            return True
    
    def process_event(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a security event and execute remediation if approved.
        
        This is the main entry point for the RemediationAgent node.
        
        Args:
            state: SentinelState dictionary from LangGraph
        
        Returns:
            Updated state dictionary with remediation fields
        
        Requirements:
            1.4: Consume complete state from report_generator
            1.5: Preserve all upstream state fields
            16.1: Accept state dictionary as input
            16.2: Add remediation fields to state
            16.3: Return updated state dictionary
            16.4: Set remediation_status to "skipped" with reason
            16.5: Preserve existing state fields
        """
        start_time = time.time()
        event_id = state.get("event_id", state.get("raw_event", {}).get("event_id", "unknown"))
        
        try:
            # Validate event has required fields
            valid, error_msg = self._validate_event(state)
            if not valid:
                self.audit_logger.log_action(
                    event_id=event_id,
                    action_type="",
                    confidence_score=state.get("guide_score", 0.0),
                    autonomy_mode=self.config.autonomy_mode,
                    execution_status="skipped",
                    error_message=f"Validation failed: {error_msg}",
                    mitre_techniques=state.get("mitre_techniques", [])
                )
                
                return {
                    **state,
                    "remediation_status": "skipped",
                    "remediation_action": "",
                    "remediation_timestamp": datetime.now(timezone.utc).isoformat(),
                    "remediation_error": error_msg
                }
            
            # Check idempotency
            should_skip, skip_reason = self._check_idempotency(event_id)
            if should_skip:
                self.audit_logger.log_action(
                    event_id=event_id,
                    action_type="",
                    confidence_score=state.get("guide_score", 0.0),
                    autonomy_mode=self.config.autonomy_mode,
                    execution_status="duplicate_skipped",
                    error_message=skip_reason,
                    mitre_techniques=state.get("mitre_techniques", [])
                )
                
                return {
                    **state,
                    "remediation_status": "skipped",
                    "remediation_action": "",
                    "remediation_timestamp": datetime.now(timezone.utc).isoformat(),
                    "remediation_error": skip_reason
                }
            
            # Determine action type based on MITRE tactics
            mitre_techniques = state.get("mitre_techniques", [])
            action_type = self.routing_engine.determine_action(mitre_techniques)
            
            # Evaluate confidence threshold
            confidence_score = state.get("guide_score", 0.0)
            approved, rejection_reason = self.decision_gate.evaluate_action(
                confidence_score, action_type
            )
            
            if not approved:
                self.audit_logger.log_action(
                    event_id=event_id,
                    action_type=action_type,
                    confidence_score=confidence_score,
                    autonomy_mode=self.config.autonomy_mode,
                    execution_status="skipped",
                    error_message=rejection_reason,
                    mitre_techniques=mitre_techniques
                )
                
                return {
                    **state,
                    "remediation_status": "skipped",
                    "remediation_action": action_type,
                    "remediation_timestamp": datetime.now(timezone.utc).isoformat(),
                    "remediation_error": rejection_reason
                }
            
            # Check if human approval required
            if self._requires_human_approval(action_type):
                logger.info(
                    f"Human approval required for {action_type} "
                    f"(autonomy_mode={self.config.autonomy_mode})"
                )
                
                self.audit_logger.log_action(
                    event_id=event_id,
                    action_type=action_type,
                    confidence_score=confidence_score,
                    autonomy_mode=self.config.autonomy_mode,
                    execution_status="pending_approval",
                    error_message="Awaiting human confirmation",
                    mitre_techniques=mitre_techniques
                )
                
                return {
                    **state,
                    "remediation_status": "pending_approval",
                    "remediation_action": action_type,
                    "remediation_timestamp": datetime.now(timezone.utc).isoformat(),
                    "remediation_error": "Awaiting human confirmation"
                }
            
            # Execute remediation action
            execution_result = self._execute_action(state, action_type)
            
            # Log to audit trail
            self.audit_logger.log_action(
                event_id=event_id,
                action_type=action_type,
                confidence_score=confidence_score,
                autonomy_mode=self.config.autonomy_mode,
                execution_status=execution_result["status"],
                error_message=execution_result.get("error_message", ""),
                mitre_techniques=mitre_techniques
            )
            
            # Record metrics
            duration_seconds = time.time() - start_time
            record_processing_duration(duration_seconds)
            record_action(
                action_type=action_type,
                status=execution_result["status"],
                reason=execution_result.get("error_message", "")
            )
            
            duration = duration_seconds * 1000
            logger.info(
                f"[NODE D] remediation_agent | action={action_type} "
                f"| status={execution_result['status']} | {duration:.0f}ms"
            )
            
            return {
                **state,
                "remediation_status": execution_result["status"],
                "remediation_action": action_type,
                "remediation_timestamp": datetime.now(timezone.utc).isoformat(),
                "remediation_error": execution_result.get("error_message", "")
            }
        
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            logger.exception(f"[NODE D] remediation_agent FAILED | {duration:.0f}ms")
            
            # Log error to audit trail
            self.audit_logger.log_action(
                event_id=event_id,
                action_type="",
                confidence_score=state.get("guide_score", 0.0),
                autonomy_mode=self.config.autonomy_mode,
                execution_status="error",
                error_message=str(e),
                mitre_techniques=state.get("mitre_techniques", [])
            )
            
            return {
                **state,
                "remediation_status": "error",
                "remediation_action": "",
                "remediation_timestamp": datetime.now(timezone.utc).isoformat(),
                "remediation_error": str(e)
            }
    
    def _execute_action(self, state: Dict[str, Any], action_type: str) -> Dict[str, Any]:
        """
        Execute the determined remediation action.
        
        Args:
            state: SentinelState dictionary
            action_type: "SIGKILL" or "YAML"
        
        Returns:
            Execution result dict with status and error_message
        """
        if action_type == "SIGKILL":
            context = self._extract_event_context(state.get("raw_event", {}))
            return self.executor.execute_sigkill(
                pod=context["pod"],
                namespace=context["namespace"],
                pid=context["pid"],
                dry_run=self.config.dry_run
            )
        
        elif action_type == "YAML":
            yaml_patch = state.get("yaml_fix", "")
            return self.executor.execute_yaml(
                yaml_patch=yaml_patch,
                dry_run=self.config.dry_run
            )
        
        else:
            return {
                "status": "failed",
                "error_message": f"Unknown action type: {action_type}"
            }


# ============================================================================
# LANGGRAPH NODE FUNCTION
# ============================================================================

# Global agent instance (initialized on first use)
_agent_instance = None


def remediation_agent(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node function for RemediationAgent (Node D).
    
    This function is called by the LangGraph pipeline for TP events.
    
    Args:
        state: SentinelState dictionary from report_generator
    
    Returns:
        Updated SentinelState dictionary with remediation fields
    
    Requirements:
        1.1: Receive event as input from report_generator
        1.3: Route to END after completion
        2.1: Process TP events only
    """
    global _agent_instance
    
    # Initialize agent on first use
    if _agent_instance is None:
        from .config import RemediationConfig
        config = RemediationConfig.from_env()
        _agent_instance = RemediationAgent(config)
    
    # Process the event
    return _agent_instance.process_event(state)
