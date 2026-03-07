"""
decision_gate.py

Confidence-based decision gating for remediation actions.

This module implements the Decision Gate component that evaluates whether
a remediation action should be approved based on confidence thresholds.

Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5
"""

import logging
from typing import Tuple, Literal

logger = logging.getLogger(__name__)

ActionType = Literal["SIGKILL", "YAML"]


class DecisionGate:
    """
    Evaluates remediation actions against confidence thresholds.
    
    The Decision Gate ensures that only high-confidence detections trigger
    potentially disruptive remediation actions. Different action types have
    different confidence requirements:
    - SIGKILL (process termination): >= 0.92 confidence
    - YAML (resource patch): >= 0.95 confidence
    """
    
    def __init__(self, sigkill_threshold: float = 0.92, yaml_threshold: float = 0.95):
        """
        Initialize Decision Gate with confidence thresholds.
        
        Args:
            sigkill_threshold: Minimum confidence for SIGKILL actions (default: 0.92)
            yaml_threshold: Minimum confidence for YAML actions (default: 0.95)
        """
        self.sigkill_threshold = sigkill_threshold
        self.yaml_threshold = yaml_threshold
        
        logger.info(
            f"Decision Gate initialized: SIGKILL threshold={sigkill_threshold}, "
            f"YAML threshold={yaml_threshold}"
        )
    
    def evaluate_action(
        self,
        confidence_score: float,
        action_type: ActionType
    ) -> Tuple[bool, str]:
        """
        Evaluate whether a remediation action should be approved.
        
        Args:
            confidence_score: ML model confidence score (0.0-1.0)
            action_type: Type of remediation action ("SIGKILL" or "YAML")
        
        Returns:
            Tuple of (approved: bool, rejection_reason: str or None)
            - If approved=True, rejection_reason will be empty string
            - If approved=False, rejection_reason explains why
        
        Requirements:
            3.1: SIGKILL approval at confidence >= 0.92
            3.2: SIGKILL rejection below 0.92
            3.3: YAML approval at confidence >= 0.95
            3.4: YAML rejection below 0.95
            3.5: Rejection reason formatting
        """
        # Determine threshold based on action type
        if action_type == "SIGKILL":
            threshold = self.sigkill_threshold
        elif action_type == "YAML":
            threshold = self.yaml_threshold
        else:
            logger.error(f"Unknown action type: {action_type}")
            return False, f"Unknown action type: {action_type}"
        
        # Evaluate confidence against threshold
        if confidence_score >= threshold:
            logger.info(
                f"Action APPROVED: {action_type} with confidence {confidence_score:.3f} "
                f"(threshold: {threshold:.3f})"
            )
            return True, ""
        else:
            rejection_reason = (
                f"confidence_too_low: {confidence_score:.3f} < {threshold:.3f} "
                f"required for {action_type}"
            )
            logger.warning(
                f"Action REJECTED: {action_type} with confidence {confidence_score:.3f} "
                f"below threshold {threshold:.3f}"
            )
            return False, rejection_reason
